"""Typed, bounded HTTP client for the SheetSafe AI Streamlit dashboard.

Security invariants:
- Connects only to an explicit HTTP(S) FastAPI control-plane base URL.
- Never imports SQLite, private storage, parser_worker, or runner modules.
- Preserves HttpOnly cookie semantics in an internal HTTPX cookie jar, never
  exposing raw session credentials in public attributes, logs, or UI models.
- Enforces Origin, X-SheetSafe-Request, and X-CSRF-Token headers per the
  backend session protocol.
- Explicitly blocks unimplemented endpoints (real uploads, dataset profiling
  dispatch, live AI code execution) rather than fabricating responses.
"""

from dataclasses import dataclass, field
from enum import StrEnum
import hashlib
from http.cookies import SimpleCookie
import json
import re
from typing import Literal
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator


DEFAULT_API_BASE_URL = "http://127.0.0.1:8000"
DEFAULT_CLIENT_ORIGIN = "http://localhost:8501"
MAX_API_RESPONSE_BYTES = 32 * 1024


class FrontendClientCode(StrEnum):
    INVALID_CONFIGURATION = "INVALID_CONFIGURATION"
    BACKEND_UNREACHABLE = "BACKEND_UNREACHABLE"
    BACKEND_TIMEOUT = "BACKEND_TIMEOUT"
    NOT_READY = "NOT_READY"
    INVALID_REQUEST = "INVALID_REQUEST"
    UNAUTHENTICATED = "UNAUTHENTICATED"
    FORBIDDEN = "FORBIDDEN"
    NOT_FOUND = "NOT_FOUND"
    CONFLICT = "CONFLICT"
    UNPROCESSABLE_REQUEST = "UNPROCESSABLE_REQUEST"
    RATE_LIMITED = "RATE_LIMITED"
    UPSTREAM_CONTRACT_ERROR = "UPSTREAM_CONTRACT_ERROR"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE"
    FEATURE_DISABLED_BY_GATE = "FEATURE_DISABLED_BY_GATE"


class FrontendClientError(ValueError):
    """Sanitized client exception; never embeds cookies, CSRF tokens, or raw payloads."""

    def __init__(
        self,
        code: FrontendClientCode,
        message: str,
        *,
        status_code: int | None = None,
        retryable: bool = False,
        request_id: str | None = None,
        retry_after: int | None = None,
        backend_code: str | None = None,
    ) -> None:
        self.code = code
        self.safe_message = message
        self.status_code = status_code
        self.retryable = retryable
        self.request_id = request_id
        self.retry_after = retry_after
        self.backend_code = backend_code or code.value
        super().__init__(f"{code.value}: {message}")


class StrictFrontendModel(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid", hide_input_in_errors=True)


class ApiErrorEnvelope(StrictFrontendModel):
    code: str = Field(min_length=1, max_length=64)
    message: str = Field(min_length=1, max_length=256)
    retryable: bool
    request_id: str = Field(min_length=1, max_length=64)


class HealthStatus(StrictFrontendModel):
    status: Literal["ok"]


class ReadyStatus(StrictFrontendModel):
    status: Literal["ready"]


class BackendStatusSnapshot(StrictFrontendModel):
    """Combined real-time status of FastAPI liveness and readiness."""

    api_base_url: str
    reachable: bool
    liveness_ok: bool
    readiness_ok: bool
    status_label: Literal["ONLINE & READY", "DEGRADED (NOT READY)", "OFFLINE"]
    detail_message: str
    request_id: str | None = None


class ActiveSessionView(StrictFrontendModel):
    """Public session metadata safe for UI presentation. Never holds raw cookie or CSRF secret."""

    session_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    expires_at: int = Field(gt=0)
    lifetime_seconds: int = Field(ge=60, le=3600)
    mode: Literal["synthetic"] = "synthetic"
    private_uploads_enabled: Literal[False] = False
    cookie_name: Literal["__Host-sheetsafe_session", "sheetsafe_dev_session"]
    cookie_httponly: Literal[True] = True
    cookie_samesite: Literal["strict"] = "strict"


class SessionDeletionReceiptView(StrictFrontendModel):
    receipt_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    session_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    access_revoked: Literal[True] = True
    cancellation_status: Literal["requested"] = "requested"
    cleanup_status: Literal["not_started"] = "not_started"
    request_id: str | None = None


class SchemaColumnView(StrictFrontendModel):
    column_id: str = Field(pattern=r"^col_[0-9]{3}$")
    name: str = Field(min_length=1, max_length=128)
    inferred_type: Literal["empty", "text", "integer", "number", "boolean", "date", "mixed"]
    missing_count: int = Field(ge=0)


class DatasetSchemaView(StrictFrontendModel):
    version: Literal[1] = 1
    row_count: int = Field(ge=1)
    column_count: int = Field(ge=1)
    columns: tuple[SchemaColumnView, ...]
    schema_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class SyntheticDatasetView(StrictFrontendModel):
    dataset_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    session_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    version: Literal[1] = 1
    state: Literal["READY"] = "READY"
    is_synthetic_fixture: Literal[True] = True
    fixture_id: Literal["synthetic_quarterly_revenue_v1"]
    fixture_label: str
    dataset_schema: DatasetSchemaView
    request_id: str | None = None


class RequiredColumnView(StrictFrontendModel):
    column_id: str = Field(pattern=r"^col_[0-9]{3}$")
    name: str = Field(min_length=1, max_length=128)
    expected_type: Literal["empty", "text", "integer", "number", "boolean", "date", "mixed"]


class OperationStepView(StrictFrontendModel):
    step_number: int = Field(ge=1, le=8)
    operation: str
    target_columns: tuple[str, ...]
    group_by_columns: tuple[str, ...] = ()
    aggregation: str | None = None
    sort_direction: Literal["asc", "desc"] | None = None
    limit_rows: int | None = None
    rationale: str


class AnalysisPlanView(StrictFrontendModel):
    version: Literal[1] = 1
    schema_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    intent_summary: str
    required_columns: tuple[RequiredColumnView, ...]
    operations: tuple[OperationStepView, ...]
    expected_result_type: str


class ClarificationView(StrictFrontendModel):
    version: Literal[1] = 1
    reason_code: str
    clarification_prompt: str
    candidate_columns: tuple[str, ...] = ()


class PlanningEnvelopeView(StrictFrontendModel):
    version: Literal[1] = 1
    status: Literal["PLAN_READY", "CLARIFICATION_REQUIRED"]
    plan: AnalysisPlanView | None = None
    clarification: ClarificationView | None = None


class ASTValidationReceiptView(StrictFrontendModel):
    version: Literal[1] = 1
    valid: Literal[True] = True
    code_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    schema_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    declared_imports: tuple[str, ...]
    node_count: int = Field(ge=1)
    max_depth: int = Field(ge=1)
    execution_authorized: Literal[False] = False
    sandbox_isolation_required: Literal[True] = True
    security_notice: str = Field(min_length=10, max_length=240)


class CodeGenerationPreviewView(StrictFrontendModel):
    version: Literal[1] = 1
    code_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    schema_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    declared_imports: tuple[str, ...]
    referenced_columns: tuple[str, ...]
    output_columns: tuple[str, ...]
    expected_result_type: str = Field(min_length=1, max_length=64)
    python_source: str = Field(min_length=10, max_length=16384)
    execution_authorized: Literal[False] = False
    ast_receipt: ASTValidationReceiptView

    @model_validator(mode="after")
    def _verify_code_integrity(self) -> "CodeGenerationPreviewView":
        """Verify internal payload consistency (not proof of code safety or provenance)."""
        computed = hashlib.sha256(self.python_source.encode("utf-8")).hexdigest()
        if computed != self.code_sha256:
            raise ValueError("Candidate python_source SHA-256 mismatch")
        if (
            self.ast_receipt.code_sha256 != self.code_sha256
            or self.ast_receipt.plan_sha256 != self.plan_sha256
            or self.ast_receipt.schema_sha256 != self.schema_sha256
        ):
            raise ValueError("AST validation receipt hash consistency mismatch")
        return self


class ChartPointView(StrictFrontendModel):
    x: str | int | float | bool
    y: float


class ColumnCompletenessInsightView(StrictFrontendModel):
    column_id: str = Field(pattern=r"^col_[0-9]{3}$")
    column_name: str = Field(min_length=1, max_length=128)
    inferred_type: Literal["empty", "text", "integer", "number", "boolean", "date", "mixed"]
    row_count: int = Field(ge=1)
    missing_count: int = Field(ge=0)
    present_count: int = Field(ge=0)
    completeness_pct: float = Field(ge=0.0, le=100.0)
    referenced_in_plan: bool = False


class NumericColumnSummaryView(StrictFrontendModel):
    column_id: str = Field(min_length=1, max_length=64)
    display_label: str = Field(min_length=1, max_length=160)
    non_null_count: int = Field(ge=0, le=200)
    null_count: int = Field(ge=0, le=200)
    total_sum: float
    mean_value: float
    min_value: float
    max_value: float


class DemonstrationReportView(StrictFrontendModel):
    version: Literal[1] = 1
    demonstration_only: Literal[True] = True
    report_label: str = Field(min_length=10, max_length=240)
    markdown_filename: str = Field(pattern=r"^sheetsafe_demo_report_[0-9a-f]{12}\.md$")
    csv_filename: str = Field(pattern=r"^sheetsafe_demo_table_[0-9a-f]{12}\.csv$")
    markdown_content: str = Field(min_length=32, max_length=16384)
    csv_content: str = Field(min_length=10, max_length=16384)
    markdown_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    csv_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    formula_injection_neutralized: Literal[True] = True

    @model_validator(mode="after")
    def _verify_report_integrity(self) -> "DemonstrationReportView":
        if "DEMO / SYNTHETIC" not in self.report_label:
            raise ValueError("Demonstration report is missing required DEMO / SYNTHETIC label")
        if "DEMO / SYNTHETIC" not in self.markdown_content or "DEMO / SYNTHETIC" not in self.csv_content:
            raise ValueError("Demonstration report content is missing required DEMO / SYNTHETIC watermark")
        md_hash = hashlib.sha256(self.markdown_content.encode("utf-8")).hexdigest()
        csv_hash = hashlib.sha256(self.csv_content.encode("utf-8")).hexdigest()
        if md_hash != self.markdown_sha256 or csv_hash != self.csv_sha256:
            raise ValueError("Demonstration report SHA-256 integrity mismatch")
        return self


class SyntheticVerificationPreviewView(StrictFrontendModel):
    version: Literal[1] = 1
    demonstration_only: Literal[True] = True
    verification_label: str = Field(min_length=10, max_length=240)
    validation_status: Literal["SYNTHETIC_EXPECTED_RESULT_COMPUTED"] = (
        "SYNTHETIC_EXPECTED_RESULT_COMPUTED"
    )
    candidate_output_verified: Literal[False] = False
    publication_authorized: Literal[False] = False
    sandbox_execution_verified: Literal[False] = False
    schema_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    code_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    verified_output_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    result_type: str = Field(min_length=1, max_length=64)
    columns: tuple[str, ...]
    column_headers: dict[str, str]
    row_count: int = Field(ge=1, le=200)
    rows: tuple[dict[str, str | int | float | bool | None], ...]
    scalar_value: float | int | None = None
    chart_kind: Literal["BAR", "LINE", "NONE"] = "NONE"
    chart_x_label: str | None = None
    chart_y_label: str | None = None
    chart_series: tuple[ChartPointView, ...] = ()
    numeric_summaries: tuple[NumericColumnSummaryView, ...] = ()
    missing_value_insights: tuple[ColumnCompletenessInsightView, ...] = ()
    total_missing_cells: int = Field(default=0, ge=0)
    dataset_completeness_pct: float = Field(default=100.0, ge=0.0, le=100.0)
    zero_division_count: int = Field(default=0, ge=0)
    max_abs_error: float = Field(default=0.0, ge=0.0)
    demo_report: DemonstrationReportView

    @model_validator(mode="after")
    def _verify_synthetic_preview_contract(self) -> "SyntheticVerificationPreviewView":
        if "DEMO / SYNTHETIC" not in self.verification_label:
            raise ValueError("Synthetic verification preview is missing required DEMO label")
        if len(self.rows) != self.row_count:
            raise ValueError("Synthetic verification preview row_count mismatch")
        if len(self.chart_series) > 100:
            raise ValueError("Synthetic verification preview chart_series exceeds 100 points")
        if set(self.column_headers.keys()) != set(self.columns):
            raise ValueError("Synthetic verification preview column_headers must match columns")
        return self


class PlanningPreviewView(StrictFrontendModel):
    run_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    session_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    dataset_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    dataset_version: int = Field(ge=1)
    run_state: Literal["AWAIT_CONFIRMATION", "NEEDS_CLARIFICATION"]
    provider_mode: Literal["SIMULATED_MOCK"] = "SIMULATED_MOCK"
    simulated_response: Literal[True] = True
    provider_label: str
    is_synthetic_dataset: bool = True
    execution_enabled: Literal[False] = False
    model: str
    question: str
    dataset_schema: DatasetSchemaView
    envelope: PlanningEnvelopeView
    plan_sha256: str | None = None
    code_preview: CodeGenerationPreviewView | None = None
    synthetic_verification_preview: SyntheticVerificationPreviewView | None = None
    request_id: str | None = None

    @model_validator(mode="after")
    def _verify_preview_bindings(self) -> "PlanningPreviewView":
        """Check internal SHA-256 consistency across schema, plan, and preview payloads."""
        if self.envelope.status == "PLAN_READY":
            if self.envelope.plan is None or self.plan_sha256 is None:
                raise ValueError("PLAN_READY outcome requires plan and plan_sha256")
            if self.envelope.plan.schema_sha256 != self.dataset_schema.schema_sha256:
                raise ValueError("Plan schema_sha256 does not match dataset_schema")
            if self.code_preview is not None:
                if (
                    self.code_preview.schema_sha256 != self.dataset_schema.schema_sha256
                    or self.code_preview.plan_sha256 != self.plan_sha256
                ):
                    raise ValueError("Code preview SHA-256 consistency mismatch")
            if self.synthetic_verification_preview is not None:
                if self.code_preview is None:
                    raise ValueError("Synthetic verification preview requires code_preview")
                if (
                    self.synthetic_verification_preview.schema_sha256 != self.dataset_schema.schema_sha256
                    or self.synthetic_verification_preview.plan_sha256 != self.plan_sha256
                    or self.synthetic_verification_preview.code_sha256 != self.code_preview.code_sha256
                ):
                    raise ValueError("Synthetic verification preview consistency mismatch")
        else:
            if self.code_preview is not None or self.synthetic_verification_preview is not None:
                raise ValueError("CLARIFICATION_REQUIRED must not include code or verification previews")
        return self


class PersistedRunSummaryView(StrictFrontendModel):
    run_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    session_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    dataset_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    dataset_version: int = Field(ge=1)
    state: str
    question: str
    provider_mode: Literal["SIMULATED_MOCK"] = "SIMULATED_MOCK"
    simulated_response: Literal[True] = True
    execution_enabled: Literal[False] = False
    plan_sha256: str | None = None
    code_sha256: str | None = None
    expected_result_type: str | None = None
    intent_summary: str | None = None
    clarification_reason: str | None = None
    created_at: int = Field(gt=0)
    updated_at: int = Field(gt=0)


class SessionRunsListView(StrictFrontendModel):
    session_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    runs: tuple[PersistedRunSummaryView, ...]


@dataclass(slots=True)
class _SealedSessionJar:
    """Opaque in-memory holder for the HttpOnly session cookie and CSRF token.

    Values are stored in `SecretStr` with `repr=False` so Streamlit state dumps,
    exceptions, or logs never reveal session credentials.
    """

    view: ActiveSessionView
    _cookie_value: SecretStr = field(repr=False)
    _csrf_token: SecretStr = field(repr=False)

    def __repr__(self) -> str:
        return f"<_SealedSessionJar session_id={self.view.session_id!r}>"


def _coerce_tuples(value: object) -> object:
    if isinstance(value, list):
        return tuple(_coerce_tuples(item) for item in value)
    if isinstance(value, dict):
        return {k: _coerce_tuples(v) for k, v in value.items()}
    return value


def validate_canonical_origin(url: str, *, allow_path: bool = False) -> str:
    if type(url) is not str or not url.strip():
        raise FrontendClientError(
            FrontendClientCode.INVALID_CONFIGURATION,
            "URL must be a non-empty HTTP(S) origin.",
        )
    cleaned = url.strip()
    parsed = urlsplit(cleaned)
    try:
        _ = parsed.port
    except ValueError:
        raise FrontendClientError(
            FrontendClientCode.INVALID_CONFIGURATION,
            "URL contains an invalid port.",
        ) from None
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (not allow_path and parsed.path)
        or (allow_path and parsed.path not in {"", "/"})
    ):
        raise FrontendClientError(
            FrontendClientCode.INVALID_CONFIGURATION,
            "URL must be a canonical HTTP or HTTPS origin without credentials or query parameters.",
        )
    loopback_hosts = {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme == "http" and parsed.hostname.lower() not in loopback_hosts:
        raise FrontendClientError(
            FrontendClientCode.INVALID_CONFIGURATION,
            "Plain HTTP is restricted to loopback addresses (127.0.0.1 / localhost).",
        )
    return f"{parsed.scheme}://{parsed.netloc.lower()}"


class SheetSafeApiClient:
    """Bounded, security-preserving HTTP client for the SheetSafe AI FastAPI backend."""

    def __init__(
        self,
        api_base_url: str = DEFAULT_API_BASE_URL,
        client_origin: str = DEFAULT_CLIENT_ORIGIN,
        *,
        connect_timeout_seconds: float = 2.0,
        read_timeout_seconds: float = 5.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._api_base_url = validate_canonical_origin(api_base_url)
        self._client_origin = validate_canonical_origin(client_origin)
        if not (0.1 <= connect_timeout_seconds <= 10.0 and 0.2 <= read_timeout_seconds <= 15.0):
            raise FrontendClientError(
                FrontendClientCode.INVALID_CONFIGURATION,
                "HTTP timeouts must stay within bounded limits.",
            )
        self._timeout = httpx.Timeout(
            connect=connect_timeout_seconds,
            read=read_timeout_seconds,
            write=connect_timeout_seconds,
            pool=connect_timeout_seconds,
        )
        self._transport = transport
        self._sealed_session: _SealedSessionJar | None = None

    def __repr__(self) -> str:
        active_id = self._sealed_session.view.session_id if self._sealed_session else None
        return (
            f"<SheetSafeApiClient api_base_url={self._api_base_url!r} "
            f"client_origin={self._client_origin!r} active_session_id={active_id!r}>"
        )

    @property
    def api_base_url(self) -> str:
        return self._api_base_url

    @property
    def client_origin(self) -> str:
        return self._client_origin

    @property
    def active_session(self) -> ActiveSessionView | None:
        return self._sealed_session.view if self._sealed_session is not None else None

    def clear_local_session(self) -> None:
        self._sealed_session = None

    def _require_sealed_session(self) -> _SealedSessionJar:
        if self._sealed_session is None:
            raise FrontendClientError(
                FrontendClientCode.UNAUTHENTICATED,
                "An active authenticated session is required.",
            )
        return self._sealed_session

    def _request_raw(
        self,
        method: Literal["GET", "POST", "DELETE"],
        path: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: dict[str, object] | None = None,
    ) -> tuple[int, httpx.Headers, bytes]:
        if not path.startswith("/api/v1/"):
            raise FrontendClientError(
                FrontendClientCode.INVALID_CONFIGURATION,
                "Only versioned /api/v1/ endpoints are permitted.",
            )
        url = f"{self._api_base_url}{path}"
        req_headers = {"Accept": "application/json", **(headers or {})}
        content: bytes | None = None
        if json_body is not None:
            content = json.dumps(json_body, separators=(",", ":"), allow_nan=False).encode("utf-8")
            req_headers["Content-Type"] = "application/json"

        try:
            with httpx.Client(
                transport=self._transport,
                timeout=self._timeout,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                request = client.build_request(method, url, headers=req_headers, content=content)
                response = client.send(request, stream=True)
                try:
                    buffer = bytearray()
                    for chunk in response.iter_bytes(chunk_size=4096):
                        buffer.extend(chunk)
                        if len(buffer) > MAX_API_RESPONSE_BYTES:
                            raise FrontendClientError(
                                FrontendClientCode.MALFORMED_RESPONSE,
                                "Backend response exceeded the safety size limit.",
                                status_code=response.status_code,
                            )
                    return response.status_code, response.headers, bytes(buffer)
                finally:
                    response.close()
        except FrontendClientError:
            raise
        except httpx.TimeoutException:
            raise FrontendClientError(
                FrontendClientCode.BACKEND_TIMEOUT,
                "FastAPI backend timed out while responding.",
                retryable=True,
            ) from None
        except httpx.HTTPError:
            raise FrontendClientError(
                FrontendClientCode.BACKEND_UNREACHABLE,
                "FastAPI backend is unreachable at the configured address.",
                retryable=True,
            ) from None

    @staticmethod
    def _parse_json(raw: bytes) -> dict[str, object]:
        if not raw or len(raw) > MAX_API_RESPONSE_BYTES:
            raise FrontendClientError(
                FrontendClientCode.MALFORMED_RESPONSE,
                "Backend returned an empty or oversized payload.",
            )

        def unique_pairs(items: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in items:
                if key in result:
                    raise ValueError("Duplicate JSON key")
                result[key] = value
            return result

        def reject_constant(_: str) -> None:
            raise ValueError("Invalid JSON constant")

        try:
            parsed = json.loads(
                raw.decode("utf-8", errors="strict"),
                object_pairs_hook=unique_pairs,
                parse_constant=reject_constant,
            )
        except Exception:
            raise FrontendClientError(
                FrontendClientCode.MALFORMED_RESPONSE,
                "Backend returned malformed JSON.",
            ) from None
        if type(parsed) is not dict:
            raise FrontendClientError(
                FrontendClientCode.MALFORMED_RESPONSE,
                "Backend JSON payload must be an object.",
            )
        return parsed

    def _raise_api_error(self, status_code: int, headers: httpx.Headers, raw: bytes) -> None:
        retry_after_hdr = headers.get("Retry-After")
        retry_after = (
            int(retry_after_hdr)
            if retry_after_hdr and re.fullmatch(r"[0-9]{1,4}", retry_after_hdr.strip())
            else None
        )
        backend_code: str | None = None
        try:
            envelope = ApiErrorEnvelope.model_validate(self._parse_json(raw))
            request_id = envelope.request_id
            message = envelope.message
            retryable = envelope.retryable
            backend_code = envelope.code
        except Exception:
            request_id = headers.get("X-Request-ID")
            message = "Request was rejected by the backend control plane."
            retryable = status_code in {429, 503, 504}

        mapping = {
            400: FrontendClientCode.INVALID_REQUEST,
            401: FrontendClientCode.UNAUTHENTICATED,
            403: FrontendClientCode.FORBIDDEN,
            404: FrontendClientCode.NOT_FOUND,
            409: FrontendClientCode.CONFLICT,
            422: FrontendClientCode.UNPROCESSABLE_REQUEST,
            429: FrontendClientCode.RATE_LIMITED,
            502: FrontendClientCode.UPSTREAM_CONTRACT_ERROR,
            503: FrontendClientCode.NOT_READY if "ready" in message.lower() else FrontendClientCode.SERVICE_UNAVAILABLE,
            504: FrontendClientCode.BACKEND_TIMEOUT,
        }
        code = mapping.get(status_code, FrontendClientCode.SERVICE_UNAVAILABLE)
        raise FrontendClientError(
            code,
            message,
            status_code=status_code,
            retryable=retryable,
            request_id=request_id,
            retry_after=retry_after,
            backend_code=backend_code,
        )

    def check_health(self) -> HealthStatus:
        """Call GET /api/v1/health on the FastAPI backend."""
        status_code, headers, raw = self._request_raw("GET", "/api/v1/health")
        if status_code != 200:
            self._raise_api_error(status_code, headers, raw)
        try:
            return HealthStatus.model_validate(self._parse_json(raw))
        except Exception:
            raise FrontendClientError(
                FrontendClientCode.MALFORMED_RESPONSE,
                "Invalid health response schema from backend.",
            ) from None

    def check_ready(self) -> ReadyStatus:
        """Call GET /api/v1/ready on the FastAPI backend."""
        status_code, headers, raw = self._request_raw("GET", "/api/v1/ready")
        if status_code != 200:
            self._raise_api_error(status_code, headers, raw)
        try:
            return ReadyStatus.model_validate(self._parse_json(raw))
        except Exception:
            raise FrontendClientError(
                FrontendClientCode.MALFORMED_RESPONSE,
                "Invalid readiness response schema from backend.",
            ) from None

    def probe_backend_status(self) -> BackendStatusSnapshot:
        """Check both /api/v1/health and /api/v1/ready and return a structured status snapshot."""
        try:
            self.check_health()
        except FrontendClientError as exc:
            return BackendStatusSnapshot(
                api_base_url=self._api_base_url,
                reachable=False,
                liveness_ok=False,
                readiness_ok=False,
                status_label="OFFLINE",
                detail_message=exc.safe_message,
                request_id=exc.request_id,
            )

        try:
            self.check_ready()
            return BackendStatusSnapshot(
                api_base_url=self._api_base_url,
                reachable=True,
                liveness_ok=True,
                readiness_ok=True,
                status_label="ONLINE & READY",
                detail_message="FastAPI process, SQLite WAL integrity, private storage, and retention worker are ready.",
            )
        except FrontendClientError as exc:
            return BackendStatusSnapshot(
                api_base_url=self._api_base_url,
                reachable=True,
                liveness_ok=True,
                readiness_ok=False,
                status_label="DEGRADED (NOT READY)",
                detail_message=exc.safe_message,
                request_id=exc.request_id,
            )

    def create_synthetic_session(self) -> ActiveSessionView:
        """Bootstrap a synthetic session via POST /api/v1/sessions preserving HttpOnly cookie & CSRF rules."""
        status_code, headers, raw = self._request_raw(
            "POST",
            "/api/v1/sessions",
            headers={
                "Origin": self._client_origin,
                "X-SheetSafe-Request": "1",
            },
            json_body={"mode": "synthetic"},
        )
        if status_code != 201:
            self._raise_api_error(status_code, headers, raw)

        payload = self._parse_json(raw)
        session_id = payload.get("session_id")
        expires_at = payload.get("expires_at")
        lifetime_seconds = payload.get("lifetime_seconds")
        mode = payload.get("mode")
        private_uploads = payload.get("private_uploads_enabled")
        csrf_token = payload.get("csrf_token")

        if (
            type(session_id) is not str
            or not re.fullmatch(r"[0-9a-f]{32}", session_id)
            or type(expires_at) is not int
            or type(lifetime_seconds) is not int
            or mode != "synthetic"
            or private_uploads is not False
            or type(csrf_token) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", csrf_token)
        ):
            raise FrontendClientError(
                FrontendClientCode.MALFORMED_RESPONSE,
                "Session response violated the expected security schema.",
            )

        set_cookie_header = headers.get("set-cookie")
        if not set_cookie_header:
            raise FrontendClientError(
                FrontendClientCode.MALFORMED_RESPONSE,
                "Backend did not issue the required HttpOnly session cookie.",
            )
        parsed_cookie = SimpleCookie()
        parsed_cookie.load(set_cookie_header)
        cookie_name: Literal["__Host-sheetsafe_session", "sheetsafe_dev_session"] | None = None
        morsel = None
        for candidate_name in ("__Host-sheetsafe_session", "sheetsafe_dev_session"):
            if candidate_name in parsed_cookie:
                cookie_name = candidate_name
                morsel = parsed_cookie[candidate_name]
                break

        if (
            cookie_name is None
            or morsel is None
            or not re.fullmatch(r"[A-Za-z0-9_-]{43}", morsel.value)
            or not morsel["httponly"]
            or morsel["samesite"].lower() != "strict"
        ):
            raise FrontendClientError(
                FrontendClientCode.MALFORMED_RESPONSE,
                "Issued session cookie is missing required HttpOnly/SameSite=Strict attributes.",
            )

        view = ActiveSessionView(
            session_id=session_id,
            expires_at=expires_at,
            lifetime_seconds=lifetime_seconds,
            mode="synthetic",
            private_uploads_enabled=False,
            cookie_name=cookie_name,
        )
        self._sealed_session = _SealedSessionJar(
            view=view,
            _cookie_value=SecretStr(morsel.value),
            _csrf_token=SecretStr(csrf_token),
        )
        return view

    def revoke_active_session(self) -> SessionDeletionReceiptView:
        """Immediately revoke the active session via DELETE /api/v1/sessions/{session_id}."""
        jar = self._require_sealed_session()
        cookie_header = f"{jar.view.cookie_name}={jar._cookie_value.get_secret_value()}"
        status_code, headers, raw = self._request_raw(
            "DELETE",
            f"/api/v1/sessions/{jar.view.session_id}",
            headers={
                "Origin": self._client_origin,
                "X-CSRF-Token": jar._csrf_token.get_secret_value(),
                "Cookie": cookie_header,
            },
        )
        if status_code != 200:
            if status_code == 401:
                self._sealed_session = None
            self._raise_api_error(status_code, headers, raw)

        payload = self._parse_json(raw)
        try:
            receipt = SessionDeletionReceiptView.model_validate({
                **payload,
                "request_id": headers.get("X-Request-ID"),
            })
        except Exception:
            raise FrontendClientError(
                FrontendClientCode.MALFORMED_RESPONSE,
                "Invalid deletion receipt returned by the backend.",
            ) from None

        self._sealed_session = None
        return receipt

    def bootstrap_synthetic_dataset(self) -> SyntheticDatasetView:
        """Provision or retrieve the session-owned synthetic demonstration dataset."""
        jar = self._require_sealed_session()
        cookie_header = f"{jar.view.cookie_name}={jar._cookie_value.get_secret_value()}"
        status_code, headers, raw = self._request_raw(
            "POST",
            "/api/v1/planning/synthetic-dataset",
            headers={
                "Origin": self._client_origin,
                "X-CSRF-Token": jar._csrf_token.get_secret_value(),
                "Cookie": cookie_header,
            },
            json_body={},
        )
        if status_code != 200:
            if status_code == 401:
                self._sealed_session = None
            self._raise_api_error(status_code, headers, raw)

        payload = _coerce_tuples(self._parse_json(raw))
        if type(payload) is not dict:
            raise FrontendClientError(
                FrontendClientCode.MALFORMED_RESPONSE,
                "Invalid synthetic dataset payload.",
            )
        try:
            return SyntheticDatasetView.model_validate({
                **payload,
                "request_id": headers.get("X-Request-ID"),
            })
        except Exception:
            raise FrontendClientError(
                FrontendClientCode.MALFORMED_RESPONSE,
                "Backend returned an invalid synthetic dataset schema.",
            ) from None

    def create_planning_preview(
        self,
        question: str,
        *,
        dataset_id: str | None = None,
    ) -> PlanningPreviewView:
        """Call POST /api/v1/planning/preview for an authenticated session."""
        jar = self._require_sealed_session()
        cookie_header = f"{jar.view.cookie_name}={jar._cookie_value.get_secret_value()}"
        body: dict[str, object] = {"question": question}
        if dataset_id is not None:
            body["dataset_id"] = dataset_id
        status_code, headers, raw = self._request_raw(
            "POST",
            "/api/v1/planning/preview",
            headers={
                "Origin": self._client_origin,
                "X-CSRF-Token": jar._csrf_token.get_secret_value(),
                "Cookie": cookie_header,
            },
            json_body=body,
        )
        if status_code != 200:
            if status_code == 401:
                self._sealed_session = None
            self._raise_api_error(status_code, headers, raw)

        payload = _coerce_tuples(self._parse_json(raw))
        if type(payload) is not dict:
            raise FrontendClientError(
                FrontendClientCode.MALFORMED_RESPONSE,
                "Invalid planning preview payload.",
            )
        try:
            return PlanningPreviewView.model_validate({
                **payload,
                "request_id": headers.get("X-Request-ID"),
            })
        except Exception:
            raise FrontendClientError(
                FrontendClientCode.MALFORMED_RESPONSE,
                "Backend returned an invalid planning preview schema.",
            ) from None

    def list_planning_runs(self) -> tuple[PersistedRunSummaryView, ...]:
        """Call GET /api/v1/planning/runs for the active session."""
        jar = self._require_sealed_session()
        cookie_header = f"{jar.view.cookie_name}={jar._cookie_value.get_secret_value()}"
        status_code, headers, raw = self._request_raw(
            "GET",
            "/api/v1/planning/runs",
            headers={"Cookie": cookie_header},
        )
        if status_code != 200:
            if status_code == 401:
                self._sealed_session = None
            self._raise_api_error(status_code, headers, raw)

        payload = _coerce_tuples(self._parse_json(raw))
        try:
            parsed = SessionRunsListView.model_validate(payload)
            return parsed.runs
        except Exception:
            raise FrontendClientError(
                FrontendClientCode.MALFORMED_RESPONSE,
                "Backend returned an invalid runs list schema.",
            ) from None

    def submit_dataset_upload(self, *_args: object, **_kwargs: object) -> None:
        """Explicitly fail closed: real upload routes are disabled until parser sandbox gates pass."""
        raise FrontendClientError(
            FrontendClientCode.FEATURE_DISABLED_BY_GATE,
            "Dataset upload submission is disabled until native Linux parser sandbox acceptance (SEC01-SEC10) and PRD transport amendments (AM01-AM04) are approved.",
        )

    def submit_analysis_run(self, *_args: object, **_kwargs: object) -> None:
        """Explicitly fail closed: live code execution requires a verified Linux sandbox."""
        raise FrontendClientError(
            FrontendClientCode.FEATURE_DISABLED_BY_GATE,
            "Generated-code execution and sandboxed container dispatch are disabled until native Linux runner acceptance (SEC01-SEC10) is active.",
        )
