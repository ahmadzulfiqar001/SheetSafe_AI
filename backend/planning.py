"""Step 9B AI analysis-planning service connecting FastAPI sessions to Step 9A inference.

Security and architectural invariants:
- Requires an active authenticated synthetic session (`require_active_session`).
- Never enables real file uploads, generated-code execution, Docker containers, or
  live external Vultr network calls (`allow_live_network=False`).
- Never fabricates a `READY` state for `PENDING` or unvalidated datasets.
- Permits a clearly labeled, server-owned synthetic demonstration fixture only when
  `settings.synthetic_planning_enabled` is explicitly enabled in non-production.
- Executes external/mocked provider calls outside SQLite writer transactions and
  re-verifies session activity and run cancellation before persisting plans.
- Never transitions runs to `COMPLETE` or publishes unverified analytical results.
"""

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
import hashlib
import json
import re
import sqlite3
import time
from typing import Literal
from uuid import uuid4

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from backend.config import Settings, VULTR_INFERENCE_BASE_URL
from backend.inference import (
    AIAnalysisPlan,
    AIClarificationNeeded,
    AIPlanningEnvelope,
    CHAT_COMPLETIONS_URL,
    InferenceCode,
    InferenceError,
    UserAnalysisQuestion,
    ValidatedDatasetSchema,
    VultrInferenceClient,
    build_validated_dataset_schema,
    validate_user_question,
)
from backend.security.authorization import owned_dataset, owned_run
from backend.security.sessions import SessionError, SessionPrincipal, require_active_session
from backend.storage.database import Database, DatabaseVersionError
from backend.storage.files import PrivateStorage
from ingestion.contracts import ColumnProfile, DatasetProfile


SYNTHETIC_FIXTURE_ID = "synthetic_quarterly_revenue_v1"
SYNTHETIC_FIXTURE_IDEMPOTENCY_KEY = f"synthetic-fixture:{SYNTHETIC_FIXTURE_ID}"
SYNTHETIC_FIXTURE_LABEL = (
    "DEMO / SYNTHETIC FIXTURE — Quarterly Regional Revenue & Headcount "
    "(Server-Owned Offline Dataset)"
)
SIMULATED_PROVIDER_LABEL = (
    "DEMO / SIMULATED — Deterministic HTTPX Mock Transport (Not Live Vultr Output)"
)
SIMULATED_MODEL_ID = "simulated-planner-v1"
_SIMULATED_API_KEY = SecretStr("simulated_offline_key_not_a_real_secret")

# Server-owned synthetic CSV bytes sealed into the session's PrivateStorage namespace
# so PrivateStorage.remove_and_verify() can verify and clean up the object normally.
SYNTHETIC_FIXTURE_CSV_BYTES = (
    b"quarter,department,region,revenue_usd,headcount\n"
    b"2025-03-31,Enterprise,North America,425000.50,42\n"
    b"2025-03-31,MidMarket,Europe,198500.00,24\n"
    b"2025-06-30,Enterprise,North America,462100.75,45\n"
    b"2025-06-30,Commercial,Asia Pacific,154200.25,19\n"
    b"2025-09-30,MidMarket,Europe,215800.00,26\n"
)

SYNTHETIC_FIXTURE_PROFILE = DatasetProfile(
    selected_worksheet=None,
    delimiter=",",
    row_count=5,
    column_count=5,
    nonempty_cells=30,
    columns=(
        ColumnProfile(
            column_id="col_001",
            name="quarter",
            inferred_type="date",
            missing_count=0,
        ),
        ColumnProfile(
            column_id="col_002",
            name="department",
            inferred_type="text",
            missing_count=0,
        ),
        ColumnProfile(
            column_id="col_003",
            name="region",
            inferred_type="text",
            missing_count=0,
        ),
        ColumnProfile(
            column_id="col_004",
            name="revenue_usd",
            inferred_type="number",
            missing_count=0,
        ),
        ColumnProfile(
            column_id="col_005",
            name="headcount",
            inferred_type="integer",
            missing_count=0,
        ),
    ),
    preview=(
        ("2025-03-31", "Enterprise", "North America", "425000.50", "42"),
        ("2025-03-31", "MidMarket", "Europe", "198500.00", "24"),
        ("2025-06-30", "Enterprise", "North America", "462100.75", "45"),
        ("2025-06-30", "Commercial", "Asia Pacific", "154200.25", "19"),
        ("2025-09-30", "MidMarket", "Europe", "215800.00", "26"),
    ),
    warnings=(),
)


class PlanningCode(StrEnum):
    SYNTHETIC_PLANNING_DISABLED = "SYNTHETIC_PLANNING_DISABLED"
    DATASET_NOT_READY = "DATASET_NOT_READY"
    RUN_CANCELLED = "RUN_CANCELLED"
    INVALID_QUESTION = "INVALID_QUESTION"
    PROMPT_INJECTION_DETECTED = "PROMPT_INJECTION_DETECTED"
    SENSITIVE_METADATA_BLOCKED = "SENSITIVE_METADATA_BLOCKED"
    UNKNOWN_COLUMN_REFERENCE = "UNKNOWN_COLUMN_REFERENCE"
    UNSAFE_OPERATION_REJECTED = "UNSAFE_OPERATION_REJECTED"
    INVALID_PLAN_CONTRACT = "INVALID_PLAN_CONTRACT"
    MALFORMED_PROVIDER_RESPONSE = "MALFORMED_PROVIDER_RESPONSE"
    PROVIDER_TIMEOUT = "PROVIDER_TIMEOUT"
    RATE_LIMITED = "RATE_LIMITED"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"


PLANNING_ERROR_TABLE: dict[PlanningCode, tuple[int, str, bool]] = {
    PlanningCode.SYNTHETIC_PLANNING_DISABLED: (
        403,
        "Synthetic fixture planning is disabled in this environment.",
        False,
    ),
    PlanningCode.DATASET_NOT_READY: (
        409,
        "Dataset is not in READY state for analysis planning.",
        False,
    ),
    PlanningCode.RUN_CANCELLED: (
        409,
        "Analysis run was cancelled before planning completed.",
        False,
    ),
    PlanningCode.INVALID_QUESTION: (
        400,
        "Analysis question must be between 3 and 500 valid characters.",
        False,
    ),
    PlanningCode.PROMPT_INJECTION_DETECTED: (
        422,
        "Question or metadata contains disallowed instruction-override or capability patterns.",
        False,
    ),
    PlanningCode.SENSITIVE_METADATA_BLOCKED: (
        422,
        "Question or metadata contains restricted personal or secret identifiers.",
        False,
    ),
    PlanningCode.UNKNOWN_COLUMN_REFERENCE: (
        422,
        "AI plan referenced a column that does not match the validated dataset schema.",
        False,
    ),
    PlanningCode.UNSAFE_OPERATION_REJECTED: (
        422,
        "AI plan proposed an unsupported or unsafe operation.",
        False,
    ),
    PlanningCode.INVALID_PLAN_CONTRACT: (
        502,
        "AI provider returned a plan that failed schema or contract validation.",
        False,
    ),
    PlanningCode.MALFORMED_PROVIDER_RESPONSE: (
        502,
        "AI provider returned an unreadable or malformed response.",
        False,
    ),
    PlanningCode.PROVIDER_TIMEOUT: (
        504,
        "AI inference provider timed out while generating a plan.",
        True,
    ),
    PlanningCode.RATE_LIMITED: (
        429,
        "Planning request rate limit reached. Try again later.",
        True,
    ),
    PlanningCode.PROVIDER_UNAVAILABLE: (
        503,
        "AI inference provider is currently unavailable.",
        True,
    ),
}


class PlanningError(Exception):
    """Sanitized planning workflow exception mapped to safe JSON ErrorResponse."""

    def __init__(self, code: PlanningCode, *, retry_after: int | None = None) -> None:
        super().__init__(code.value)
        status_code, message, retryable = PLANNING_ERROR_TABLE[code]
        self.code = code
        self.status_code = status_code
        self.safe_message = message
        self.retryable = retryable
        self.retry_after = retry_after if (type(retry_after) is int and 1 <= retry_after <= 3600) else None


class StrictPlanningContract(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid", hide_input_in_errors=True)


class SyntheticDatasetSnapshot(StrictPlanningContract):
    """Metadata for the session-owned synthetic demonstration dataset."""

    dataset_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    session_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    version: Literal[1] = 1
    state: Literal["READY"] = "READY"
    is_synthetic_fixture: Literal[True] = True
    fixture_id: Literal["synthetic_quarterly_revenue_v1"] = SYNTHETIC_FIXTURE_ID
    fixture_label: str = SYNTHETIC_FIXTURE_LABEL
    dataset_schema: ValidatedDatasetSchema


class PlanningPreviewOutcome(StrictPlanningContract):
    """Validated, persisted planning preview response returned by FastAPI."""

    run_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    session_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    dataset_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    dataset_version: int = Field(ge=1)
    run_state: Literal["AWAIT_CONFIRMATION", "NEEDS_CLARIFICATION"]
    provider_mode: Literal["SIMULATED_MOCK"] = "SIMULATED_MOCK"
    simulated_response: Literal[True] = True
    provider_label: str = SIMULATED_PROVIDER_LABEL
    is_synthetic_dataset: bool = True
    execution_enabled: Literal[False] = False
    model: str = Field(min_length=1, max_length=96)
    question: str = Field(min_length=3, max_length=500)
    dataset_schema: ValidatedDatasetSchema
    envelope: AIPlanningEnvelope
    plan_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class PersistedRunSummary(StrictPlanningContract):
    """Summary of a session-owned planning run stored in SQLite."""

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
    expected_result_type: str | None = None
    intent_summary: str | None = None
    clarification_reason: str | None = None
    created_at: int = Field(gt=0)
    updated_at: int = Field(gt=0)


def build_deterministic_mock_transport() -> httpx.MockTransport:
    """Build a deterministic in-memory HTTPX MockTransport for offline Step 9B planning.

    Inspects the outbound Vultr chat/completions payload generated by
    `VultrInferenceClient.plan_analysis()` and produces a deterministic
    `AIPlanningEnvelope` bound to the actual `dataset_schema`.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method != "POST" or str(request.url) != CHAT_COMPLETIONS_URL:
            return httpx.Response(404, json={"error": "Not found"})

        try:
            body = json.loads(request.content.decode("utf-8"))
            messages = body["messages"]
            user_content = json.loads(messages[1]["content"])
            question_text = str(user_content["untrusted_user_question"]).lower()
            ds_schema = user_content["dataset_schema"]
            schema_sha256 = ds_schema["schema_sha256"]
            columns = ds_schema["columns"]
        except Exception:
            return httpx.Response(400, json={"error": "Invalid request payload"})

        col_by_name = {c["name"]: c for c in columns}
        col_by_id = {c["column_id"]: c for c in columns}

        # Deterministic clarification trigger when the user asks an ambiguous question
        if any(
            token in question_text
            for token in ("ambiguous", "unclear", "which metric", "best performance", "compare performance")
        ):
            candidate_ids = [
                c["column_id"]
                for c in columns
                if c["inferred_type"] in {"number", "integer"}
            ][:2]
            envelope_dict = {
                "version": 1,
                "status": "CLARIFICATION_REQUIRED",
                "clarification": {
                    "version": 1,
                    "reason_code": "AMBIGUOUS_METRIC",
                    "clarification_prompt": (
                        "Please clarify whether you want to analyze revenue_usd (col_004) "
                        "or headcount (col_005), and how records should be grouped."
                    ),
                    "candidate_columns": candidate_ids,
                },
            }
        elif "ratio" in question_text or "per headcount" in question_text or "per employee" in question_text:
            rev_col = col_by_name.get("revenue_usd") or col_by_id.get("col_004") or columns[0]
            hc_col = col_by_name.get("headcount") or col_by_id.get("col_005") or columns[-1]
            envelope_dict = {
                "version": 1,
                "status": "PLAN_READY",
                "plan": {
                    "version": 1,
                    "schema_sha256": schema_sha256,
                    "intent_summary": (
                        "Compute the ratio of revenue_usd to headcount across validated records "
                        "(DEMO / SIMULATED offline plan)."
                    ),
                    "required_columns": [
                        {
                            "column_id": rev_col["column_id"],
                            "name": rev_col["name"],
                            "expected_type": rev_col["inferred_type"],
                        },
                        {
                            "column_id": hc_col["column_id"],
                            "name": hc_col["name"],
                            "expected_type": hc_col["inferred_type"],
                        },
                    ],
                    "operations": [
                        {
                            "step_number": 1,
                            "operation": "COMPUTE_RATIO",
                            "target_columns": [rev_col["column_id"], hc_col["column_id"]],
                            "group_by_columns": [],
                            "rationale": "Compute revenue per headcount using safe zero-division handling.",
                        }
                    ],
                    "expected_result_type": "SUMMARY_TABLE",
                },
            }
        elif "quarter" in question_text or "trend" in question_text or "time" in question_text:
            date_col = col_by_name.get("quarter") or col_by_id.get("col_001") or columns[0]
            rev_col = col_by_name.get("revenue_usd") or col_by_id.get("col_004") or columns[-1]
            envelope_dict = {
                "version": 1,
                "status": "PLAN_READY",
                "plan": {
                    "version": 1,
                    "schema_sha256": schema_sha256,
                    "intent_summary": (
                        "Roll up quarterly revenue_usd over quarter dates in chronological order "
                        "(DEMO / SIMULATED offline plan)."
                    ),
                    "required_columns": [
                        {
                            "column_id": date_col["column_id"],
                            "name": date_col["name"],
                            "expected_type": date_col["inferred_type"],
                        },
                        {
                            "column_id": rev_col["column_id"],
                            "name": rev_col["name"],
                            "expected_type": rev_col["inferred_type"],
                        },
                    ],
                    "operations": [
                        {
                            "step_number": 1,
                            "operation": "TIME_SERIES_ROLLUP",
                            "target_columns": [date_col["column_id"], rev_col["column_id"]],
                            "group_by_columns": [],
                            "rationale": "Aggregate revenue_usd across verified quarter date periods.",
                        },
                        {
                            "step_number": 2,
                            "operation": "SORT_VALUES",
                            "target_columns": [date_col["column_id"]],
                            "group_by_columns": [],
                            "sort_direction": "asc",
                            "rationale": "Order quarterly rollup chronologically from earliest to latest.",
                        },
                    ],
                    "expected_result_type": "TIME_SERIES_TABLE",
                },
            }
        else:
            # Default grouped aggregation plan
            group_col = (
                col_by_name.get("region")
                if "region" in question_text and "region" in col_by_name
                else col_by_name.get("department") or col_by_id.get("col_002") or columns[0]
            )
            metric_col = (
                col_by_name.get("headcount")
                if "headcount" in question_text and "headcount" in col_by_name
                else col_by_name.get("revenue_usd") or col_by_id.get("col_004") or columns[-1]
            )
            if group_col["column_id"] == metric_col["column_id"] and len(columns) >= 2:
                group_col = columns[0]
                metric_col = columns[1]

            if metric_col["inferred_type"] in {"number", "integer"} and group_col["column_id"] != metric_col["column_id"]:
                envelope_dict = {
                    "version": 1,
                    "status": "PLAN_READY",
                    "plan": {
                        "version": 1,
                        "schema_sha256": schema_sha256,
                        "intent_summary": (
                            f"Group records by {group_col['name']} and compute total {metric_col['name']} "
                            f"sorted highest to lowest (DEMO / SIMULATED offline plan)."
                        ),
                        "required_columns": [
                            {
                                "column_id": group_col["column_id"],
                                "name": group_col["name"],
                                "expected_type": group_col["inferred_type"],
                            },
                            {
                                "column_id": metric_col["column_id"],
                                "name": metric_col["name"],
                                "expected_type": metric_col["inferred_type"],
                            },
                        ],
                        "operations": [
                            {
                                "step_number": 1,
                                "operation": "GROUP_AGGREGATE",
                                "target_columns": [metric_col["column_id"]],
                                "group_by_columns": [group_col["column_id"]],
                                "aggregation": "sum",
                                "rationale": f"Sum {metric_col['name']} grouped by {group_col['name']}.",
                            },
                            {
                                "step_number": 2,
                                "operation": "SORT_VALUES",
                                "target_columns": [metric_col["column_id"]],
                                "group_by_columns": [],
                                "sort_direction": "desc",
                                "rationale": f"Rank grouped {metric_col['name']} totals from highest to lowest.",
                            },
                        ],
                        "expected_result_type": "GROUPED_TABLE",
                    },
                }
            else:
                first_col = columns[0]
                envelope_dict = {
                    "version": 1,
                    "status": "PLAN_READY",
                    "plan": {
                        "version": 1,
                        "schema_sha256": schema_sha256,
                        "intent_summary": (
                            f"Select and sort {first_col['name']} records (DEMO / SIMULATED offline plan)."
                        ),
                        "required_columns": [
                            {
                                "column_id": first_col["column_id"],
                                "name": first_col["name"],
                                "expected_type": first_col["inferred_type"],
                            }
                        ],
                        "operations": [
                            {
                                "step_number": 1,
                                "operation": "SELECT_COLUMNS",
                                "target_columns": [first_col["column_id"]],
                                "group_by_columns": [],
                                "rationale": f"Project validated column {first_col['name']}.",
                            }
                        ],
                        "expected_result_type": "SUMMARY_TABLE",
                    },
                }

        return httpx.Response(
            200,
            json={
                "id": "chatcmpl_simulated_step9b",
                "model": body.get("model", SIMULATED_MODEL_ID),
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {
                            "role": "assistant",
                            "content": json.dumps(envelope_dict, separators=(",", ":")),
                        },
                    }
                ],
                "usage": {
                    "prompt_tokens": 180,
                    "completion_tokens": 140,
                    "total_tokens": 320,
                },
            },
        )

    return httpx.MockTransport(handler)


def _map_inference_error(error: InferenceError) -> tuple[PlanningCode, str]:
    """Map Step 9A InferenceError to (PlanningCode, terminal_run_state)."""
    mapping: dict[InferenceCode, tuple[PlanningCode, str]] = {
        InferenceCode.INVALID_QUESTION: (PlanningCode.INVALID_QUESTION, "BLOCKED_POLICY"),
        InferenceCode.PROMPT_INJECTION_DETECTED: (PlanningCode.PROMPT_INJECTION_DETECTED, "BLOCKED_POLICY"),
        InferenceCode.SENSITIVE_METADATA_BLOCKED: (PlanningCode.SENSITIVE_METADATA_BLOCKED, "BLOCKED_POLICY"),
        InferenceCode.PROFILE_NOT_READY: (PlanningCode.DATASET_NOT_READY, "BLOCKED_POLICY"),
        InferenceCode.UNKNOWN_COLUMN_REFERENCE: (PlanningCode.UNKNOWN_COLUMN_REFERENCE, "BLOCKED_POLICY"),
        InferenceCode.UNSAFE_OPERATION_REJECTED: (PlanningCode.UNSAFE_OPERATION_REJECTED, "BLOCKED_POLICY"),
        InferenceCode.CODE_POLICY_VIOLATION: (PlanningCode.UNSAFE_OPERATION_REJECTED, "BLOCKED_POLICY"),
        InferenceCode.INVALID_PLAN_CONTRACT: (PlanningCode.INVALID_PLAN_CONTRACT, "BLOCKED_POLICY"),
        InferenceCode.MALFORMED_PROVIDER_RESPONSE: (
            PlanningCode.MALFORMED_PROVIDER_RESPONSE,
            "PROVIDER_UNAVAILABLE",
        ),
        InferenceCode.RESPONSE_TOO_LARGE: (
            PlanningCode.MALFORMED_PROVIDER_RESPONSE,
            "PROVIDER_UNAVAILABLE",
        ),
        InferenceCode.PROVIDER_TIMEOUT: (PlanningCode.PROVIDER_TIMEOUT, "TIMED_OUT"),
        InferenceCode.RATE_LIMITED: (PlanningCode.RATE_LIMITED, "PROVIDER_UNAVAILABLE"),
        InferenceCode.PROVIDER_UNAVAILABLE: (PlanningCode.PROVIDER_UNAVAILABLE, "PROVIDER_UNAVAILABLE"),
        InferenceCode.AUTHENTICATION_FAILED: (PlanningCode.PROVIDER_UNAVAILABLE, "PROVIDER_UNAVAILABLE"),
        InferenceCode.PERMISSION_DENIED: (PlanningCode.PROVIDER_UNAVAILABLE, "PROVIDER_UNAVAILABLE"),
        InferenceCode.MODEL_NOT_SUPPORTED: (PlanningCode.PROVIDER_UNAVAILABLE, "PROVIDER_UNAVAILABLE"),
        InferenceCode.NOT_CONFIGURED: (PlanningCode.PROVIDER_UNAVAILABLE, "PROVIDER_UNAVAILABLE"),
        InferenceCode.REQUEST_TOO_LARGE: (PlanningCode.INVALID_QUESTION, "BLOCKED_POLICY"),
        InferenceCode.TOKEN_BUDGET_EXCEEDED: (PlanningCode.PROVIDER_UNAVAILABLE, "PROVIDER_UNAVAILABLE"),
    }
    return mapping.get(error.code, (PlanningCode.PROVIDER_UNAVAILABLE, "PROVIDER_UNAVAILABLE"))


class PlanningService:
    """Narrowly scoped Step 9B AI analysis-planning service."""

    def __init__(
        self,
        database: Database,
        storage: PrivateStorage,
        settings: Settings,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.database = database
        self.storage = storage
        self.settings = settings
        self._transport = transport

    def _require_synthetic_gate(self) -> None:
        if not self.settings.synthetic_planning_enabled or self.settings.environment == "production":
            raise PlanningError(PlanningCode.SYNTHETIC_PLANNING_DISABLED)

    def _effective_inference_client(
        self, transport_override: httpx.BaseTransport | None = None,
    ) -> VultrInferenceClient:
        chosen_transport = (
            transport_override
            if transport_override is not None
            else self._transport
            if self._transport is not None
            else build_deterministic_mock_transport()
        )
        effective_settings = self.settings.model_copy(
            update={
                "vultr_inference_base_url": VULTR_INFERENCE_BASE_URL,
                "vultr_inference_api_key": (
                    self.settings.vultr_inference_api_key or _SIMULATED_API_KEY
                ),
                "vultr_inference_model": (
                    self.settings.vultr_inference_model or SIMULATED_MODEL_ID
                ),
            }
        )
        return VultrInferenceClient(
            effective_settings,
            transport=chosen_transport,
            allow_live_network=False,
        )

    def ensure_synthetic_dataset(self, principal: SessionPrincipal) -> SyntheticDatasetSnapshot:
        """Idempotently provision the server-owned synthetic dataset for the active session."""
        self._require_synthetic_gate()
        validated_schema = build_validated_dataset_schema(SYNTHETIC_FIXTURE_PROFILE)
        try:
            with self.database.connection() as connection:
                require_active_session(connection, principal)
                existing = connection.execute(
                    "SELECT * FROM datasets WHERE session_id=? AND idempotency_key=?",
                    (principal.session_id, SYNTHETIC_FIXTURE_IDEMPOTENCY_KEY),
                ).fetchone()
                if existing is not None:
                    owned_dataset(connection, principal, existing["dataset_id"])
                    ver = connection.execute(
                        "SELECT * FROM dataset_versions WHERE dataset_id=? AND version=1 AND session_id=?",
                        (existing["dataset_id"], principal.session_id),
                    ).fetchone()
                    if ver is None or ver["state"] != "READY":
                        raise PlanningError(PlanningCode.DATASET_NOT_READY)
                    return SyntheticDatasetSnapshot(
                        dataset_id=existing["dataset_id"],
                        session_id=principal.session_id,
                        dataset_schema=validated_schema,
                    )
        except (sqlite3.Error, OSError, DatabaseVersionError):
            raise SessionError(503) from None

        # Check if the session already has an original storage object (e.g., from a synthetic test)
        try:
            with self.database.connection() as connection:
                require_active_session(connection, principal)
                existing_obj = connection.execute(
                    "SELECT * FROM storage_objects WHERE session_id=? AND category='original' AND state='SEALED'",
                    (principal.session_id,),
                ).fetchone()
        except (sqlite3.Error, OSError, DatabaseVersionError):
            raise SessionError(503) from None

        if existing_obj is not None:
            raise PlanningError(PlanningCode.DATASET_NOT_READY)

        stored = self.storage.store(
            principal,
            category="original",
            file_type="csv",
            chunks=[SYNTHETIC_FIXTURE_CSV_BYTES],
            byte_count=len(SYNTHETIC_FIXTURE_CSV_BYTES),
        )
        parsing_settings = json.dumps(
            {"fixture_id": SYNTHETIC_FIXTURE_ID, "synthetic_demo": True},
            separators=(",", ":"),
        )
        profile_json = SYNTHETIC_FIXTURE_PROFILE.model_dump_json()
        fingerprint = hashlib.sha256(
            f"{stored.object_id}:{parsing_settings}".encode("utf-8")
        ).hexdigest()

        try:
            with self.database.transaction() as connection:
                require_active_session(connection, principal)
                now = self.database.now()
                dataset_id = uuid4().hex
                connection.execute(
                    """INSERT INTO datasets(
                        dataset_id, session_id, source_sha256, storage_ref,
                        file_type, byte_count, idempotency_key, request_sha256, created_at
                    ) VALUES (?, ?, ?, ?, 'csv', ?, ?, ?, ?)""",
                    (
                        dataset_id,
                        principal.session_id,
                        stored.sha256,
                        stored.object_id,
                        stored.byte_count,
                        SYNTHETIC_FIXTURE_IDEMPOTENCY_KEY,
                        fingerprint,
                        now,
                    ),
                )
                connection.execute(
                    """INSERT INTO dataset_versions(
                        dataset_id, version, session_id, parsing_settings_json,
                        profile_json, state, created_at
                    ) VALUES (?, 1, ?, ?, ?, 'READY', ?)""",
                    (
                        dataset_id,
                        principal.session_id,
                        parsing_settings,
                        profile_json,
                        now,
                    ),
                )
                self.database.append_audit_event(
                    connection,
                    session_pseudonym=principal.audit_pseudonym,
                    event_type="DATASET_CREATED",
                    build_version="0.1.0",
                    timestamp=now,
                    details={"byte_count": stored.byte_count, "source_sha256": stored.sha256},
                )
                self.database.append_audit_event(
                    connection,
                    session_pseudonym=principal.audit_pseudonym,
                    event_type="DATASET_PROFILED",
                    build_version="0.1.0",
                    timestamp=now,
                    details={"schema_sha256": validated_schema.schema_sha256},
                )
                return SyntheticDatasetSnapshot(
                    dataset_id=dataset_id,
                    session_id=principal.session_id,
                    dataset_schema=validated_schema,
                )
        except (sqlite3.Error, OSError, DatabaseVersionError):
            raise SessionError(503) from None

    def create_plan_preview(
        self,
        principal: SessionPrincipal,
        *,
        question: str,
        dataset_id: str | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> PlanningPreviewOutcome:
        """Execute the end-to-end Step 9B planning workflow with transactional state persistence."""
        # Validate question shape/security before any DB write or provider call
        try:
            validated_question: UserAnalysisQuestion = validate_user_question(question)
        except InferenceError as exc:
            plan_code, _ = _map_inference_error(exc)
            raise PlanningError(plan_code, retry_after=exc.retry_after) from None

        if dataset_id is None:
            snapshot = self.ensure_synthetic_dataset(principal)
            target_dataset_id = snapshot.dataset_id
        else:
            if type(dataset_id) is not str or not re.fullmatch(r"[0-9a-f]{32}", dataset_id):
                raise SessionError(404)
            target_dataset_id = dataset_id

        # Step 1: Pre-inference transaction — verify ownership, dataset state, rate limits, and create run
        try:
            with self.database.transaction() as connection:
                require_active_session(connection, principal)
                now = self.database.now()

                # Verify dataset ownership first (raises 404 if missing or owned by another session)
                ds_row = owned_dataset(connection, principal, target_dataset_id)
                ver_row = connection.execute(
                    "SELECT * FROM dataset_versions WHERE dataset_id=? AND version=1 AND session_id=?",
                    (ds_row["dataset_id"], principal.session_id),
                ).fetchone()
                if ver_row is None or ver_row["state"] != "READY":
                    raise PlanningError(PlanningCode.DATASET_NOT_READY)

                is_synthetic_dataset = (
                    ds_row["idempotency_key"] == SYNTHETIC_FIXTURE_IDEMPOTENCY_KEY
                )
                if is_synthetic_dataset:
                    self._require_synthetic_gate()

                try:
                    profile = DatasetProfile.model_validate_json(ver_row["profile_json"])
                    validated_schema = build_validated_dataset_schema(profile)
                except InferenceError as exc:
                    plan_code, _ = _map_inference_error(exc)
                    raise PlanningError(plan_code) from None
                except Exception:
                    raise PlanningError(PlanningCode.DATASET_NOT_READY) from None

                # Per-session planning rate limit and total run cap
                window_start = now - 60
                recent_count = connection.execute(
                    "SELECT COUNT(*) FROM runs WHERE session_id=? AND created_at>=?",
                    (principal.session_id, window_start),
                ).fetchone()[0]
                if recent_count >= self.settings.planning_requests_per_session_per_minute:
                    raise PlanningError(PlanningCode.RATE_LIMITED, retry_after=60)

                total_runs = connection.execute(
                    "SELECT COUNT(*) FROM runs WHERE session_id=?",
                    (principal.session_id,),
                ).fetchone()[0]
                if total_runs >= self.settings.max_runs_per_session:
                    raise PlanningError(PlanningCode.RATE_LIMITED, retry_after=60)

                run_id = uuid4().hex
                idempotency_key = f"plan-preview:{run_id}"
                request_sha256 = hashlib.sha256(
                    f"{target_dataset_id}:1:{validated_question.question}".encode("utf-8")
                ).hexdigest()

                connection.execute(
                    """INSERT INTO runs(
                        run_id, session_id, dataset_id, dataset_version, question,
                        interpretation_json, plan_json, state, state_version,
                        candidate_versions, execution_attempts, validation_status,
                        cleanup_status, created_at, updated_at, idempotency_key, request_sha256
                    ) VALUES (
                        ?, ?, ?, 1, ?, '{}', '{}', 'PLAN_AND_CODE', 1,
                        0, 0, 'PENDING', 'PENDING', ?, ?, ?, ?
                    )""",
                    (
                        run_id,
                        principal.session_id,
                        target_dataset_id,
                        validated_question.question,
                        now,
                        now,
                        idempotency_key,
                        request_sha256,
                    ),
                )
                self.database.append_audit_event(
                    connection,
                    session_pseudonym=principal.audit_pseudonym,
                    event_type="RUN_CREATED",
                    build_version="0.1.0",
                    run_id=run_id,
                    state="PLAN_AND_CODE",
                    timestamp=now,
                    details={"schema_sha256": validated_schema.schema_sha256},
                )
        except (SessionError, PlanningError):
            raise
        except (sqlite3.Error, OSError, DatabaseVersionError):
            raise SessionError(503) from None

        # Step 2: Provider call outside SQLite writer lock
        inference_client = self._effective_inference_client(transport)
        started_mono = time.monotonic()
        planning_result = None
        inference_error: InferenceError | None = None
        try:
            planning_result = inference_client.plan_analysis(
                profile=profile,
                question=validated_question,
                verify_model=False,
            )
        except InferenceError as exc:
            inference_error = exc
        duration_ms = max(0, int((time.monotonic() - started_mono) * 1000))

        # Step 3: Post-inference transaction — check cancellation/expiry race and persist state
        deferred_error: Exception | None = None
        outcome: PlanningPreviewOutcome | None = None
        try:
            with self.database.transaction() as connection:
                now = self.database.now()
                session_row = connection.execute(
                    """SELECT 1 FROM sessions WHERE session_id=? AND auth_token_hash=?
                        AND revoked_at IS NULL AND deletion_requested_at IS NULL
                        AND mode='synthetic' AND expires_at>?""",
                    (principal.session_id, principal.auth_token_hash, now),
                ).fetchone()
                run_row = connection.execute(
                    "SELECT * FROM runs WHERE run_id=? AND session_id=?",
                    (run_id, principal.session_id),
                ).fetchone()

                if session_row is None or run_row is None or run_row["cancel_requested_at"] is not None:
                    if run_row is not None and run_row["state"] != "CANCELLED":
                        updated_ts = max(now, int(run_row["created_at"]))
                        connection.execute(
                            """UPDATE runs SET state='CANCELLED', state_version=state_version+1,
                                updated_at=? WHERE run_id=?""",
                            (updated_ts, run_id),
                        )
                        self.database.append_audit_event(
                            connection,
                            session_pseudonym=principal.audit_pseudonym,
                            event_type="RUN_STATE_CHANGED",
                            build_version="0.1.0",
                            run_id=run_id,
                            state="CANCELLED",
                            timestamp=updated_ts,
                        )
                    deferred_error = (
                        SessionError(401)
                        if session_row is None
                        else PlanningError(PlanningCode.RUN_CANCELLED)
                    )
                elif inference_error is not None:
                    updated_ts = max(now, int(run_row["created_at"]))
                    plan_code, failure_state = _map_inference_error(inference_error)
                    connection.execute(
                        """UPDATE runs SET state=?, state_version=state_version+1,
                            updated_at=? WHERE run_id=?""",
                        (failure_state, updated_ts, run_id),
                    )
                    if failure_state == "BLOCKED_POLICY":
                        self.database.append_audit_event(
                            connection,
                            session_pseudonym=principal.audit_pseudonym,
                            event_type="POLICY_DECISION",
                            build_version="0.1.0",
                            run_id=run_id,
                            state="BLOCKED_POLICY",
                            timestamp=updated_ts,
                            details={
                                "check_passed": False,
                                "schema_sha256": validated_schema.schema_sha256,
                            },
                        )
                    self.database.append_audit_event(
                        connection,
                        session_pseudonym=principal.audit_pseudonym,
                        event_type="RUN_STATE_CHANGED",
                        build_version="0.1.0",
                        run_id=run_id,
                        state=failure_state,
                        timestamp=updated_ts,
                        details={"duration_ms": duration_ms},
                    )
                    deferred_error = PlanningError(plan_code, retry_after=inference_error.retry_after)
                else:
                    updated_ts = max(now, int(run_row["created_at"]))
                    assert planning_result is not None
                    envelope = planning_result.envelope
                    self.database.append_audit_event(
                        connection,
                        session_pseudonym=principal.audit_pseudonym,
                        event_type="INFERENCE_COMPLETED",
                        build_version="0.1.0",
                        run_id=run_id,
                        timestamp=updated_ts,
                        details={
                            "schema_sha256": planning_result.schema_sha256,
                            "input_tokens": planning_result.input_tokens,
                            "output_tokens": planning_result.output_tokens,
                            "retry_count": planning_result.retry_count,
                            "duration_ms": duration_ms,
                        },
                    )

                    if envelope.status == "PLAN_READY":
                        assert envelope.plan is not None
                        plan: AIAnalysisPlan = envelope.plan
                        plan_sha = plan.plan_sha256()
                        target_state: Literal["AWAIT_CONFIRMATION", "NEEDS_CLARIFICATION"] = "AWAIT_CONFIRMATION"
                        confirm_expires = min(principal.expires_at, updated_ts + 900)
                        interpretation_payload = {
                            "version": 1,
                            "status": "PLAN_READY",
                            "provider_mode": "SIMULATED_MOCK",
                            "simulated_response": True,
                            "model": planning_result.model,
                            "schema_sha256": planning_result.schema_sha256,
                            "plan_sha256": plan_sha,
                            "intent_summary": plan.intent_summary,
                            "expected_result_type": plan.expected_result_type,
                        }
                        connection.execute(
                            """UPDATE runs SET state=?, state_version=state_version+1,
                                interpretation_json=?, plan_json=?, confirmation_expires_at=?,
                                updated_at=? WHERE run_id=?""",
                            (
                                target_state,
                                json.dumps(interpretation_payload, separators=(",", ":"), allow_nan=False),
                                plan.model_dump_json(),
                                confirm_expires,
                                updated_ts,
                                run_id,
                            ),
                        )
                        self.database.append_audit_event(
                            connection,
                            session_pseudonym=principal.audit_pseudonym,
                            event_type="RUN_STATE_CHANGED",
                            build_version="0.1.0",
                            run_id=run_id,
                            state=target_state,
                            timestamp=updated_ts,
                            details={
                                "schema_sha256": planning_result.schema_sha256,
                                "plan_sha256": plan_sha,
                            },
                        )
                    else:
                        assert envelope.clarification is not None
                        clarification: AIClarificationNeeded = envelope.clarification
                        plan_sha = None
                        target_state = "NEEDS_CLARIFICATION"
                        interpretation_payload = {
                            "version": 1,
                            "status": "CLARIFICATION_REQUIRED",
                            "provider_mode": "SIMULATED_MOCK",
                            "simulated_response": True,
                            "model": planning_result.model,
                            "schema_sha256": planning_result.schema_sha256,
                            "reason_code": clarification.reason_code,
                            "clarification_prompt": clarification.clarification_prompt,
                            "candidate_columns": list(clarification.candidate_columns),
                        }
                        connection.execute(
                            """UPDATE runs SET state=?, state_version=state_version+1,
                                interpretation_json=?, plan_json='{}', updated_at=? WHERE run_id=?""",
                            (
                                target_state,
                                json.dumps(interpretation_payload, separators=(",", ":"), allow_nan=False),
                                updated_ts,
                                run_id,
                            ),
                        )
                        self.database.append_audit_event(
                            connection,
                            session_pseudonym=principal.audit_pseudonym,
                            event_type="RUN_STATE_CHANGED",
                            build_version="0.1.0",
                            run_id=run_id,
                            state=target_state,
                            timestamp=updated_ts,
                            details={"schema_sha256": planning_result.schema_sha256},
                        )

                    outcome = PlanningPreviewOutcome(
                        run_id=run_id,
                        session_id=principal.session_id,
                        dataset_id=target_dataset_id,
                        dataset_version=1,
                        run_state=target_state,
                        is_synthetic_dataset=is_synthetic_dataset,
                        model=planning_result.model,
                        question=validated_question.question,
                        dataset_schema=validated_schema,
                        envelope=envelope,
                        plan_sha256=plan_sha,
                    )
        except (SessionError, PlanningError):
            raise
        except (sqlite3.Error, OSError, DatabaseVersionError):
            raise SessionError(503) from None

        if deferred_error is not None:
            raise deferred_error
        assert outcome is not None
        return outcome

    def list_session_runs(self, principal: SessionPrincipal) -> tuple[PersistedRunSummary, ...]:
        """Return up to 25 persisted runs owned by the active session."""
        try:
            with self.database.connection() as connection:
                require_active_session(connection, principal)
                rows = connection.execute(
                    """SELECT * FROM runs WHERE session_id=?
                        ORDER BY created_at DESC, run_id DESC LIMIT 25""",
                    (principal.session_id,),
                ).fetchall()
                summaries: list[PersistedRunSummary] = []
                for row in rows:
                    owned_run(connection, principal, row["run_id"])
                    interp = json.loads(row["interpretation_json"] or "{}")
                    summaries.append(
                        PersistedRunSummary(
                            run_id=row["run_id"],
                            session_id=row["session_id"],
                            dataset_id=row["dataset_id"],
                            dataset_version=row["dataset_version"],
                            state=row["state"],
                            question=row["question"],
                            plan_sha256=interp.get("plan_sha256"),
                            expected_result_type=interp.get("expected_result_type"),
                            intent_summary=interp.get("intent_summary"),
                            clarification_reason=interp.get("reason_code"),
                            created_at=row["created_at"],
                            updated_at=row["updated_at"],
                        )
                    )
                return tuple(summaries)
        except SessionError:
            raise
        except (sqlite3.Error, OSError, DatabaseVersionError):
            raise SessionError(503) from None
