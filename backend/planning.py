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
import math
import re
import sqlite3
import time
from typing import Literal
import unicodedata
from uuid import uuid4

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from backend.codegen import (
    CodeGenCode,
    CodeGenError,
    generate_analysis_code,
)
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
from validator.numerical_verifier import (
    SyntheticTableFixture,
    VerificationError,
    compute_expected_analysis_result,
)


SYNTHETIC_FIXTURE_ID = "synthetic_quarterly_revenue_v1"
SYNTHETIC_FIXTURE_IDEMPOTENCY_KEY = f"synthetic-fixture:{SYNTHETIC_FIXTURE_ID}"
SYNTHETIC_FIXTURE_LABEL = (
    "DEMO / SYNTHETIC FIXTURE — Quarterly Regional Revenue & Headcount "
    "(Server-Owned Offline Dataset)"
)
SIMULATED_PROVIDER_LABEL = (
    "DEMO / SIMULATED — Deterministic HTTPX Mock Transport (Not Live Vultr Output)"
)
SYNTHETIC_VERIFICATION_LABEL = (
    "DEMO / SYNTHETIC EXPECTED RESULT PREVIEW — Independent Stdlib Reference Computation "
    "on Server-Owned Synthetic Fixture (Candidate Code Not Executed; Candidate Output Not Verified; Publication Unauthorized)"
)
SYNTHETIC_REPORT_LABEL = (
    "DEMO / SYNTHETIC REPORT — Reference Expected Result Only "
    "(Candidate Code Not Executed; Candidate Output Not Verified; Not a Production Export)"
)
SIMULATED_MODEL_ID = "simulated-planner-v1"
_SIMULATED_API_KEY = SecretStr("simulated_offline_key_not_a_real_secret")

SYNTHETIC_FIXTURE_RECORDS: tuple[dict[str, str | int | float | bool | None], ...] = (
    {
        "col_001": "2025-03-31",
        "col_002": "Enterprise",
        "col_003": "North America",
        "col_004": 425000.50,
        "col_005": 42,
    },
    {
        "col_001": "2025-03-31",
        "col_002": "MidMarket",
        "col_003": "Europe",
        "col_004": 198500.00,
        "col_005": 24,
    },
    {
        "col_001": "2025-06-30",
        "col_002": "Enterprise",
        "col_003": "North America",
        "col_004": 462100.75,
        "col_005": 45,
    },
    {
        "col_001": "2025-06-30",
        "col_002": "Commercial",
        "col_003": "Asia Pacific",
        "col_004": 154200.25,
        "col_005": 19,
    },
    {
        "col_001": "2025-09-30",
        "col_002": "MidMarket",
        "col_003": "Europe",
        "col_004": 215800.00,
        "col_005": 26,
    },
)

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


class ASTValidationReceiptPreview(StrictPlanningContract):
    """Static AST admission receipt for the deterministic candidate preview."""

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


class CodeGenerationPreview(StrictPlanningContract):
    """Deterministic code preview compiled from the validated AIAnalysisPlan."""

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
    ast_receipt: ASTValidationReceiptPreview


class ChartPointPreview(StrictPlanningContract):
    """Single chart point in the demonstration-only synthetic verification preview."""

    x: str | int | float | bool
    y: float


class ColumnCompletenessInsight(StrictPlanningContract):
    """Per-column missing-value and completeness insight derived from ValidatedDatasetSchema."""

    column_id: str = Field(pattern=r"^col_[0-9]{3}$")
    column_name: str = Field(min_length=1, max_length=128)
    inferred_type: Literal["empty", "text", "integer", "number", "boolean", "date", "mixed"]
    row_count: int = Field(ge=1)
    missing_count: int = Field(ge=0)
    present_count: int = Field(ge=0)
    completeness_pct: float = Field(ge=0.0, le=100.0)
    referenced_in_plan: bool = False


class NumericColumnSummaryPreview(StrictPlanningContract):
    """Independent descriptive summary for a numeric output column in the synthetic preview."""

    column_id: str = Field(min_length=1, max_length=64)
    display_label: str = Field(min_length=1, max_length=160)
    non_null_count: int = Field(ge=0, le=200)
    null_count: int = Field(ge=0, le=200)
    total_sum: float
    mean_value: float
    min_value: float
    max_value: float


class DemonstrationReportPreview(StrictPlanningContract):
    """Bounded, formula-injection-neutralized demonstration report for local download."""

    version: Literal[1] = 1
    demonstration_only: Literal[True] = True
    report_label: str = SYNTHETIC_REPORT_LABEL
    markdown_filename: str = Field(pattern=r"^sheetsafe_demo_report_[0-9a-f]{12}\.md$")
    csv_filename: str = Field(pattern=r"^sheetsafe_demo_table_[0-9a-f]{12}\.csv$")
    markdown_content: str = Field(min_length=32, max_length=16384)
    csv_content: str = Field(min_length=10, max_length=16384)
    markdown_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    csv_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    formula_injection_neutralized: Literal[True] = True


class SyntheticVerificationPreview(StrictPlanningContract):
    """Demonstration-only reference expected-result preview over the synthetic fixture.

    Never executes generated Python code or verifies a candidate-produced artifact.
    """

    version: Literal[1] = 1
    demonstration_only: Literal[True] = True
    verification_label: str = SYNTHETIC_VERIFICATION_LABEL
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
    chart_series: tuple[ChartPointPreview, ...] = ()
    numeric_summaries: tuple[NumericColumnSummaryPreview, ...] = ()
    missing_value_insights: tuple[ColumnCompletenessInsight, ...] = ()
    total_missing_cells: int = Field(default=0, ge=0)
    dataset_completeness_pct: float = Field(default=100.0, ge=0.0, le=100.0)
    zero_division_count: int = Field(default=0, ge=0)
    max_abs_error: float = Field(default=0.0, ge=0.0)
    demo_report: DemonstrationReportPreview


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
    code_preview: CodeGenerationPreview | None = None
    synthetic_verification_preview: SyntheticVerificationPreview | None = None


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
    code_sha256: str | None = None
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
        elif "filter_rows" in question_text or "filter rows" in question_text:
            rev_col = col_by_name.get("revenue_usd") or col_by_id.get("col_004") or columns[0]
            envelope_dict = {
                "version": 1,
                "status": "PLAN_READY",
                "plan": {
                    "version": 1,
                    "schema_sha256": schema_sha256,
                    "intent_summary": (
                        "Attempt to filter rows on revenue_usd using ProposedOperation v1 "
                        "(unsupported operation without typed predicate)."
                    ),
                    "required_columns": [
                        {
                            "column_id": rev_col["column_id"],
                            "name": rev_col["name"],
                            "expected_type": rev_col["inferred_type"],
                        }
                    ],
                    "operations": [
                        {
                            "step_number": 1,
                            "operation": "FILTER_ROWS",
                            "target_columns": [rev_col["column_id"]],
                            "group_by_columns": [],
                            "rationale": "Filter rows where revenue_usd exceeds threshold.",
                        }
                    ],
                    "expected_result_type": "SUMMARY_TABLE",
                },
            }
        elif "bar chart" in question_text or "bar_chart" in question_text:
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
            envelope_dict = {
                "version": 1,
                "status": "PLAN_READY",
                "plan": {
                    "version": 1,
                    "schema_sha256": schema_sha256,
                    "intent_summary": (
                        f"Group records by {group_col['name']}, compute total {metric_col['name']}, "
                        f"and project a categorical bar chart series (DEMO / SIMULATED offline plan)."
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
                        {
                            "step_number": 3,
                            "operation": "CHART_SERIES",
                            "target_columns": [group_col["column_id"], metric_col["column_id"]],
                            "group_by_columns": [],
                            "rationale": f"Emit bar chart coordinates ({group_col['name']} vs {metric_col['name']}).",
                        },
                    ],
                    "expected_result_type": "BAR_CHART",
                },
            }
        elif "line chart" in question_text or "line_chart" in question_text:
            date_col = col_by_name.get("quarter") or col_by_id.get("col_001") or columns[0]
            rev_col = col_by_name.get("revenue_usd") or col_by_id.get("col_004") or columns[-1]
            envelope_dict = {
                "version": 1,
                "status": "PLAN_READY",
                "plan": {
                    "version": 1,
                    "schema_sha256": schema_sha256,
                    "intent_summary": (
                        "Roll up quarterly revenue_usd over quarter dates and project a chronological "
                        "line chart series (DEMO / SIMULATED offline plan)."
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
                        {
                            "step_number": 3,
                            "operation": "CHART_SERIES",
                            "target_columns": [date_col["column_id"], rev_col["column_id"]],
                            "group_by_columns": [],
                            "rationale": "Emit chronological line chart coordinates (quarter vs revenue_usd).",
                        },
                    ],
                    "expected_result_type": "LINE_CHART",
                },
            }
        elif (
            "scalar" in question_text
            or "grand total" in question_text
            or "overall average" in question_text
        ):
            rev_col = col_by_name.get("revenue_usd") or col_by_id.get("col_004") or columns[-1]
            agg = "mean" if ("average" in question_text or "mean" in question_text) else "sum"
            envelope_dict = {
                "version": 1,
                "status": "PLAN_READY",
                "plan": {
                    "version": 1,
                    "schema_sha256": schema_sha256,
                    "intent_summary": (
                        f"Compute overall scalar {agg} of {rev_col['name']} across validated records "
                        "(DEMO / SIMULATED offline plan)."
                    ),
                    "required_columns": [
                        {
                            "column_id": rev_col["column_id"],
                            "name": rev_col["name"],
                            "expected_type": rev_col["inferred_type"],
                        },
                    ],
                    "operations": [
                        {
                            "step_number": 1,
                            "operation": "SUMMARY_STATS",
                            "target_columns": [rev_col["column_id"]],
                            "group_by_columns": [],
                            "aggregation": agg,
                            "rationale": f"Compute scalar {agg} over {rev_col['name']}.",
                        },
                    ],
                    "expected_result_type": "SCALAR_METRIC",
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


def _map_codegen_error(error: CodeGenError | VerificationError) -> tuple[PlanningCode, str]:
    """Map Step 10A CodeGenError or VerificationError to (PlanningCode, terminal_run_state)."""
    if isinstance(error, CodeGenError):
        if error.code is CodeGenCode.UNKNOWN_COLUMN:
            return (PlanningCode.UNKNOWN_COLUMN_REFERENCE, "BLOCKED_POLICY")
        if error.code in {CodeGenCode.SCHEMA_MISMATCH, CodeGenCode.INVALID_CONTRACT}:
            return (PlanningCode.INVALID_PLAN_CONTRACT, "BLOCKED_POLICY")
    return (PlanningCode.UNSAFE_OPERATION_REJECTED, "BLOCKED_POLICY")


_RATIO_COL_RE = re.compile(r"^ratio_(col_[0-9]{3})_(col_[0-9]{3})$")
# Spreadsheet-sensitive leading characters (ASCII and full-width variants). Leading
# whitespace and control/format characters are stripped before this check so they
# cannot hide a formula trigger (e.g. "\t=1", "\u200b=1", "\u00a0+1").
_FORMULA_TRIGGER_PREFIXES = (
    "=", "+", "-", "@", "|", "\t", "\r", "\n",
    "\uff1d", "\uff0b", "\uff0d", "\uff20", "\uff5c",
)
# Byte budgets keep the demo report well inside the contract maxima (16 KiB each)
# and the Streamlit client's 32 KiB total response limit.
DEMO_REPORT_MARKDOWN_BUDGET_BYTES = 8192
DEMO_REPORT_CSV_BUDGET_BYTES = 6144
_DEMO_REPORT_MARKDOWN_TABLE_ROW_CAP = 50
_DEMO_REPORT_CSV_ROW_CAP = 200
_MARKDOWN_ESCAPE_TABLE = str.maketrans(
    {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        "\\": "\\\\",
        "`": "\\`",
        "*": "\\*",
        "[": "\\[",
        "]": "\\]",
        "|": "\\|",
    }
)


def _sanitize_control_characters(text: str) -> str:
    """Replace control, format and line/paragraph separator characters with spaces."""
    return "".join(
        " " if unicodedata.category(ch) in {"Cc", "Cf", "Zl", "Zp"} else ch
        for ch in text
    )


def _neutralize_spreadsheet_cell(value: str | int | float | bool | None) -> str:
    """Format a primitive cell for CSV export while neutralizing formula injection.

    Numeric and boolean cells are emitted as literals. Text cells have control and
    invisible format characters replaced with spaces; if the remaining text begins
    (after leading whitespace) with a spreadsheet-sensitive prefix, a leading single
    quote is added so spreadsheet applications treat the cell as plain text.
    """
    if value is None:
        return ""
    if type(value) is bool:
        return "TRUE" if value else "FALSE"
    if type(value) in (int, float):
        return str(value)
    raw = str(value)
    text = _sanitize_control_characters(raw)
    stripped = text.lstrip()
    if raw[:1] != text[:1] or stripped.startswith(_FORMULA_TRIGGER_PREFIXES):
        return f"'{text}"
    return text


def _escape_markdown_text(value: object) -> str:
    """Escape dynamic text so Markdown renderers cannot produce raw HTML or links."""
    text = _sanitize_control_characters(str(value))
    return text.translate(_MARKDOWN_ESCAPE_TABLE)


class _BoundedLineWriter:
    """Accumulate lines within a UTF-8 byte budget, appending a truncation notice once."""

    def __init__(self, budget_bytes: int, truncation_notice: str) -> None:
        self._budget = budget_bytes
        self._notice = truncation_notice
        self._notice_bytes = len(truncation_notice.encode("utf-8")) + 1
        self._lines: list[str] = []
        self._used = 0
        self.truncated = False

    def add(self, line: str) -> bool:
        if self.truncated:
            return False
        line_bytes = len(line.encode("utf-8")) + 1
        if self._used + line_bytes + self._notice_bytes > self._budget:
            self._lines.append(self._notice)
            self._used += self._notice_bytes
            self.truncated = True
            return False
        self._lines.append(line)
        self._used += line_bytes
        return True

    def render(self) -> str:
        return "\n".join(self._lines) + "\n"


def _encode_csv_row(cells: list[str]) -> str:
    """Encode a list of already-neutralized string cells as an RFC-4180 CSV line."""
    encoded: list[str] = []
    for cell in cells:
        if "," in cell or '"' in cell or "\n" in cell or "\r" in cell:
            encoded.append('"' + cell.replace('"', '""') + '"')
        else:
            encoded.append(cell)
    return ",".join(encoded)


def _build_column_headers(
    output_columns: tuple[str, ...],
    validated_schema: ValidatedDatasetSchema,
) -> dict[str, str]:
    """Map validated output column IDs to human-readable headers."""
    col_by_id = {c.column_id: c.name for c in validated_schema.columns}
    headers: dict[str, str] = {}
    for col_id in output_columns:
        if col_id in col_by_id:
            headers[col_id] = f"{col_by_id[col_id]} ({col_id})"
        else:
            ratio_match = _RATIO_COL_RE.match(col_id)
            if ratio_match is not None:
                num_id, den_id = ratio_match.group(1), ratio_match.group(2)
                num_name = col_by_id.get(num_id, num_id)
                den_name = col_by_id.get(den_id, den_id)
                headers[col_id] = f"ratio_{num_name}_{den_name} ({col_id})"
            else:
                headers[col_id] = col_id
    return headers


def _build_demonstration_report(
    *,
    plan: AIAnalysisPlan,
    validated_schema: ValidatedDatasetSchema,
    code_sha256: str,
    plan_sha256: str,
    verified_output_sha256: str,
    result_type: str,
    columns: tuple[str, ...],
    column_headers: dict[str, str],
    rows: tuple[dict[str, str | int | float | bool | None], ...],
    scalar_value: float | int | None,
    zero_division_count: int,
    numeric_summaries: tuple[NumericColumnSummaryPreview, ...],
    missing_value_insights: tuple[ColumnCompletenessInsight, ...],
) -> DemonstrationReportPreview:
    """Build bounded, formula-injection-neutralized Markdown and CSV demo reports.

    Both outputs stay within fixed UTF-8 byte budgets and record a visible
    truncation notice instead of failing when the reference table is large.
    Dynamic Markdown text is escaped so renderers cannot emit raw HTML or links.
    """
    short_hash = verified_output_sha256[:12]
    md_filename = f"sheetsafe_demo_report_{short_hash}.md"
    csv_filename = f"sheetsafe_demo_table_{short_hash}.csv"
    total_rows = len(rows)

    csv_writer = _BoundedLineWriter(
        DEMO_REPORT_CSV_BUDGET_BYTES,
        _encode_csv_row(["# DEMO / SYNTHETIC — TRUNCATED: remaining rows omitted to respect report size limit"]),
    )
    csv_writer.add(
        _encode_csv_row(
            [
                "# DEMO / SYNTHETIC REPORT",
                "Reference Expected Result Only (Candidate Code Not Executed; Not a Production Export)",
                f"expected_output_sha256={verified_output_sha256}",
            ]
        )
    )
    csv_writer.add(
        _encode_csv_row([_neutralize_spreadsheet_cell(column_headers.get(c, c)) for c in columns])
    )
    for row in rows[:_DEMO_REPORT_CSV_ROW_CAP]:
        if not csv_writer.add(
            _encode_csv_row([_neutralize_spreadsheet_cell(row.get(c)) for c in columns])
        ):
            break
    csv_content = csv_writer.render()

    md = _BoundedLineWriter(
        DEMO_REPORT_MARKDOWN_BUDGET_BYTES,
        "\n> **DEMO / SYNTHETIC — TRUNCATED**: remaining sections omitted to respect report size limit.",
    )
    header_lines = [
        f"# SheetSafe AI — {SYNTHETIC_REPORT_LABEL}",
        "",
        "> **SECURITY & PROVENANCE NOTICE**: This report is generated strictly from the server-owned",
        "> synthetic demonstration fixture (`synthetic_quarterly_revenue_v1`). Generated Python code",
        "> was **NOT** executed (`execution_authorized=False`), no candidate output was verified",
        "> (`candidate_output_verified=False`), and publication remains locked (`publication_authorized=False`).",
        "",
        "## 1. Consistency Digests (Reference Expected Result — Not Candidate Verification)",
        "- **Preview Status**: `SYNTHETIC_EXPECTED_RESULT_COMPUTED`",
        f"- **Result Type**: `{_escape_markdown_text(result_type)}`",
        f"- **Expected Output Rows**: `{total_rows}`",
        f"- **Zero-Division Count**: `{zero_division_count}`",
        f"- **Schema SHA-256**: `{validated_schema.schema_sha256}`",
        f"- **Plan SHA-256**: `{plan_sha256}`",
        f"- **Candidate Code SHA-256 (not executed)**: `{code_sha256}`",
        f"- **Expected Output SHA-256**: `{verified_output_sha256}`",
    ]
    if scalar_value is not None:
        header_lines.append(f"- **Expected Scalar Metric**: `{scalar_value}`")
    header_lines.extend(
        [
            "",
            "## 2. Simulated Plan Intent (DEMO / SIMULATED provider output)",
            _escape_markdown_text(plan.intent_summary),
            "",
            "## 3. Reference Expected Result Table (DEMO / SYNTHETIC)",
            "| " + " | ".join(_escape_markdown_text(column_headers.get(c, c)) for c in columns) + " |",
            "| " + " | ".join("---" for _ in columns) + " |",
        ]
    )
    for line in header_lines:
        md.add(line)

    for row in rows[:_DEMO_REPORT_MARKDOWN_TABLE_ROW_CAP]:
        cells = [_escape_markdown_text(_neutralize_spreadsheet_cell(row.get(c))) for c in columns]
        if not md.add("| " + " | ".join(cells) + " |"):
            break
    if total_rows > _DEMO_REPORT_MARKDOWN_TABLE_ROW_CAP:
        md.add(
            f"> Table preview limited to the first {_DEMO_REPORT_MARKDOWN_TABLE_ROW_CAP} of {total_rows} rows."
        )

    if numeric_summaries:
        for line in (
            "",
            "## 4. Reference Numeric Column Summary (DEMO / SYNTHETIC)",
            "| Column | Non-Null | Null | Sum | Mean | Min | Max |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ):
            md.add(line)
        for ns in numeric_summaries:
            md.add(
                f"| {_escape_markdown_text(ns.display_label)} | {ns.non_null_count} | {ns.null_count} | "
                f"{ns.total_sum} | {ns.mean_value} | {ns.min_value} | {ns.max_value} |"
            )

    if missing_value_insights:
        for line in (
            "",
            "## 5. Dataset Completeness & Missing-Value Insights (DEMO / SYNTHETIC)",
            "| Column ID | Name | Type | Missing | Present | Completeness (%) | In Plan |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ):
            md.add(line)
        for mvi in missing_value_insights:
            md.add(
                f"| {mvi.column_id} | {_escape_markdown_text(mvi.column_name)} | {mvi.inferred_type} | "
                f"{mvi.missing_count} | {mvi.present_count} | {mvi.completeness_pct}% | "
                f"{mvi.referenced_in_plan} |"
            )

    markdown_content = md.render()
    md_sha256 = hashlib.sha256(markdown_content.encode("utf-8")).hexdigest()
    csv_sha256 = hashlib.sha256(csv_content.encode("utf-8")).hexdigest()
    return DemonstrationReportPreview(
        demonstration_only=True,
        report_label=SYNTHETIC_REPORT_LABEL,
        markdown_filename=md_filename,
        csv_filename=csv_filename,
        markdown_content=markdown_content,
        csv_content=csv_content,
        markdown_sha256=md_sha256,
        csv_sha256=csv_sha256,
        formula_injection_neutralized=True,
    )


def _build_code_and_verification_previews(
    plan: AIAnalysisPlan,
    validated_schema: ValidatedDatasetSchema,
    *,
    is_synthetic_dataset: bool,
) -> tuple[CodeGenerationPreview, SyntheticVerificationPreview | None]:
    """Compile deterministic candidate preview and optional synthetic verification preview.

    Never executes generated Python code or authorizes publication.
    """
    compiled = generate_analysis_code(plan, validated_schema)
    ast_preview = ASTValidationReceiptPreview(
        valid=True,
        code_sha256=compiled.ast_receipt.code_sha256,
        plan_sha256=compiled.ast_receipt.plan_sha256,
        schema_sha256=compiled.ast_receipt.schema_sha256,
        declared_imports=compiled.ast_receipt.declared_imports,
        node_count=compiled.ast_receipt.node_count,
        max_depth=compiled.ast_receipt.max_depth,
        execution_authorized=False,
        sandbox_isolation_required=True,
        security_notice=compiled.ast_receipt.security_notice,
    )
    code_preview = CodeGenerationPreview(
        code_sha256=compiled.code_sha256,
        plan_sha256=compiled.plan_sha256,
        schema_sha256=compiled.schema_sha256,
        declared_imports=compiled.candidate.declared_imports,
        referenced_columns=compiled.candidate.referenced_columns,
        output_columns=compiled.output_columns,
        expected_result_type=compiled.expected_result_type,
        python_source=compiled.candidate.python_source,
        execution_authorized=False,
        ast_receipt=ast_preview,
    )

    synthetic_fixture_schema = build_validated_dataset_schema(SYNTHETIC_FIXTURE_PROFILE)
    if not is_synthetic_dataset or validated_schema.schema_sha256 != synthetic_fixture_schema.schema_sha256:
        return code_preview, None

    fixture = SyntheticTableFixture.from_records(validated_schema, SYNTHETIC_FIXTURE_RECORDS)
    expected = compute_expected_analysis_result(plan, validated_schema, fixture)
    canonical_expected: dict[str, object] = {
        "schema_sha256": expected.schema_sha256,
        "plan_sha256": expected.plan_sha256,
        "result_type": expected.result_type,
        "columns": list(expected.columns),
        "rows": [dict(r) for r in expected.rows],
        "row_count": expected.row_count,
        "zero_division_count": expected.zero_division_count,
    }
    if expected.scalar_value is not None:
        canonical_expected["scalar_value"] = expected.scalar_value
    if expected.chart_series:
        canonical_expected["chart_series"] = [
            {"x": pt.x, "y": pt.y} for pt in expected.chart_series
        ]

    expected_output_sha256 = hashlib.sha256(
        json.dumps(
            canonical_expected,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()

    column_headers = _build_column_headers(expected.columns, validated_schema)

    # Derive interactive chart points and chart kind for visualizable result types
    chart_points: tuple[ChartPointPreview, ...] = ()
    chart_kind: Literal["BAR", "LINE", "NONE"] = "NONE"
    chart_x_label: str | None = None
    chart_y_label: str | None = None

    if expected.chart_series:
        chart_points = tuple(ChartPointPreview(x=pt.x, y=pt.y) for pt in expected.chart_series[:100])
        chart_kind = "LINE" if expected.result_type in {"LINE_CHART", "TIME_SERIES_TABLE"} else "BAR"
        chart_ops = [op for op in plan.operations if op.operation == "CHART_SERIES"]
        if chart_ops and len(chart_ops[-1].target_columns) == 2:
            x_id, y_id = chart_ops[-1].target_columns
            chart_x_label = column_headers.get(x_id, x_id)
            chart_y_label = column_headers.get(y_id, y_id)
        elif len(expected.columns) >= 2:
            chart_x_label = column_headers.get(expected.columns[0], expected.columns[0])
            chart_y_label = column_headers.get(expected.columns[-1], expected.columns[-1])
    elif expected.result_type == "TIME_SERIES_TABLE" and len(expected.columns) >= 2:
        x_col = expected.columns[0]
        y_col = expected.columns[-1]
        derived_pts: list[ChartPointPreview] = []
        for row in expected.rows[:100]:
            xv = row.get(x_col)
            yv = row.get(y_col)
            if xv is not None and type(yv) in (int, float):
                derived_pts.append(ChartPointPreview(x=xv, y=round(float(yv), 6)))
        if derived_pts:
            chart_points = tuple(derived_pts)
            chart_kind = "LINE"
            chart_x_label = column_headers.get(x_col, x_col)
            chart_y_label = column_headers.get(y_col, y_col)
    elif expected.result_type in {"GROUPED_TABLE", "SUMMARY_TABLE"} and len(expected.columns) >= 2:
        x_col = expected.columns[0]
        y_col = expected.columns[-1]
        derived_pts = []
        for row in expected.rows[:100]:
            xv = row.get(x_col)
            yv = row.get(y_col)
            if xv is not None and type(yv) in (int, float):
                derived_pts.append(ChartPointPreview(x=xv, y=round(float(yv), 6)))
        if derived_pts:
            chart_points = tuple(derived_pts)
            chart_kind = "BAR"
            chart_x_label = column_headers.get(x_col, x_col)
            chart_y_label = column_headers.get(y_col, y_col)

    # Compute per-column numerical descriptive summaries
    numeric_summaries_list: list[NumericColumnSummaryPreview] = []
    for col_id in expected.columns:
        nums = [
            float(row[col_id])
            for row in expected.rows
            if type(row.get(col_id)) in (int, float)
        ]
        if nums:
            non_null_count = len(nums)
            null_count = len(expected.rows) - non_null_count
            total_sum = round(math.fsum(nums), 6)
            mean_val = round(total_sum / non_null_count, 6)
            min_val = round(min(nums), 6)
            max_val = round(max(nums), 6)
            numeric_summaries_list.append(
                NumericColumnSummaryPreview(
                    column_id=col_id,
                    display_label=column_headers.get(col_id, col_id),
                    non_null_count=non_null_count,
                    null_count=null_count,
                    total_sum=total_sum,
                    mean_value=mean_val,
                    min_value=min_val,
                    max_value=max_val,
                )
            )
    numeric_summaries = tuple(numeric_summaries_list)

    # Compute missing-value & completeness insights from ValidatedDatasetSchema
    referenced_set = set(compiled.candidate.referenced_columns)
    missing_insights_list: list[ColumnCompletenessInsight] = []
    for col in validated_schema.columns:
        present_cnt = max(0, validated_schema.row_count - col.missing_count)
        comp_pct = (
            round((present_cnt / validated_schema.row_count) * 100.0, 2)
            if validated_schema.row_count > 0
            else 100.0
        )
        missing_insights_list.append(
            ColumnCompletenessInsight(
                column_id=col.column_id,
                column_name=col.name,
                inferred_type=col.inferred_type,
                row_count=validated_schema.row_count,
                missing_count=col.missing_count,
                present_count=present_cnt,
                completeness_pct=comp_pct,
                referenced_in_plan=(col.column_id in referenced_set),
            )
        )
    missing_value_insights = tuple(missing_insights_list)
    total_cells = validated_schema.row_count * validated_schema.column_count
    total_missing_cells = sum(col.missing_count for col in validated_schema.columns)
    dataset_completeness_pct = (
        round(((total_cells - total_missing_cells) / total_cells) * 100.0, 2)
        if total_cells > 0
        else 100.0
    )

    demo_report = _build_demonstration_report(
        plan=plan,
        validated_schema=validated_schema,
        code_sha256=compiled.code_sha256,
        plan_sha256=expected.plan_sha256,
        verified_output_sha256=expected_output_sha256,
        result_type=expected.result_type,
        columns=expected.columns,
        column_headers=column_headers,
        rows=expected.rows,
        scalar_value=expected.scalar_value,
        zero_division_count=expected.zero_division_count,
        numeric_summaries=numeric_summaries,
        missing_value_insights=missing_value_insights,
    )

    verification_preview = SyntheticVerificationPreview(
        demonstration_only=True,
        verification_label=SYNTHETIC_VERIFICATION_LABEL,
        validation_status="SYNTHETIC_EXPECTED_RESULT_COMPUTED",
        candidate_output_verified=False,
        publication_authorized=False,
        sandbox_execution_verified=False,
        schema_sha256=expected.schema_sha256,
        plan_sha256=expected.plan_sha256,
        code_sha256=compiled.code_sha256,
        verified_output_sha256=expected_output_sha256,
        result_type=expected.result_type,
        columns=expected.columns,
        column_headers=column_headers,
        row_count=expected.row_count,
        rows=expected.rows,
        scalar_value=expected.scalar_value,
        chart_kind=chart_kind,
        chart_x_label=chart_x_label,
        chart_y_label=chart_y_label,
        chart_series=chart_points,
        numeric_summaries=numeric_summaries,
        missing_value_insights=missing_value_insights,
        total_missing_cells=total_missing_cells,
        dataset_completeness_pct=dataset_completeness_pct,
        zero_division_count=expected.zero_division_count,
        max_abs_error=0.0,
        demo_report=demo_report,
    )
    return code_preview, verification_preview


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

                    code_preview: CodeGenerationPreview | None = None
                    verification_preview: SyntheticVerificationPreview | None = None
                    if envelope.status == "PLAN_READY":
                        assert envelope.plan is not None
                        plan: AIAnalysisPlan = envelope.plan
                        plan_sha = plan.plan_sha256()
                        try:
                            code_preview, verification_preview = _build_code_and_verification_previews(
                                plan,
                                validated_schema,
                                is_synthetic_dataset=is_synthetic_dataset,
                            )
                        except (CodeGenError, VerificationError) as exc:
                            plan_code, failure_state = _map_codegen_error(exc)
                            connection.execute(
                                """UPDATE runs SET state=?, state_version=state_version+1,
                                    interpretation_json='{}', plan_json='{}', updated_at=? WHERE run_id=?""",
                                (failure_state, updated_ts, run_id),
                            )
                            self.database.append_audit_event(
                                connection,
                                session_pseudonym=principal.audit_pseudonym,
                                event_type="POLICY_DECISION",
                                build_version="0.1.0",
                                run_id=run_id,
                                state=failure_state,
                                timestamp=updated_ts,
                                details={
                                    "check_passed": False,
                                    "schema_sha256": validated_schema.schema_sha256,
                                    "plan_sha256": plan_sha,
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
                            deferred_error = PlanningError(plan_code)
                        else:
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
                                "code_sha256": code_preview.code_sha256,
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
                                    "code_sha256": code_preview.code_sha256,
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

                    if deferred_error is None:
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
                            code_preview=code_preview,
                            synthetic_verification_preview=verification_preview,
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
                            code_sha256=interp.get("code_sha256"),
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
