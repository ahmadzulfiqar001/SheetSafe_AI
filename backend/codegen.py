"""Deterministic Plan-to-Code Generator and Bounded Repair Contract (Step 10A).

SECURITY & ARCHITECTURAL INVARIANTS:
- Converts a strictly validated `AIAnalysisPlan` + `ValidatedDatasetSchema` into
  an inert `GeneratedCodeCandidate` (`execution_authorized=False`) and verifies
  it through both `validate_code_candidate` and `validate_candidate_ast`.
- Never interpolates user questions, intent summaries, operation rationales, or
  column display names (`col.name`) into generated Python syntax or comments.
- References columns exclusively by validated `^col_[0-9]{3}$` identifiers.
- Never executes generated Python (`eval`, `exec`, `compile`, `subprocess`, or
  dynamic imports are never invoked).
- Preserves the original PRD 20 MiB (`20 * 1024**2` bytes) upload limit and all
  runner/parser fail-closed gates (`execution_enabled=False`).
"""

from dataclasses import dataclass
from enum import StrEnum
import hashlib
import re
from typing import Literal

from backend.inference import (
    AIAnalysisPlan,
    ExpectedResultType,
    GeneratedCodeCandidate,
    InferenceCode,
    InferenceError,
    InferredColumnType,
    OperationKind,
    ProposedOperation,
    ValidatedDatasetSchema,
    _has_forbidden_capability,
    _has_inline_secret_or_pii,
    _has_prompt_injection,
    _has_sensitive_header,
    validate_code_candidate,
)
from ingestion.contracts import safe_label
from validator.ast_policy import (
    ASTPolicyError,
    ASTValidationReceipt,
    validate_candidate_ast,
)
from validator.numerical_verifier import (
    MAX_CHART_POINTS,
    MAX_OUTPUT_COLUMNS,
    MAX_OUTPUT_ROWS,
    VerificationCode,
    VerificationError,
    validate_plan_for_execution,
)


MAX_CODE_CANDIDATES = 3
MAX_EXECUTION_ATTEMPTS = 3
MAX_RUN_WALL_SECONDS = 180

SUPPORTED_CODEGEN_OPERATIONS: frozenset[OperationKind] = frozenset({
    "SELECT_COLUMNS",
    "DROP_MISSING",
    "GROUP_AGGREGATE",
    "SUMMARY_STATS",
    "SORT_VALUES",
    "TOP_N",
    "COMPUTE_RATIO",
    "TIME_SERIES_ROLLUP",
    "CHART_SERIES",
})

UNSUPPORTED_CODEGEN_OPERATIONS: frozenset[OperationKind] = frozenset({
    "FILTER_ROWS",
})

_STRICT_COL_ID_RE = re.compile(r"^col_[0-9]{3}$")
_DECLARED_IMPORTS: tuple[str, ...] = ("math", "pandas", "numpy")


class CodeGenCode(StrEnum):
    INVALID_CONTRACT = "INVALID_CONTRACT"
    SCHEMA_MISMATCH = "SCHEMA_MISMATCH"
    UNKNOWN_COLUMN = "UNKNOWN_COLUMN"
    UNSUPPORTED_OPERATION = "UNSUPPORTED_OPERATION"
    INCOMPATIBLE_COLUMN_TYPE = "INCOMPATIBLE_COLUMN_TYPE"
    UNSAFE_METADATA_REJECTED = "UNSAFE_METADATA_REJECTED"
    OUTPUT_LIMIT_EXCEEDED = "OUTPUT_LIMIT_EXCEEDED"
    AST_POLICY_REJECTED = "AST_POLICY_REJECTED"


class CodeGenError(ValueError):
    """Sanitized deterministic code-generation error; never embeds untrusted payloads."""

    def __init__(self, code: CodeGenCode, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"Deterministic code generation failed ({code.value}): {detail}")


@dataclass(frozen=True, slots=True)
class CompiledAnalysisCandidate:
    """Immutable compiled candidate bundle bound to its plan, schema, and AST receipt."""

    candidate: GeneratedCodeCandidate
    ast_receipt: ASTValidationReceipt
    plan_sha256: str
    schema_sha256: str
    code_sha256: str
    output_columns: tuple[str, ...]
    expected_result_type: ExpectedResultType
    execution_authorized: Literal[False] = False


def _require_strict_col_id(col_id: str) -> str:
    if type(col_id) is not str or not _STRICT_COL_ID_RE.fullmatch(col_id):
        raise CodeGenError(CodeGenCode.UNKNOWN_COLUMN, "Column ID failed strict format check.")
    return col_id


def _format_col_list(col_ids: tuple[str, ...] | list[str]) -> str:
    checked = [_require_strict_col_id(c) for c in col_ids]
    return "[" + ", ".join(f'"{c}"' for c in checked) + "]"


def _format_Step_statements(
    op: ProposedOperation,
    active_cols: list[str],
    active_types: dict[str, InferredColumnType],
) -> tuple[list[str], list[str], dict[str, InferredColumnType]]:
    """Emit fixed, reviewed Python lines for one validated ProposedOperation."""
    step_idx = op.step_number
    lines: list[str] = []

    if op.operation == "SELECT_COLUMNS":
        cols_expr = _format_col_list(op.target_columns)
        lines.append(f"    df = df.loc[:, {cols_expr}].copy()")
        new_cols = list(op.target_columns)
        new_types = {c: active_types[c] for c in new_cols}
        return lines, new_cols, new_types

    if op.operation == "DROP_MISSING":
        cols_expr = _format_col_list(op.target_columns)
        lines.append(f"    df = df.dropna(subset={cols_expr}).reset_index(drop=True)")
        return lines, list(active_cols), dict(active_types)

    if op.operation == "GROUP_AGGREGATE":
        assert op.aggregation is not None
        group_expr = _format_col_list(op.group_by_columns)
        agg_pairs = ", ".join(
            f'"{_require_strict_col_id(t_col)}": "{op.aggregation}"'
            for t_col in op.target_columns
        )
        lines.append(f"    df = df.dropna(subset={group_expr}).reset_index(drop=True)")
        lines.append(
            f"    df = df.groupby({group_expr}, as_index=False, sort=True)"
            f".agg({{{agg_pairs}}}).reset_index(drop=True)"
        )
        new_cols = [*op.group_by_columns, *op.target_columns]
        new_types: dict[str, InferredColumnType] = {
            g_col: active_types[g_col] for g_col in op.group_by_columns
        }
        for t_col in op.target_columns:
            if op.aggregation == "count":
                new_types[t_col] = "integer"
            elif op.aggregation in {"min", "max"} and active_types[t_col] == "date":
                new_types[t_col] = "date"
            elif op.aggregation in {"sum", "min", "max"} and active_types[t_col] == "integer":
                new_types[t_col] = "integer"
            else:
                new_types[t_col] = "number"
        return lines, new_cols, new_types

    if op.operation == "SUMMARY_STATS":
        assert op.aggregation is not None
        row_entries: list[str] = []
        new_types = {}
        for t_col in op.target_columns:
            cid = _require_strict_col_id(t_col)
            if op.aggregation == "count":
                row_entries.append(f'"{cid}": int(df["{cid}"].count())')
                new_types[cid] = "integer"
            else:
                row_entries.append(
                    f'"{cid}": (None if int(df["{cid}"].count()) == 0 else df["{cid}"].dropna().{op.aggregation}())'
                )
                if op.aggregation in {"min", "max"} and active_types[cid] == "date":
                    new_types[cid] = "date"
                elif op.aggregation in {"sum", "min", "max"} and active_types[cid] == "integer":
                    new_types[cid] = "integer"
                else:
                    new_types[cid] = "number"
        cols_expr = _format_col_list(op.target_columns)
        lines.append(
            f"    df = pd.DataFrame([{{{', '.join(row_entries)}}}], columns={cols_expr})"
        )
        return lines, list(op.target_columns), new_types

    if op.operation == "SORT_VALUES":
        assert op.sort_direction is not None
        cols_expr = _format_col_list(op.target_columns)
        asc_literal = "True" if op.sort_direction == "asc" else "False"
        lines.append(
            f"    df = df.sort_values(by={cols_expr}, ascending={asc_literal}, "
            f'na_position="last", kind="mergesort").reset_index(drop=True)'
        )
        return lines, list(active_cols), dict(active_types)

    if op.operation == "TOP_N":
        assert op.sort_direction is not None and op.limit_rows is not None
        cols_expr = _format_col_list(op.target_columns)
        asc_literal = "True" if op.sort_direction == "asc" else "False"
        limit_val = min(int(op.limit_rows), MAX_OUTPUT_ROWS)
        lines.append(
            f"    df = df.sort_values(by={cols_expr}, ascending={asc_literal}, "
            f'na_position="last", kind="mergesort").head({limit_val}).reset_index(drop=True)'
        )
        return lines, list(active_cols), dict(active_types)

    if op.operation == "COMPUTE_RATIO":
        num_col = _require_strict_col_id(op.target_columns[0])
        den_col = _require_strict_col_id(op.target_columns[1])
        ratio_col = f"ratio_{num_col}_{den_col}"
        step_ratios = f"step_{step_idx}_ratios"
        step_row = f"step_{step_idx}_row"
        num_val = f"step_{step_idx}_num"
        den_val = f"step_{step_idx}_den"
        lines.extend([
            f"    {step_ratios} = []",
            f'    for {step_row} in df.where(df.notna(), None).to_dict(orient="records"):',
            f'        {num_val} = {step_row}.get("{num_col}")',
            f'        {den_val} = {step_row}.get("{den_col}")',
            f"        if {num_val} is None or {den_val} is None:",
            f"            {step_ratios}.append(None)",
            f"        elif float({den_val}) == 0.0:",
            f"            {step_ratios}.append(None)",
            f"            zero_division_count += 1",
            f"        else:",
            f"            {step_ratios}.append(float({num_val}) / float({den_val}))",
            f"    df = df.copy()",
            f'    df["{ratio_col}"] = {step_ratios}',
        ])
        new_cols = list(active_cols)
        if ratio_col not in active_types:
            new_cols.append(ratio_col)
        new_types = dict(active_types)
        new_types[ratio_col] = "number"
        return lines, new_cols, new_types

    if op.operation == "TIME_SERIES_ROLLUP":
        date_col = _require_strict_col_id(op.target_columns[0])
        metric_cols = [_require_strict_col_id(c) for c in op.target_columns[1:]]
        agg_pairs = ", ".join(f'"{m_col}": "sum"' for m_col in metric_cols)
        lines.extend([
            f'    df = df.dropna(subset=["{date_col}"]).reset_index(drop=True)',
            f'    df = df.groupby(["{date_col}"], as_index=False, sort=True)'
            f".agg({{{agg_pairs}}})"
            f'.sort_values(by=["{date_col}"], ascending=True, na_position="last", kind="mergesort")'
            f".reset_index(drop=True)",
        ])
        new_cols = [date_col, *metric_cols]
        new_types = {date_col: "date"}
        for m_col in metric_cols:
            new_types[m_col] = active_types[m_col]
        return lines, new_cols, new_types

    if op.operation == "CHART_SERIES":
        x_col = _require_strict_col_id(op.target_columns[0])
        y_col = _require_strict_col_id(op.target_columns[1])
        lines.append(
            f'    df = df.loc[:, ["{x_col}", "{y_col}"]]'
            f'.dropna(subset=["{x_col}", "{y_col}"])'
            f".head(MAX_CHART_OUT).reset_index(drop=True)"
        )
        new_cols = [x_col, y_col]
        new_types = {x_col: active_types[x_col], y_col: active_types[y_col]}
        return lines, new_cols, new_types

    raise CodeGenError(CodeGenCode.UNSUPPORTED_OPERATION, f"Unsupported operation: {op.operation}")


def _map_verification_error(err: VerificationError) -> CodeGenError:
    mapping: dict[VerificationCode, CodeGenCode] = {
        VerificationCode.SCHEMA_MISMATCH: CodeGenCode.SCHEMA_MISMATCH,
        VerificationCode.PLAN_MISMATCH: CodeGenCode.INVALID_CONTRACT,
        VerificationCode.UNKNOWN_COLUMN: CodeGenCode.UNKNOWN_COLUMN,
        VerificationCode.UNSUPPORTED_OPERATION: CodeGenCode.UNSUPPORTED_OPERATION,
        VerificationCode.INCOMPATIBLE_COLUMN_TYPE: CodeGenCode.INCOMPATIBLE_COLUMN_TYPE,
        VerificationCode.OUTPUT_LIMIT_EXCEEDED: CodeGenCode.OUTPUT_LIMIT_EXCEEDED,
    }
    return CodeGenError(mapping.get(err.code, CodeGenCode.INVALID_CONTRACT), err.detail)


def generate_analysis_code(
    plan: AIAnalysisPlan,
    schema: ValidatedDatasetSchema,
) -> CompiledAnalysisCandidate:
    """Deterministically compile a validated AIAnalysisPlan into a restricted Python candidate.

    Never executes the generated script. Validates the emitted candidate through both
    `validate_code_candidate` and `validate_candidate_ast`.
    """
    if type(plan) is not AIAnalysisPlan or type(schema) is not ValidatedDatasetSchema:
        raise CodeGenError(
            CodeGenCode.INVALID_CONTRACT,
            "Expected validated AIAnalysisPlan and ValidatedDatasetSchema instances.",
        )

    # Re-verify untrusted display metadata for defense in depth
    for col in schema.columns:
        if (
            not safe_label(col.name)
            or _has_prompt_injection(col.name)
            or _has_forbidden_capability(col.name)
            or _has_sensitive_header(col.name)
            or _has_inline_secret_or_pii(col.name)
        ):
            raise CodeGenError(
                CodeGenCode.UNSAFE_METADATA_REJECTED,
                "Schema column display name failed safety re-verification.",
            )
    if (
        _has_prompt_injection(plan.intent_summary)
        or _has_forbidden_capability(plan.intent_summary)
        or _has_inline_secret_or_pii(plan.intent_summary)
    ):
        raise CodeGenError(
            CodeGenCode.UNSAFE_METADATA_REJECTED,
            "Plan intent_summary failed safety re-verification.",
        )

    try:
        final_cols, final_types = validate_plan_for_execution(plan, schema)
    except VerificationError as exc:
        raise _map_verification_error(exc) from None

    # Sort required_columns deterministically by column_id for canonical code generation
    canonical_required_ids = tuple(sorted(_require_strict_col_id(c.column_id) for c in plan.required_columns))
    active_cols: list[str] = list(canonical_required_ids)
    active_types: dict[str, InferredColumnType] = {
        c.column_id: c.expected_type for c in plan.required_columns
    }

    plan_sha256 = plan.plan_sha256()
    schema_sha256 = schema.schema_sha256
    req_tuple_expr = "(" + ", ".join(f'"{cid}"' for cid in active_cols) + ("," if len(active_cols) == 1 else "") + ")"

    source_lines: list[str] = [
        "import math",
        "import pandas as pd",
        "import numpy as np",
        "",
        f'SCHEMA_SHA256 = "{schema_sha256}"',
        f'PLAN_SHA256 = "{plan_sha256}"',
        f'RESULT_TYPE = "{plan.expected_result_type}"',
        f"REQUIRED_COLUMNS = {req_tuple_expr}",
        f"MAX_ROWS_OUT = {MAX_OUTPUT_ROWS}",
        f"MAX_CHART_OUT = {MAX_CHART_POINTS}",
        "",
        "def run_analysis(records):",
        "    df = pd.DataFrame.from_records(records, columns=list(REQUIRED_COLUMNS))",
        "    zero_division_count = 0",
    ]

    for op in plan.operations:
        step_lines, active_cols, active_types = _format_Step_statements(op, active_cols, active_types)
        source_lines.extend(step_lines)

    out_cols_expr = "[" + ", ".join(f'"{c}"' for c in final_cols) + "]"
    source_lines.extend([
        f"    output_columns = {out_cols_expr}",
        "    df = df.loc[:, output_columns].head(MAX_ROWS_OUT).reset_index(drop=True)",
        '    rows_out = df.where(df.notna(), None).to_dict(orient="records")',
        "    chart_series = []",
    ])

    has_chart = plan.expected_result_type in {"BAR_CHART", "LINE_CHART"} or any(
        op.operation == "CHART_SERIES" for op in plan.operations
    )
    if has_chart and len(final_cols) >= 2:
        x_col, y_col = final_cols[0], final_cols[1]
        source_lines.extend([
            "    for chart_row in rows_out[:MAX_CHART_OUT]:",
            f'        x_val = chart_row.get("{x_col}")',
            f'        y_val = chart_row.get("{y_col}")',
            "        if x_val is not None and y_val is not None:",
            '            chart_series.append({"x": x_val, "y": float(y_val)})',
        ])

    if plan.expected_result_type == "SCALAR_METRIC":
        numeric_cols = [c for c in final_cols if final_types[c] in {"integer", "number"}]
        target_scalar_col = numeric_cols[-1]
        source_lines.extend([
            "    scalar_value = None",
            "    if len(rows_out) == 1:",
            f'        raw_scalar = rows_out[0].get("{target_scalar_col}")',
            "        if raw_scalar is not None and math.isfinite(float(raw_scalar)):",
            "            scalar_value = float(raw_scalar)",
        ])
    else:
        source_lines.append("    scalar_value = None")

    source_lines.extend([
        "    return {",
        '        "schema_sha256": SCHEMA_SHA256,',
        '        "plan_sha256": PLAN_SHA256,',
        '        "result_type": RESULT_TYPE,',
        '        "columns": output_columns,',
        '        "row_count": len(rows_out),',
        '        "rows": rows_out,',
        '        "scalar_value": scalar_value,',
        '        "chart_series": chart_series,',
        '        "zero_division_count": zero_division_count,',
        "    }",
    ])

    python_source = "\n".join(source_lines) + "\n"

    try:
        candidate = GeneratedCodeCandidate(
            plan_sha256=plan_sha256,
            schema_sha256=schema_sha256,
            declared_imports=_DECLARED_IMPORTS,
            referenced_columns=canonical_required_ids,
            expected_result_type=plan.expected_result_type,
            python_source=python_source,
            execution_authorized=False,
        )
        validated_candidate = validate_code_candidate(candidate, plan=plan, schema=schema)
    except InferenceError as exc:
        raise CodeGenError(
            CodeGenCode.AST_POLICY_REJECTED if exc.code == InferenceCode.CODE_POLICY_VIOLATION else CodeGenCode.UNKNOWN_COLUMN,
            "Generated candidate failed GeneratedCodeCandidate contract validation.",
        ) from None

    try:
        ast_receipt = validate_candidate_ast(
            validated_candidate,
            expected_code_sha256=validated_candidate.code_sha256(),
        )
    except ASTPolicyError as exc:
        raise CodeGenError(CodeGenCode.AST_POLICY_REJECTED, exc.detail) from None

    return CompiledAnalysisCandidate(
        candidate=validated_candidate,
        ast_receipt=ast_receipt,
        plan_sha256=plan_sha256,
        schema_sha256=schema_sha256,
        code_sha256=validated_candidate.code_sha256(),
        output_columns=final_cols,
        expected_result_type=plan.expected_result_type,
        execution_authorized=False,
    )


# ============================================================================
# PHASE 5 — BOUNDED REPAIR CONTRACT (Transport-Neutral State & Policy Rules)
# ============================================================================

class RepairFailureKind(StrEnum):
    # Repairable execution/validation failures (subject to budget, deadline, cleanup, and active session)
    RUNTIME_EXCEPTION = "RUNTIME_EXCEPTION"
    EXECUTION_TIMED_OUT = "EXECUTION_TIMED_OUT"
    MALFORMED_OUTPUT_ARTIFACT = "MALFORMED_OUTPUT_ARTIFACT"
    NUMERICAL_VALIDATION_MISMATCH = "NUMERICAL_VALIDATION_MISMATCH"
    # Non-repairable policy / security violations (terminal immediately; never weaken AST or sandbox policy)
    AST_POLICY_VIOLATION = "AST_POLICY_VIOLATION"
    CODE_POLICY_VIOLATION = "CODE_POLICY_VIOLATION"
    UNSUPPORTED_OPERATION = "UNSUPPORTED_OPERATION"
    SECURITY_FAILURE = "SECURITY_FAILURE"
    # Non-repairable ambiguous external state (never automatically rerun ambiguous external execution)
    EXTERNAL_DISPATCH_AMBIGUOUS = "EXTERNAL_DISPATCH_AMBIGUOUS"
    CLEANUP_UNCONFIRMED = "CLEANUP_UNCONFIRMED"


_REPAIRABLE_FAILURE_KINDS: frozenset[RepairFailureKind] = frozenset({
    RepairFailureKind.RUNTIME_EXCEPTION,
    RepairFailureKind.EXECUTION_TIMED_OUT,
    RepairFailureKind.MALFORMED_OUTPUT_ARTIFACT,
    RepairFailureKind.NUMERICAL_VALIDATION_MISMATCH,
})

_SAFE_FAILURE_SUMMARIES: dict[RepairFailureKind, str] = {
    RepairFailureKind.RUNTIME_EXCEPTION: "Candidate execution exited with a runtime error.",
    RepairFailureKind.EXECUTION_TIMED_OUT: "Candidate execution exceeded the per-attempt wall/CPU budget.",
    RepairFailureKind.MALFORMED_OUTPUT_ARTIFACT: "Candidate output artifact failed structural validation.",
    RepairFailureKind.NUMERICAL_VALIDATION_MISMATCH: "Candidate numerical output failed independent verification.",
    RepairFailureKind.AST_POLICY_VIOLATION: "Candidate rejected by static AST admission policy.",
    RepairFailureKind.CODE_POLICY_VIOLATION: "Candidate rejected by code contract policy.",
    RepairFailureKind.UNSUPPORTED_OPERATION: "Plan requested an unsupported operation.",
    RepairFailureKind.SECURITY_FAILURE: "Sandbox security boundary violation detected.",
    RepairFailureKind.EXTERNAL_DISPATCH_AMBIGUOUS: "External container dispatch outcome is ambiguous.",
    RepairFailureKind.CLEANUP_UNCONFIRMED: "Prior container cleanup is not yet confirmed.",
}


@dataclass(frozen=True, slots=True)
class SanitizedFailureRecord:
    """Content-free failure descriptor safe for bounded repair state transitions.

    Never stores raw stderr, stack traces, cell values, file paths, or credentials.
    """

    failure_kind: RepairFailureKind
    repairable: bool
    step_number: int | None
    column_id: str | None
    safe_summary: str
    error_signature_sha256: str


@dataclass(frozen=True, slots=True)
class RepairBudgetState:
    """Current bounded run attempt/deadline state aligned with SQLite `runs` constraints."""

    run_id: str
    session_id: str
    session_active: bool
    cancel_requested: bool
    admitted_at: int
    deadline_at: int
    candidate_versions: int
    execution_attempts: int
    prior_cleanup_confirmed: bool

    def __post_init__(self) -> None:
        if not 0 <= self.candidate_versions <= MAX_CODE_CANDIDATES:
            raise ValueError("candidate_versions must be between 0 and 3.")
        if not 0 <= self.execution_attempts <= self.candidate_versions:
            raise ValueError("execution_attempts must be between 0 and candidate_versions.")
        if self.admitted_at <= 0 or not (
            self.admitted_at <= self.deadline_at <= self.admitted_at + MAX_RUN_WALL_SECONDS
        ):
            raise ValueError("deadline_at must be within 180 seconds of admitted_at.")


@dataclass(frozen=True, slots=True)
class RepairDecision:
    """Deterministic transition decision after an attempt or admission failure."""

    allow_repair: bool
    next_run_state: Literal[
        "REPAIR",
        "BLOCKED_POLICY",
        "SECURITY_FAILURE",
        "CANCELLED",
        "TIMED_OUT",
        "INTERRUPTED",
        "FAILED_EXECUTION",
        "FAILED_VALIDATION",
    ]
    next_candidate_version: int | None
    error_signature_sha256: str
    reason_code: str
    ast_policy_weakened: Literal[False] = False
    sandbox_policy_weakened: Literal[False] = False


def sanitize_failure_for_repair(
    failure_kind: RepairFailureKind,
    *,
    step_number: int | None = None,
    column_id: str | None = None,
    raw_diagnostic_ignored: object = None,
) -> SanitizedFailureRecord:
    """Produce a sanitized failure record without retaining raw exceptions or data samples."""
    del raw_diagnostic_ignored
    if type(failure_kind) is not RepairFailureKind:
        raise ValueError("Invalid RepairFailureKind.")
    if step_number is not None and (type(step_number) is not int or not 1 <= step_number <= 8):
        raise ValueError("step_number must be an integer between 1 and 8.")
    if column_id is not None and (type(column_id) is not str or not _STRICT_COL_ID_RE.fullmatch(column_id)):
        raise ValueError("column_id must match ^col_[0-9]{3}$.")

    canonical_sig = f"v1:{failure_kind.value}:step={step_number or 0}:col={column_id or 'none'}"
    sig_sha256 = hashlib.sha256(canonical_sig.encode("utf-8")).hexdigest()
    return SanitizedFailureRecord(
        failure_kind=failure_kind,
        repairable=failure_kind in _REPAIRABLE_FAILURE_KINDS,
        step_number=step_number,
        column_id=column_id,
        safe_summary=_SAFE_FAILURE_SUMMARIES[failure_kind],
        error_signature_sha256=sig_sha256,
    )


def evaluate_repair_transition(
    budget: RepairBudgetState,
    failure: SanitizedFailureRecord,
    *,
    now: int,
) -> RepairDecision:
    """Evaluate whether a failed attempt may enter REPAIR or must terminate fail-closed."""
    if type(budget) is not RepairBudgetState or type(failure) is not SanitizedFailureRecord:
        raise ValueError("Expected RepairBudgetState and SanitizedFailureRecord.")
    if type(now) is not int or now <= 0:
        raise ValueError("now must be a positive Unix timestamp.")

    # 1. Session ownership / revocation / cancellation takes highest priority
    if not budget.session_active or budget.cancel_requested:
        return RepairDecision(
            allow_repair=False,
            next_run_state="CANCELLED",
            next_candidate_version=None,
            error_signature_sha256=failure.error_signature_sha256,
            reason_code="SESSION_INACTIVE_OR_CANCELLED",
        )

    # 2. Policy & security violations are NEVER repairable
    if failure.failure_kind in {
        RepairFailureKind.AST_POLICY_VIOLATION,
        RepairFailureKind.CODE_POLICY_VIOLATION,
        RepairFailureKind.UNSUPPORTED_OPERATION,
    }:
        return RepairDecision(
            allow_repair=False,
            next_run_state="BLOCKED_POLICY",
            next_candidate_version=None,
            error_signature_sha256=failure.error_signature_sha256,
            reason_code=failure.failure_kind.value,
        )

    if failure.failure_kind == RepairFailureKind.SECURITY_FAILURE:
        return RepairDecision(
            allow_repair=False,
            next_run_state="SECURITY_FAILURE",
            next_candidate_version=None,
            error_signature_sha256=failure.error_signature_sha256,
            reason_code="SECURITY_FAILURE",
        )

    # 3. Ambiguous external execution or unconfirmed container cleanup is NEVER automatically rerun
    if (
        failure.failure_kind
        in {RepairFailureKind.EXTERNAL_DISPATCH_AMBIGUOUS, RepairFailureKind.CLEANUP_UNCONFIRMED}
        or not budget.prior_cleanup_confirmed
    ):
        return RepairDecision(
            allow_repair=False,
            next_run_state="INTERRUPTED",
            next_candidate_version=None,
            error_signature_sha256=failure.error_signature_sha256,
            reason_code="EXTERNAL_STATE_OR_CLEANUP_UNCONFIRMED",
        )

    # 4. Enforce 180-second run wall-clock deadline
    if now >= budget.deadline_at or (now - budget.admitted_at) >= MAX_RUN_WALL_SECONDS:
        return RepairDecision(
            allow_repair=False,
            next_run_state="TIMED_OUT",
            next_candidate_version=None,
            error_signature_sha256=failure.error_signature_sha256,
            reason_code="RUN_DEADLINE_EXCEEDED",
        )

    # 5. Enforce max 3 candidates and max 3 execution attempts
    if (
        budget.candidate_versions >= MAX_CODE_CANDIDATES
        or budget.execution_attempts >= MAX_EXECUTION_ATTEMPTS
    ):
        terminal_state: Literal["FAILED_VALIDATION", "FAILED_EXECUTION", "TIMED_OUT"] = (
            "FAILED_VALIDATION"
            if failure.failure_kind == RepairFailureKind.NUMERICAL_VALIDATION_MISMATCH
            else "TIMED_OUT"
            if failure.failure_kind == RepairFailureKind.EXECUTION_TIMED_OUT
            else "FAILED_EXECUTION"
        )
        return RepairDecision(
            allow_repair=False,
            next_run_state=terminal_state,
            next_candidate_version=None,
            error_signature_sha256=failure.error_signature_sha256,
            reason_code="ATTEMPT_BUDGET_EXHAUSTED",
        )

    return RepairDecision(
        allow_repair=True,
        next_run_state="REPAIR",
        next_candidate_version=budget.candidate_versions + 1,
        error_signature_sha256=failure.error_signature_sha256,
        reason_code="REPAIR_PERMITTED",
    )
