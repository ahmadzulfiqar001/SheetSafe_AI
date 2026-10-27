"""Independent numerical verifier foundation for SheetSafe AI (Step 10A).

SECURITY & ARCHITECTURAL INVARIANTS:
- Never executes or trusts generated Python code, candidate stdout, or
  candidate-reported checksums.
- Recomputes expected metrics, tables, ratios, rollups, and chart series
  independently using deterministic Python standard-library operations.
- Operates exclusively on validated `SyntheticTableFixture` structures in this
  foundation milestone; never exposes an in-process path that reads untrusted
  uploaded spreadsheets inside FastAPI.
- Production verification requires running the validator in its own isolated
  execution environment after candidate sandbox teardown (`cleanup_status == 'CONFIRMED'`).
  Host-side unit tests do not constitute production sandbox validation.
"""

from dataclasses import dataclass
from datetime import date
from enum import StrEnum
import hashlib
import json
import math
import re
import statistics
from typing import Literal

from backend.inference import (
    AIAnalysisPlan,
    AISchemaColumn,
     ExpectedResultType,
    InferredColumnType,
    ProposedOperation,
    ValidatedDatasetSchema,
)


MAX_CANDIDATE_ARTIFACT_BYTES = 512 * 1024
MAX_OUTPUT_ROWS = 1000
MAX_OUTPUT_COLUMNS = 32
MAX_CHART_POINTS = 200
MAX_CELL_STRING_CHARS = 1024

CellScalar = str | int | float | bool | None
_COLUMN_ID_RE = re.compile(r"^(?:col_[0-9]{3}|ratio_col_[0-9]{3}_col_[0-9]{3})$")


class VerificationCode(StrEnum):
    INVALID_FIXTURE = "INVALID_FIXTURE"
    SCHEMA_MISMATCH = "SCHEMA_MISMATCH"
    PLAN_MISMATCH = "PLAN_MISMATCH"
    UNKNOWN_COLUMN = "UNKNOWN_COLUMN"
    UNSUPPORTED_OPERATION = "UNSUPPORTED_OPERATION"
    INCOMPATIBLE_COLUMN_TYPE = "INCOMPATIBLE_COLUMN_TYPE"
    ARTIFACT_TOO_LARGE = "ARTIFACT_TOO_LARGE"
    MALFORMED_ARTIFACT = "MALFORMED_ARTIFACT"
    OUTPUT_LIMIT_EXCEEDED = "OUTPUT_LIMIT_EXCEEDED"
    RESULT_TYPE_MISMATCH = "RESULT_TYPE_MISMATCH"
    COLUMN_MISMATCH = "COLUMN_MISMATCH"
    ROW_COUNT_MISMATCH = "ROW_COUNT_MISMATCH"
    MISSING_VALUE_MISMATCH = "MISSING_VALUE_MISMATCH"
    VALUE_MISMATCH = "VALUE_MISMATCH"
    ORDER_OR_GROUP_MISMATCH = "ORDER_OR_GROUP_MISMATCH"
    NUMERICAL_TOLERANCE_EXCEEDED = "NUMERICAL_TOLERANCE_EXCEEDED"
    SCALAR_MISMATCH = "SCALAR_MISMATCH"
    FABRICATED_OR_MISMATCHED_CHART = "FABRICATED_OR_MISMATCHED_CHART"
    ZERO_DIVISION_MISMATCH = "ZERO_DIVISION_MISMATCH"


class VerificationError(ValueError):
    """Sanitized independent verification error; never publishes unverified data."""

    def __init__(self, code: VerificationCode, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"Independent verification failed ({code.value}): {detail}")


@dataclass(frozen=True, slots=True)
class NumericalTolerance:
    """Explicit floating-point comparison tolerance for numerical verification."""

    rel_tol: float = 1e-6
    abs_tol: float = 1e-9

    def __post_init__(self) -> None:
        if (
            type(self.rel_tol) not in {int, float}
            or type(self.abs_tol) not in {int, float}
            or not math.isfinite(self.rel_tol)
            or not math.isfinite(self.abs_tol)
            or self.rel_tol < 0.0
            or self.abs_tol < 0.0
            or self.rel_tol > 1e-2
            or self.abs_tol > 1e-2
        ):
            raise ValueError("Invalid numerical tolerance bounds.")


@dataclass(frozen=True, slots=True)
class ChartPoint:
    """Single verified chart series point."""

    x: str | int | float | bool
    y: float


@dataclass(frozen=True, slots=True)
class SyntheticTableFixture:
    """Validated in-memory synthetic dataset fixture for deterministic local verification."""

    schema_sha256: str
    columns: tuple[AISchemaColumn, ...]
    rows: tuple[dict[str, CellScalar], ...]
    synthetic_only: Literal[True] = True

    @classmethod
    def from_records(
        cls,
        schema: ValidatedDatasetSchema,
        records: list[dict[str, CellScalar]] | tuple[dict[str, CellScalar], ...],
    ) -> "SyntheticTableFixture":
        if type(schema) is not ValidatedDatasetSchema:
            raise VerificationError(VerificationCode.INVALID_FIXTURE, "Expected ValidatedDatasetSchema.")
        if not isinstance(records, (list, tuple)) or len(records) != schema.row_count:
            raise VerificationError(
                VerificationCode.INVALID_FIXTURE,
                "Fixture row count does not match ValidatedDatasetSchema.row_count.",
            )

        col_map = schema.column_map()
        expected_keys = set(col_map.keys())
        missing_Observed: dict[str, int] = {col_id: 0 for col_id in expected_keys}
        normalized_rows: list[dict[str, CellScalar]] = []

        for row in records:
            if type(row) is not dict or set(row.keys()) != expected_keys:
                raise VerificationError(
                    VerificationCode.INVALID_FIXTURE,
                    "Fixture row keys do not match schema column IDs.",
                )
            clean_row: dict[str, CellScalar] = {}
            for col in schema.columns:
                val = row[col.column_id]
                if val is None:
                    missing_Observed[col.column_id] += 1
                    clean_row[col.column_id] = None
                    continue
                clean_row[col.column_id] = _validate_fixture_cell(val, col.inferred_type)
            normalized_rows.append(clean_row)

        for col in schema.columns:
            if missing_Observed[col.column_id] != col.missing_count:
                raise VerificationError(
                    VerificationCode.INVALID_FIXTURE,
                    f"Fixture missing_count for {col.column_id} does not match schema.",
                )

        return cls(
            schema_sha256=schema.schema_sha256,
            columns=schema.columns,
            rows=tuple(normalized_rows),
        )


@dataclass(frozen=True, slots=True)
class ExpectedAnalysisResult:
    """Independently computed ground-truth result for a validated AIAnalysisPlan."""

    schema_sha256: str
    plan_sha256: str
    result_type: ExpectedResultType
    columns: tuple[str, ...]
    rows: tuple[dict[str, CellScalar], ...]
    row_count: int
    scalar_value: float | int | None
    chart_series: tuple[ChartPoint, ...]
    zero_division_count: int

    def canonical_sha256(self) -> str:
        payload = {
            "schema_sha256": self.schema_sha256,
            "plan_sha256": self.plan_sha256,
            "result_type": self.result_type,
            "columns": list(self.columns),
            "row_count": self.row_count,
            "rows": [
                {col: _canonicalize_scalar(row[col]) for col in self.columns}
                for row in self.rows
            ],
            "scalar_value": _canonicalize_scalar(self.scalar_value),
            "chart_series": [
                {"x": _canonicalize_scalar(pt.x), "y": _canonicalize_scalar(pt.y)}
                for pt in self.chart_series
            ],
            "zero_division_count": self.zero_division_count,
        }
        encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True, allow_nan=False).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class VerificationReceipt:
    """Immutable receipt emitted only when independent numerical verification succeeds."""

    validation_status: Literal["PASSED"]
    schema_sha256: str
    plan_sha256: str
    verified_output_sha256: str
    result_type: ExpectedResultType
    row_count: int
    zero_division_count: int
    max_abs_error: float
    verified_result: ExpectedAnalysisResult
    publication_authorized: Literal[False] = False
    sandbox_execution_verified: Literal[False] = False


def _canonicalize_scalar(value: CellScalar) -> CellScalar:
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("Non-finite float in canonical result.")
        return round(0.0 if value == 0.0 else value, 12)
    return value


def _validate_fixture_cell(value: object, inferred_type: InferredColumnType) -> CellScalar:
    if inferred_type in {"empty", "mixed"}:
        raise VerificationError(
            VerificationCode.INCOMPATIBLE_COLUMN_TYPE,
            f"Column type '{inferred_type}' cannot be deterministically verified.",
        )
    if inferred_type == "integer":
        if type(value) is not int:
            raise VerificationError(VerificationCode.INVALID_FIXTURE, "Expected integer cell value.")
        return value
    if inferred_type == "number":
        if type(value) not in {int, float} or not math.isfinite(float(value)):
            raise VerificationError(VerificationCode.INVALID_FIXTURE, "Expected finite numeric cell value.")
        return float(value)
    if inferred_type == "boolean":
        if type(value) is not bool:
            raise VerificationError(VerificationCode.INVALID_FIXTURE, "Expected boolean cell value.")
        return value
    if inferred_type == "date":
        if type(value) is not str:
            raise VerificationError(VerificationCode.INVALID_FIXTURE, "Expected ISO date string.")
        try:
            parsed = date.fromisoformat(value)
        except ValueError:
            raise VerificationError(VerificationCode.INVALID_FIXTURE, "Invalid ISO-8601 date value.") from None
        return parsed.isoformat()
    if inferred_type == "text":
        if type(value) is not str or len(value) > MAX_CELL_STRING_CHARS:
            raise VerificationError(VerificationCode.INVALID_FIXTURE, "Expected bounded text cell value.")
        return value
    raise VerificationError(VerificationCode.INCOMPATIBLE_COLUMN_TYPE, "Unsupported column type.")


def validate_plan_for_execution(
    plan: AIAnalysisPlan,
    schema: ValidatedDatasetSchema,
) -> tuple[tuple[str, ...], dict[str, InferredColumnType]]:
    """Verify plan/schema binding, operation support, and step-by-step column availability.

    Returns `(final_columns, final_column_types)` if all steps are supported and type-safe.
    """
    if type(plan) is not AIAnalysisPlan or type(schema) is not ValidatedDatasetSchema:
        raise VerificationError(VerificationCode.PLAN_MISMATCH, "Invalid plan or schema contract type.")
    if plan.schema_sha256 != schema.schema_sha256:
        raise VerificationError(VerificationCode.SCHEMA_MISMATCH, "Plan schema_sha256 does not match schema.")

    col_map = schema.column_map()
    for req_col in plan.required_columns:
        actual = col_map.get(req_col.column_id)
        if actual is None or actual.name != req_col.name or actual.inferred_type != req_col.expected_type:
            raise VerificationError(
                VerificationCode.UNKNOWN_COLUMN,
                f"Required column {req_col.column_id} does not match schema.",
            )
        if actual.inferred_type in {"empty", "mixed"}:
            raise VerificationError(
                VerificationCode.INCOMPATIBLE_COLUMN_TYPE,
                f"Column {req_col.column_id} has unsupported type '{actual.inferred_type}'.",
            )

    active_cols: list[str] = sorted(req.column_id for req in plan.required_columns)
    active_types: dict[str, InferredColumnType] = {
        req.column_id: req.expected_type for req in plan.required_columns
    }

    for op in plan.operations:
        if op.operation == "FILTER_ROWS":
            # ProposedOperation.v1 intentionally carries no structured predicate operator/value,
            # and free-text rationale is never parsed as executable logic.
            raise VerificationError(
                VerificationCode.UNSUPPORTED_OPERATION,
                "FILTER_ROWS is unsupported because ProposedOperation v1 carries no typed filter predicate.",
            )

        for col_id in (*op.target_columns, *op.group_by_columns):
            if col_id not in col_map:
                raise VerificationError(
                    VerificationCode.UNKNOWN_COLUMN,
                    f"Operation step {op.step_number} references unknown column {col_id}.",
                )
            if col_id not in active_types:
                raise VerificationError(
                    VerificationCode.UNKNOWN_COLUMN,
                    f"Column {col_id} is no longer available at step {op.step_number}.",
                )

        if op.operation == "SELECT_COLUMNS":
            active_cols = list(op.target_columns)
            active_types = {col_id: active_types[col_id] for col_id in active_cols}

        elif op.operation == "DROP_MISSING":
            pass

        elif op.operation == "GROUP_AGGREGATE":
            assert op.aggregation is not None
            for g_col in op.group_by_columns:
                if active_types[g_col] not in {"text", "integer", "boolean", "date"}:
                    raise VerificationError(
                        VerificationCode.INCOMPATIBLE_COLUMN_TYPE,
                        f"Grouping column {g_col} has unsupported grouping type '{active_types[g_col]}'.",
                    )
            new_types: dict[str, InferredColumnType] = {
                g_col: active_types[g_col] for g_col in op.group_by_columns
            }
            for t_col in op.target_columns:
                t_type = active_types[t_col]
                new_types[t_col] = _validate_aggregation_type(t_col, t_type, op.aggregation)
            active_cols = [*op.group_by_columns, *op.target_columns]
            active_types = new_types

        elif op.operation == "SUMMARY_STATS":
            assert op.aggregation is not None
            new_types = {}
            for t_col in op.target_columns:
                t_type = active_types[t_col]
                new_types[t_col] = _validate_aggregation_type(t_col, t_type, op.aggregation)
            active_cols = list(op.target_columns)
            active_types = new_types

        elif op.operation in {"SORT_VALUES", "TOP_N"}:
            for t_col in op.target_columns:
                if active_types[t_col] not in {"integer", "number", "date", "text", "boolean"}:
                    raise VerificationError(
                        VerificationCode.INCOMPATIBLE_COLUMN_TYPE,
                        f"Column {t_col} cannot be sorted deterministically.",
                    )

        elif op.operation == "COMPUTE_RATIO":
            if len(op.target_columns) != 2:
                raise VerificationError(
                    VerificationCode.UNSUPPORTED_OPERATION,
                    "COMPUTE_RATIO requires exactly 2 numeric columns.",
                )
            num_col, den_col = op.target_columns
            if active_types[num_col] not in {"integer", "number"} or active_types[den_col] not in {"integer", "number"}:
                raise VerificationError(
                    VerificationCode.INCOMPATIBLE_COLUMN_TYPE,
                    "COMPUTE_RATIO requires integer or number columns.",
                )
            ratio_col = f"ratio_{num_col}_{den_col}"
            if ratio_col not in active_types:
                active_cols.append(ratio_col)
            active_types[ratio_col] = "number"

        elif op.operation == "TIME_SERIES_ROLLUP":
            if len(op.target_columns) < 2:
                raise VerificationError(
                    VerificationCode.UNSUPPORTED_OPERATION,
                    "TIME_SERIES_ROLLUP requires a date column plus at least one numeric metric column.",
                )
            date_col = op.target_columns[0]
            metric_cols = op.target_columns[1:]
            if active_types[date_col] != "date":
                raise VerificationError(
                    VerificationCode.INCOMPATIBLE_COLUMN_TYPE,
                    f"TIME_SERIES_ROLLUP first target column {date_col} must be of type 'date'.",
                )
            new_types = {date_col: "date"}
            for m_col in metric_cols:
                if active_types[m_col] not in {"integer", "number"}:
                    raise VerificationError(
                        VerificationCode.INCOMPATIBLE_COLUMN_TYPE,
                        f"TIME_SERIES_ROLLUP metric column {m_col} must be numeric.",
                    )
                new_types[m_col] = active_types[m_col]
            active_cols = [date_col, *metric_cols]
            active_types = new_types

        elif op.operation == "CHART_SERIES":
            if len(op.target_columns) != 2:
                raise VerificationError(
                    VerificationCode.UNSUPPORTED_OPERATION,
                    "CHART_SERIES requires exactly 2 columns (x_axis, y_metric).",
                )
            x_col, y_col = op.target_columns
            if active_types[x_col] not in {"date", "text", "integer", "boolean"}:
                raise VerificationError(
                    VerificationCode.INCOMPATIBLE_COLUMN_TYPE,
                    f"CHART_SERIES x-axis column {x_col} has unsupported type '{active_types[x_col]}'.",
                )
            if active_types[y_col] not in {"integer", "number"}:
                raise VerificationError(
                    VerificationCode.INCOMPATIBLE_COLUMN_TYPE,
                    f"CHART_SERIES y-axis column {y_col} must be numeric.",
                )
            active_cols = [x_col, y_col]
            active_types = {x_col: active_types[x_col], y_col: active_types[y_col]}

        else:
            raise VerificationError(
                VerificationCode.UNSUPPORTED_OPERATION,
                f"Operation '{op.operation}' is not supported.",
            )

        if len(active_cols) > MAX_OUTPUT_COLUMNS:
            raise VerificationError(
                VerificationCode.OUTPUT_LIMIT_EXCEEDED,
                "Active column count exceeds MAX_OUTPUT_COLUMNS.",
            )

    if plan.expected_result_type in {"BAR_CHART", "LINE_CHART"}:
        if len(active_cols) < 2:
            raise VerificationError(
                VerificationCode.INCOMPATIBLE_COLUMN_TYPE,
                "Chart result requires at least 2 output columns (x_axis and numeric y_axis).",
            )
        x_col, y_col = active_cols[0], active_cols[1]
        if active_types[y_col] not in {"integer", "number"}:
            raise VerificationError(
                VerificationCode.INCOMPATIBLE_COLUMN_TYPE,
                "Chart y-axis column must be numeric.",
            )
        if plan.expected_result_type == "LINE_CHART" and active_types[x_col] not in {"date", "integer", "number"}:
            raise VerificationError(
                VerificationCode.INCOMPATIBLE_COLUMN_TYPE,
                "LINE_CHART requires a date or numeric x-axis column.",
            )

    if plan.expected_result_type == "SCALAR_METRIC":
        if not any(active_types[c] in {"integer", "number"} for c in active_cols):
            raise VerificationError(
                VerificationCode.INCOMPATIBLE_COLUMN_TYPE,
                "SCALAR_METRIC requires a numeric output column.",
            )

    return tuple(active_cols), active_types


def _validate_aggregation_type(
    col_id: str,
    col_type: InferredColumnType,
    aggregation: str,
) -> InferredColumnType:
    if aggregation == "count":
        return "integer"
    if aggregation in {"sum", "mean", "median", "std"}:
        if col_type not in {"integer", "number"}:
            raise VerificationError(
                VerificationCode.INCOMPATIBLE_COLUMN_TYPE,
                f"Aggregation '{aggregation}' on {col_id} requires integer or number type.",
            )
        return "integer" if (aggregation == "sum" and col_type == "integer") else "number"
    if aggregation in {"min", "max"}:
        if col_type not in {"integer", "number", "date"}:
            raise VerificationError(
                VerificationCode.INCOMPATIBLE_COLUMN_TYPE,
                f"Aggregation '{aggregation}' on {col_id} requires numeric or date type.",
            )
        return col_type
    raise VerificationError(
        VerificationCode.UNSUPPORTED_OPERATION,
        f"Unsupported aggregation metric '{aggregation}'.",
    )


def _compute_aggregate(values: list[CellScalar], aggregation: str, col_type: InferredColumnType) -> CellScalar:
    non_missing = [v for v in values if v is not None]
    if aggregation == "count":
        return len(non_missing)
    if not non_missing:
        return None
    if aggregation == "sum":
        if col_type == "integer" and all(type(v) is int for v in non_missing):
            return sum(int(v) for v in non_missing)
        return float(math.fsum(float(v) for v in non_missing))
    if aggregation == "mean":
        return float(math.fsum(float(v) for v in non_missing) / len(non_missing))
    if aggregation == "median":
        return float(statistics.median(float(v) for v in non_missing))
    if aggregation == "min":
        if col_type == "date":
            return min(str(v) for v in non_missing)
        if col_type == "integer" and all(type(v) is int for v in non_missing):
            return min(int(v) for v in non_missing)
        return float(min(float(v) for v in non_missing))
    if aggregation == "max":
        if col_type == "date":
            return max(str(v) for v in non_missing)
        if col_type == "integer" and all(type(v) is int for v in non_missing):
            return max(int(v) for v in non_missing)
        return float(max(float(v) for v in non_missing))
    if aggregation == "std":
        if len(non_missing) < 2:
            return None
        return float(statistics.stdev(float(v) for v in non_missing))
    raise VerificationError(VerificationCode.UNSUPPORTED_OPERATION, f"Unsupported aggregation '{aggregation}'.")


def _sort_rows(
    rows: list[dict[str, CellScalar]],
    target_columns: tuple[str, ...],
    sort_direction: Literal["asc", "desc"],
    col_types: dict[str, InferredColumnType],
) -> list[dict[str, CellScalar]]:
    """Deterministic multi-column sort with missing values (`None`) always placed last."""
    if not rows:
        return []
    result = list(rows)
    reverse = sort_direction == "desc"
    # Stable sort from right-most key to left-most key, partitioning missing values last at each key
    for col_id in reversed(target_columns):
        c_type = col_types[col_id]
        present: list[dict[str, CellScalar]] = []
        missing: list[dict[str, CellScalar]] = []
        for row in result:
            if row.get(col_id) is None:
                missing.append(row)
            else:
                present.append(row)
        if c_type == "date":
            present.sort(key=lambda r: date.fromisoformat(str(r[col_id])), reverse=reverse)
        elif c_type in {"integer", "number"}:
            present.sort(key=lambda r: float(r[col_id]), reverse=reverse)  # type: ignore[arg-type]
        elif c_type == "boolean":
            present.sort(key=lambda r: bool(r[col_id]), reverse=reverse)
        else:
            present.sort(key=lambda r: str(r[col_id]), reverse=reverse)
        result = present + missing
    return result


def compute_expected_analysis_result(
    plan: AIAnalysisPlan,
    schema: ValidatedDatasetSchema,
    fixture: SyntheticTableFixture,
) -> ExpectedAnalysisResult:
    """Independently compute ground-truth analysis output using pure stdlib operations."""
    if type(fixture) is not SyntheticTableFixture or not fixture.synthetic_only:
        raise VerificationError(VerificationCode.INVALID_FIXTURE, "Expected validated SyntheticTableFixture.")
    if fixture.schema_sha256 != schema.schema_sha256:
        raise VerificationError(VerificationCode.SCHEMA_MISMATCH, "Fixture schema_sha256 does not match schema.")

    validate_plan_for_execution(plan, schema)

    active_cols: list[str] = sorted(req.column_id for req in plan.required_columns)
    active_types: dict[str, InferredColumnType] = {
        req.column_id: req.expected_type for req in plan.required_columns
    }
    working_rows: list[dict[str, CellScalar]] = [
        {col_id: row[col_id] for col_id in active_cols}
        for row in fixture.rows
    ]
    zero_division_count = 0

    for op in plan.operations:
        if op.operation == "SELECT_COLUMNS":
            active_cols = list(op.target_columns)
            active_types = {col_id: active_types[col_id] for col_id in active_cols}
            working_rows = [{col_id: row[col_id] for col_id in active_cols} for row in working_rows]

        elif op.operation == "DROP_MISSING":
            working_rows = [
                dict(row)
                for row in working_rows
                if all(row.get(col_id) is not None for col_id in op.target_columns)
            ]

        elif op.operation == "GROUP_AGGREGATE":
            assert op.aggregation is not None
            grouped: dict[tuple[CellScalar, ...], list[dict[str, CellScalar]]] = {}
            for row in working_rows:
                if any(row.get(g_col) is None for g_col in op.group_by_columns):
                    continue
                key = tuple(row[g_col] for g_col in op.group_by_columns)
                grouped.setdefault(key, []).append(row)

            # Sort group keys deterministically ascending
            sorted_keys = sorted(grouped.keys(), key=lambda k: tuple(
                date.fromisoformat(str(v)).toordinal()
                if active_types[op.group_by_columns[idx]] == "date"
                else (float(v) if active_types[op.group_by_columns[idx]] in {"integer", "number"} else str(v))
                for idx, v in enumerate(k)
            ))

            new_rows: list[dict[str, CellScalar]] = []
            new_types: dict[str, InferredColumnType] = {
                g_col: active_types[g_col] for g_col in op.group_by_columns
            }
            for t_col in op.target_columns:
                new_types[t_col] = _validate_aggregation_type(t_col, active_types[t_col], op.aggregation)

            for key in sorted_keys:
                bucket = grouped[key]
                out_row: dict[str, CellScalar] = {
                    g_col: key[idx] for idx, g_col in enumerate(op.group_by_columns)
                }
                for t_col in op.target_columns:
                    col_vals = [r[t_col] for r in bucket]
                    out_row[t_col] = _compute_aggregate(col_vals, op.aggregation, active_types[t_col])
                new_rows.append(out_row)

            active_cols = [*op.group_by_columns, *op.target_columns]
            active_types = new_types
            working_rows = new_rows

        elif op.operation == "SUMMARY_STATS":
            assert op.aggregation is not None
            summary_row: dict[str, CellScalar] = {}
            new_types = {}
            for t_col in op.target_columns:
                new_types[t_col] = _validate_aggregation_type(t_col, active_types[t_col], op.aggregation)
                col_vals = [r[t_col] for r in working_rows]
                summary_row[t_col] = _compute_aggregate(col_vals, op.aggregation, active_types[t_col])
            active_cols = list(op.target_columns)
            active_types = new_types
            working_rows = [summary_row]

        elif op.operation == "SORT_VALUES":
            assert op.sort_direction is not None
            working_rows = _sort_rows(working_rows, op.target_columns, op.sort_direction, active_types)

        elif op.operation == "TOP_N":
            assert op.sort_direction is not None and op.limit_rows is not None
            sorted_rows = _sort_rows(working_rows, op.target_columns, op.sort_direction, active_types)
            working_rows = sorted_rows[: min(op.limit_rows, MAX_OUTPUT_ROWS)]

        elif op.operation == "COMPUTE_RATIO":
            num_col, den_col = op.target_columns
            ratio_col = f"ratio_{num_col}_{den_col}"
            if ratio_col not in active_types:
                active_cols.append(ratio_col)
            active_types[ratio_col] = "number"
            new_rows = []
            for row in working_rows:
                updated = dict(row)
                num_val = row.get(num_col)
                den_val = row.get(den_col)
                if num_val is None or den_val is None:
                    updated[ratio_col] = None
                elif float(den_val) == 0.0:
                    updated[ratio_col] = None
                    zero_division_count += 1
                else:
                    updated[ratio_col] = float(num_val) / float(den_val)
                new_rows.append(updated)
            working_rows = new_rows

        elif op.operation == "TIME_SERIES_ROLLUP":
            date_col = op.target_columns[0]
            metric_cols = op.target_columns[1:]
            by_date: dict[str, list[dict[str, CellScalar]]] = {}
            for row in working_rows:
                d_val = row.get(date_col)
                if d_val is None:
                    continue
                iso_str = date.fromisoformat(str(d_val)).isoformat()
                by_date.setdefault(iso_str, []).append(row)

            sorted_dates = sorted(by_date.keys(), key=date.fromisoformat)
            new_rows = []
            new_types = {date_col: "date"}
            for m_col in metric_cols:
                new_types[m_col] = active_types[m_col]

            for d_key in sorted_dates:
                bucket = by_date[d_key]
                out_row = {date_col: d_key}
                for m_col in metric_cols:
                    vals = [r[m_col] for r in bucket]
                    out_row[m_col] = _compute_aggregate(vals, "sum", active_types[m_col])
                new_rows.append(out_row)

            active_cols = [date_col, *metric_cols]
            active_types = new_types
            working_rows = new_rows

        elif op.operation == "CHART_SERIES":
            x_col, y_col = op.target_columns
            active_cols = [x_col, y_col]
            active_types = {x_col: active_types[x_col], y_col: active_types[y_col]}
            working_rows = [
                {x_col: row[x_col], y_col: row[y_col]}
                for row in working_rows
                if row.get(x_col) is not None and row.get(y_col) is not None
            ][:MAX_CHART_POINTS]

    if len(working_rows) > MAX_OUTPUT_ROWS:
        raise VerificationError(
            VerificationCode.OUTPUT_LIMIT_EXCEEDED,
            f"Expected output row count ({len(working_rows)}) exceeds MAX_OUTPUT_ROWS ({MAX_OUTPUT_ROWS}).",
        )

    chart_points: list[ChartPoint] = []
    if plan.expected_result_type in {"BAR_CHART", "LINE_CHART"} or any(
        op.operation == "CHART_SERIES" for op in plan.operations
    ):
        x_col, y_col = active_cols[0], active_cols[1]
        for row in working_rows:
            x_val = row.get(x_col)
            y_val = row.get(y_col)
            if x_val is not None and y_val is not None:
                chart_points.append(ChartPoint(x=x_val, y=float(y_val)))
        if len(chart_points) > MAX_CHART_POINTS:
            raise VerificationError(
                VerificationCode.OUTPUT_LIMIT_EXCEEDED,
                f"Chart point count ({len(chart_points)}) exceeds MAX_CHART_POINTS ({MAX_CHART_POINTS}).",
            )

    scalar_val: float | int | None = None
    if plan.expected_result_type == "SCALAR_METRIC":
        numeric_cols = [c for c in active_cols if active_types[c] in {"integer", "number"}]
        if len(working_rows) == 1 and numeric_cols:
            raw_scalar = working_rows[0].get(numeric_cols[-1])
            if raw_scalar is not None and type(raw_scalar) in {int, float}:
                scalar_val = raw_scalar

    return ExpectedAnalysisResult(
        schema_sha256=schema.schema_sha256,
        plan_sha256=plan.plan_sha256(),
        result_type=plan.expected_result_type,
        columns=tuple(active_cols),
        rows=tuple(working_rows),
        row_count=len(working_rows),
        scalar_value=scalar_val,
        chart_series=tuple(chart_points),
        zero_division_count=zero_division_count,
    )


def _parse_strict_candidate_json(raw: str | bytes | dict[str, object]) -> dict[str, object]:
    if isinstance(raw, dict):
        encoded_check = json.dumps(raw, separators=(",", ":"), allow_nan=False).encode("utf-8")
        if len(encoded_check) > MAX_CANDIDATE_ARTIFACT_BYTES:
            raise VerificationError(
                VerificationCode.ARTIFACT_TOO_LARGE,
                "Candidate output artifact exceeds maximum byte budget.",
            )
        return raw

    if isinstance(raw, str):
        encoded = raw.encode("utf-8", errors="strict")
    elif type(raw) is bytes:
        encoded = raw
    else:
        raise VerificationError(VerificationCode.MALFORMED_ARTIFACT, "Candidate output must be bytes, str, or dict.")

    if len(encoded) == 0:
        raise VerificationError(VerificationCode.MALFORMED_ARTIFACT, "Candidate output is empty.")
    if len(encoded) > MAX_CANDIDATE_ARTIFACT_BYTES:
        raise VerificationError(
            VerificationCode.ARTIFACT_TOO_LARGE,
            "Candidate output artifact exceeds maximum byte budget.",
        )

    def unique_pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        obj: dict[str, object] = {}
        for k, v in items:
            if k in obj:
                raise ValueError("Duplicate JSON key")
            obj[k] = v
        return obj

    def reject_nonfinite(_: str) -> None:
        raise ValueError("Non-finite JSON constant")

    try:
        parsed = json.loads(
            encoded.decode("utf-8", errors="strict"),
            object_pairs_hook=unique_pairs,
            parse_constant=reject_nonfinite,
        )
    except Exception:
        raise VerificationError(
            VerificationCode.MALFORMED_ARTIFACT,
            "Candidate output is not valid strict JSON.",
        ) from None

    if type(parsed) is not dict:
        raise VerificationError(
            VerificationCode.MALFORMED_ARTIFACT,
            "Top-level candidate artifact must be a JSON object.",
        )
    return parsed


def verify_candidate_output(
    raw_candidate_output: str | bytes | dict[str, object],
    *,
    plan: AIAnalysisPlan,
    schema: ValidatedDatasetSchema,
    fixture: SyntheticTableFixture,
    tolerance: NumericalTolerance = NumericalTolerance(),
) -> VerificationReceipt:
    """Independently recompute expected results and verify untrusted candidate output."""
    expected = compute_expected_analysis_result(plan, schema, fixture)
    payload = _parse_strict_candidate_json(raw_candidate_output)

    allowed_keys = {
        "schema_sha256",
        "plan_sha256",
        "result_type",
        "columns",
        "row_count",
        "rows",
        "scalar_value",
        "chart_series",
        "zero_division_count",
    }
    required_keys = {
        "schema_sha256",
        "plan_sha256",
        "result_type",
        "columns",
        "row_count",
        "rows",
    }
    if not required_keys.issubset(payload.keys()) or not set(payload.keys()).issubset(allowed_keys):
        raise VerificationError(
            VerificationCode.MALFORMED_ARTIFACT,
            "Candidate artifact has missing or unexpected top-level keys.",
        )

    if payload.get("schema_sha256") != expected.schema_sha256:
        raise VerificationError(VerificationCode.SCHEMA_MISMATCH, "Candidate schema_sha256 mismatch.")
    if payload.get("plan_sha256") != expected.plan_sha256:
        raise VerificationError(VerificationCode.PLAN_MISMATCH, "Candidate plan_sha256 mismatch.")
    if payload.get("result_type") != expected.result_type:
        raise VerificationError(VerificationCode.RESULT_TYPE_MISMATCH, "Candidate result_type mismatch.")

    cand_cols = payload.get("columns")
    if not isinstance(cand_cols, (list, tuple)) or any(
        type(c) is not str or not _COLUMN_ID_RE.fullmatch(c) for c in cand_cols
    ):
        raise VerificationError(VerificationCode.MALFORMED_ARTIFACT, "Invalid candidate columns list.")
    if len(cand_cols) > MAX_OUTPUT_COLUMNS:
        raise VerificationError(VerificationCode.OUTPUT_LIMIT_EXCEEDED, "Candidate column count exceeds limit.")
    if tuple(cand_cols) != expected.columns:
        raise VerificationError(VerificationCode.COLUMN_MISMATCH, "Candidate columns do not match expected columns.")

    cand_rows = payload.get("rows")
    cand_row_count = payload.get("row_count")
    if type(cand_row_count) is not int or not isinstance(cand_rows, (list, tuple)):
        raise VerificationError(VerificationCode.MALFORMED_ARTIFACT, "Invalid candidate rows or row_count.")
    if cand_row_count != len(cand_rows):
        raise VerificationError(VerificationCode.MALFORMED_ARTIFACT, "Candidate row_count does not match len(rows).")
    if len(cand_rows) > MAX_OUTPUT_ROWS:
        raise VerificationError(VerificationCode.OUTPUT_LIMIT_EXCEEDED, "Candidate row count exceeds MAX_OUTPUT_ROWS.")
    if len(cand_rows) != expected.row_count:
        raise VerificationError(
            VerificationCode.ROW_COUNT_MISMATCH,
            f"Candidate row count ({len(cand_rows)}) does not match expected ({expected.row_count}).",
        )

    if "zero_division_count" in payload:
        z_count = payload["zero_division_count"]
        if type(z_count) is not int or z_count < 0:
            raise VerificationError(VerificationCode.MALFORMED_ARTIFACT, "Invalid zero_division_count.")
        if z_count != expected.zero_division_count:
            raise VerificationError(
                VerificationCode.ZERO_DIVISION_MISMATCH,
                "Candidate zero_division_count does not match independent count.",
            )

    max_abs_error = 0.0

    # Verify rows cell-by-cell
    for row_idx, (exp_row, act_row) in enumerate(zip(expected.rows, cand_rows, strict=True)):
        if type(act_row) is not dict or set(act_row.keys()) != set(expected.columns):
            raise VerificationError(
                VerificationCode.MALFORMED_ARTIFACT,
                f"Row {row_idx} keys do not match expected columns.",
            )
        for col_id in expected.columns:
            exp_val = exp_row[col_id]
            act_val = act_row[col_id]
            err = _compare_cell(exp_val, act_val, tolerance=tolerance, context=f"row {row_idx} col {col_id}")
            if err > max_abs_error:
                max_abs_error = err

    # Verify scalar_value when expected_result_type == SCALAR_METRIC
    cand_scalar = payload.get("scalar_value")
    if expected.result_type == "SCALAR_METRIC":
        if expected.scalar_value is None:
            if cand_scalar is not None:
                raise VerificationError(VerificationCode.SCALAR_MISMATCH, "Expected null scalar_value.")
        else:
            if type(cand_scalar) not in {int, float} or not math.isfinite(float(cand_scalar)):
                raise VerificationError(VerificationCode.SCALAR_MISMATCH, "Candidate scalar_value must be numeric.")
            diff = abs(float(cand_scalar) - float(expected.scalar_value))
            if not math.isclose(
                float(cand_scalar),
                float(expected.scalar_value),
                rel_tol=tolerance.rel_tol,
                abs_tol=tolerance.abs_tol,
            ):
                raise VerificationError(
                    VerificationCode.NUMERICAL_TOLERANCE_EXCEEDED,
                    "Candidate scalar_value exceeded numerical tolerance.",
                )
            if diff > max_abs_error:
                max_abs_error = diff
    elif cand_scalar is not None:
        raise VerificationError(
            VerificationCode.SCALAR_MISMATCH,
            "Unexpected scalar_value for non-scalar result_type.",
        )

    # Verify chart_series
    cand_chart = payload.get("chart_series")
    if expected.chart_series:
        if not isinstance(cand_chart, (list, tuple)):
            raise VerificationError(
                VerificationCode.FABRICATED_OR_MISMATCHED_CHART,
                "Expected chart_series list for chart result.",
            )
        if len(cand_chart) > MAX_CHART_POINTS:
            raise VerificationError(
                VerificationCode.OUTPUT_LIMIT_EXCEEDED,
                "Candidate chart_series exceeds MAX_CHART_POINTS.",
            )
        if len(cand_chart) != len(expected.chart_series):
            raise VerificationError(
                VerificationCode.FABRICATED_OR_MISMATCHED_CHART,
                "Candidate chart_series point count does not match expected.",
            )
        for pt_idx, (exp_pt, act_pt) in enumerate(zip(expected.chart_series, cand_chart, strict=True)):
            if type(act_pt) is not dict or set(act_pt.keys()) != {"x", "y"}:
                raise VerificationError(
                    VerificationCode.FABRICATED_OR_MISMATCHED_CHART,
                    f"Chart point {pt_idx} has invalid structure.",
                )
            _compare_chart_x(exp_pt.x, act_pt["x"], tolerance=tolerance, context=f"chart[{pt_idx}].x")
            y_val = act_pt["y"]
            if type(y_val) not in {int, float} or not math.isfinite(float(y_val)):
                raise VerificationError(
                    VerificationCode.FABRICATED_OR_MISMATCHED_CHART,
                    f"Chart point {pt_idx} y-value is not a finite number.",
                )
            diff = abs(float(y_val) - exp_pt.y)
            if not math.isclose(
                float(y_val),
                exp_pt.y,
                rel_tol=tolerance.rel_tol,
                abs_tol=tolerance.abs_tol,
            ):
                raise VerificationError(
                    VerificationCode.FABRICATED_OR_MISMATCHED_CHART,
                    f"Chart point {pt_idx} y-value deviates from expected data.",
                )
            if diff > max_abs_error:
                max_abs_error = diff
    else:
        if cand_chart not in (None, [], ()):
            raise VerificationError(
                VerificationCode.FABRICATED_OR_MISMATCHED_CHART,
                "Candidate fabricated unexpected chart_series data.",
            )

    return VerificationReceipt(
        validation_status="PASSED",
        schema_sha256=expected.schema_sha256,
        plan_sha256=expected.plan_sha256,
        verified_output_sha256=expected.canonical_sha256(),
        result_type=expected.result_type,
        row_count=expected.row_count,
        zero_division_count=expected.zero_division_count,
        max_abs_error=max_abs_error,
        verified_result=expected,
    )


def _compare_cell(
    expected_val: CellScalar,
    actual_val: object,
    *,
    tolerance: NumericalTolerance,
    context: str,
) -> float:
    if expected_val is None:
        if actual_val is not None:
            raise VerificationError(
                VerificationCode.MISSING_VALUE_MISMATCH,
                f"Expected null at {context}, got non-null value.",
            )
        return 0.0
    if actual_val is None:
        raise VerificationError(
            VerificationCode.MISSING_VALUE_MISMATCH,
            f"Unexpected null at {context}.",
        )
    if type(expected_val) is bool:
        if type(actual_val) is not bool or actual_val != expected_val:
            raise VerificationError(
                VerificationCode.VALUE_MISMATCH,
                f"Boolean mismatch at {context}.",
            )
        return 0.0
    if type(expected_val) in {int, float}:
        if type(actual_val) not in {int, float} or not math.isfinite(float(actual_val)):
            raise VerificationError(
                VerificationCode.VALUE_MISMATCH,
                f"Expected finite numeric value at {context}.",
            )
        diff = abs(float(actual_val) - float(expected_val))
        if not math.isclose(
            float(actual_val),
            float(expected_val),
            rel_tol=tolerance.rel_tol,
            abs_tol=tolerance.abs_tol,
        ):
            raise VerificationError(
                VerificationCode.NUMERICAL_TOLERANCE_EXCEEDED,
                f"Numerical value at {context} exceeded tolerance.",
            )
        return diff
    if type(expected_val) is str:
        if type(actual_val) is not str or actual_val != expected_val:
            raise VerificationError(
                VerificationCode.ORDER_OR_GROUP_MISMATCH,
                f"Label/date mismatch at {context}.",
            )
        return 0.0
    raise VerificationError(VerificationCode.VALUE_MISMATCH, f"Unsupported value comparison at {context}.")


def _compare_chart_x(
    expected_x: str | int | float | bool,
    actual_x: object,
    *,
    tolerance: NumericalTolerance,
    context: str,
) -> None:
    if type(expected_x) is bool:
        if type(actual_x) is not bool or actual_x != expected_x:
            raise VerificationError(
                VerificationCode.FABRICATED_OR_MISMATCHED_CHART,
                f"Chart x-axis boolean mismatch at {context}.",
            )
    elif type(expected_x) in {int, float}:
        if type(actual_x) not in {int, float} or not math.isfinite(float(actual_x)):
            raise VerificationError(
                VerificationCode.FABRICATED_OR_MISMATCHED_CHART,
                f"Chart x-axis numeric type mismatch at {context}.",
            )
        if not math.isclose(
            float(actual_x),
            float(expected_x),
            rel_tol=tolerance.rel_tol,
            abs_tol=tolerance.abs_tol,
        ):
            raise VerificationError(
                VerificationCode.FABRICATED_OR_MISMATCHED_CHART,
                f"Chart x-axis numeric value mismatch at {context}.",
            )
    else:
        if type(actual_x) is not str or actual_x != expected_x:
            raise VerificationError(
                VerificationCode.FABRICATED_OR_MISMATCHED_CHART,
                f"Chart x-axis label/date mismatch at {context}.",
            )
