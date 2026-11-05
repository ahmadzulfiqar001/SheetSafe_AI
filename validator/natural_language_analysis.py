"""Deterministic natural language analysis planner and safe dataframe executor.

Translates simple user natural-language questions about uploaded datasets into
strictly validated declarative analysis intents (SUM, AVG, COUNT, MIN, MAX,
GROUP_BY, SORT, TOP_N), and executes approved deterministic dataframe operations
on the real dataset. Never executes model-generated Python, SQL, shell commands,
or arbitrary eval expressions.
"""

from dataclasses import dataclass
import hashlib
import io
import math
import re
from typing import Annotated, Any, Literal

import pandas as pd
from pydantic import BaseModel, ConfigDict, Field

from backend.inference import (
    AIAnalysisPlan,
    AIClarificationNeeded,
    AIPlanningEnvelope,
    AISchemaColumn,
    ExpectedResultType,
    InferenceCode,
    InferenceError,
    OperationKind,
    ProposedOperation,
    RequiredColumnRef,
    ValidatedDatasetSchema,
    validate_planning_envelope,
    validate_user_question,
)


class StrictNLAModel(BaseModel):
    """Immutable model with strict assignment and frozen attributes."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        validate_default=True,
        validate_assignment=True,
    )


class ChartPointPreview(StrictNLAModel):
    """Verified interactive chart coordinate point."""

    x: str | int | float | bool
    y: float


class RealDataAnalysisResult(StrictNLAModel):
    """Ground-truth analysis result computed by approved deterministic dataframe operations."""

    answer_text: str = Field(min_length=3, max_length=500)
    scalar_value: float | int | None = None
    result_type: str = Field(min_length=1, max_length=64)
    columns: tuple[str, ...] = ()
    column_headers: dict[str, str] = Field(default_factory=dict)
    rows: tuple[dict[str, Any], ...] = ()
    row_count: int = Field(default=0, ge=0)
    chart_kind: Literal["BAR", "LINE", "NONE"] = "NONE"
    chart_x_label: str | None = None
    chart_y_label: str | None = None
    chart_series: tuple[ChartPointPreview, ...] = ()
    execution_mode: Literal["DETERMINISTIC_DATAFRAME_HOST"] = "DETERMINISTIC_DATAFRAME_HOST"
    ai_code_executed: Literal[False] = False


_STOP_WORDS: frozenset[str] = frozenset({
    "a", "an", "the", "in", "on", "at", "of", "for", "to", "from", "with",
    "is", "are", "was", "were", "be", "been", "being",
    "what", "which", "who", "whom", "whose", "where", "when", "why", "how",
    "show", "give", "tell", "display", "find", "list", "get", "calculate",
    "compute", "me", "us", "please", "dataset", "table", "data", "row", "rows",
    "column", "columns", "csv", "file", "all", "our", "their", "has", "have",
    "had", "does", "do", "did", "can", "could", "would", "should", "it",
})

_AGGREGATION_TERMS: dict[str, str] = {
    "average": "mean",
    "avg": "mean",
    "mean": "mean",
    "total": "sum",
    "sum": "sum",
    "count": "count",
    "number": "count",
    "highest": "max",
    "maximum": "max",
    "max": "max",
    "largest": "max",
    "most": "max",
    "peak": "max",
    "lowest": "min",
    "minimum": "min",
    "min": "min",
    "smallest": "min",
    "least": "min",
}


def _match_column(
    word_or_phrase: str,
    columns: tuple[AISchemaColumn, ...],
) -> AISchemaColumn | None:
    """Match a token or phrase against dataset column names or components."""
    target = word_or_phrase.strip().lower().replace(" ", "_")
    if not target:
        return None

    # 1. Exact match on full column name
    for col in columns:
        if col.name.lower() == target:
            return col

    # 2. Check if column name contains target token or vice versa
    for col in columns:
        col_lower = col.name.lower()
        if target in col_lower or col_lower in target:
            return col

    # 3. Component match on underscore-separated parts
    for col in columns:
        parts = col.name.lower().split("_")
        if target in parts:
            return col

    return None


def parse_natural_language_intent(
    question_text: str,
    schema: ValidatedDatasetSchema,
) -> AIPlanningEnvelope:
    """Deterministically parse a user's natural language question into a safe analysis intent.

    Supports SUM, AVG/mean, COUNT, MIN, MAX, GROUP_BY, SORT, and TOP_N operations.
    Validates all referenced columns strictly against the dataset schema.
    """
    # 1. Validate question bounds, security, and prompt-injection checks
    validated_q = validate_user_question(question_text)
    q_lower = validated_q.question.lower()
    words = re.findall(r"\b[a-zA-Z0-9_]+\b", q_lower)

    # 2. Detect ambiguous questions requiring clarification
    if any(
        token in q_lower
        for token in ("ambiguous", "unclear", "which metric", "best performance", "compare performance")
    ):
        candidate_ids = [
            c.column_id for c in schema.columns if c.inferred_type in {"number", "integer"}
        ][:2]
        return AIPlanningEnvelope(
            version=1,
            status="CLARIFICATION_REQUIRED",
            clarification=AIClarificationNeeded(
                version=1,
                reason_code="AMBIGUOUS_METRIC",
                clarification_prompt=(
                    "Your question asks for an ambiguous or unspecified comparison. "
                    "Please specify which metric and grouping column you wish to analyze."
                ),
                candidate_columns=tuple(candidate_ids),
            ),
        )

    numeric_cols = [c for c in schema.columns if c.inferred_type in {"number", "integer"}]
    cat_cols = [c for c in schema.columns if c.inferred_type in {"text", "date", "boolean"}]

    # 3. Detect grouping column indicated by keywords like "by <col>", "per <col>", "which <col>"
    group_col: AISchemaColumn | None = None
    by_match = re.search(r"\b(?:by|per|for\s+each|across|which)\s+([a-zA-Z0-9_]+)\b", q_lower)
    if by_match:
        cand_word = by_match.group(1).lower()
        if cand_word not in _STOP_WORDS:
            matched = _match_column(cand_word, schema.columns)
            if matched is not None:
                group_col = matched
            else:
                # User explicitly requested grouping on an unknown column
                return AIPlanningEnvelope(
                    version=1,
                    status="CLARIFICATION_REQUIRED",
                    clarification=AIClarificationNeeded(
                        version=1,
                        reason_code="MISSING_TARGET_COLUMN",
                        clarification_prompt=(
                            f"Column '{cand_word}' was not found in dataset schema. "
                            f"Available grouping columns: {', '.join(c.name for c in cat_cols) or 'None'}."
                        ),
                        candidate_columns=tuple(c.column_id for c in cat_cols),
                    ),
                )

    # If no grouping column found via "by/which", search categorical columns mentioned in question
    if group_col is None:
        for c in cat_cols:
            if c.name.lower() in q_lower:
                group_col = c
                break

    # 4. Detect metric column mentioned in question
    metric_col: AISchemaColumn | None = None
    for c in numeric_cols:
        if c.name.lower() in q_lower:
            metric_col = c
            break

    # If no exact numeric column match, check component words
    if metric_col is None:
        for c in numeric_cols:
            for part in c.name.lower().split("_"):
                if len(part) >= 3 and part in words:
                    metric_col = c
                    break
            if metric_col is not None:
                break

    # Check if user explicitly asked for a known metric concept that doesn't exist in schema
    # (e.g. "profit", "margin", "cost", "score", "sales", "revenue")
    if metric_col is None:
        common_metrics = ("profit", "margin", "cost", "revenue", "sales", "units", "quantity", "price", "amount")
        for cm in common_metrics:
            if cm in words:
                matched_cm = _match_column(cm, schema.columns)
                if matched_cm is not None and matched_cm.inferred_type in {"number", "integer"}:
                    metric_col = matched_cm
                    break
                else:
                    return AIPlanningEnvelope(
                        version=1,
                        status="CLARIFICATION_REQUIRED",
                        clarification=AIClarificationNeeded(
                            version=1,
                            reason_code="MISSING_TARGET_COLUMN",
                            clarification_prompt=(
                                f"Requested metric column '{cm}' was not found in dataset schema. "
                                f"Available numeric columns: {', '.join(c.name for c in numeric_cols)}."
                            ),
                            candidate_columns=tuple(c.column_id for c in numeric_cols),
                        ),
                    )

    # If still no metric column matched, default to the primary numeric column if available
    if metric_col is None and numeric_cols:
        metric_col = numeric_cols[0]

    if metric_col is None:
        return AIPlanningEnvelope(
            version=1,
            status="CLARIFICATION_REQUIRED",
            clarification=AIClarificationNeeded(
                version=1,
                reason_code="MISSING_TARGET_COLUMN",
                clarification_prompt="No numeric columns found in this dataset for numerical analysis.",
                candidate_columns=tuple(c.column_id for c in schema.columns),
            ),
        )

    # 5. Detect aggregation and extremum
    agg: Literal["count", "sum", "mean", "median", "min", "max", "std"] = "sum"
    if any(w in words for w in ("average", "avg", "mean")):
        agg = "mean"
    elif any(w in words for w in ("count", "number", "how many")):
        agg = "count"
    elif any(w in words for w in ("minimum", "min", "lowest", "least", "smallest", "worst")):
        agg = "min"
    elif any(w in words for w in ("maximum", "max", "highest", "most", "largest", "peak", "best")):
        agg = "max"
    elif any(w in words for w in ("total", "sum")):
        agg = "sum"

    is_extremum = any(
        w in words
        for w in (
            "highest", "lowest", "top", "best", "worst", "maximum", "max",
            "minimum", "min", "most", "least", "largest", "smallest",
        )
    )
    is_desc = not any(w in words for w in ("lowest", "least", "smallest", "minimum", "min", "worst"))

    # Check for "top N" limit (e.g. "top 3", "top 5")
    top_n_match = re.search(r"\btop\s+(\d+)\b", q_lower)
    limit_rows = int(top_n_match.group(1)) if top_n_match else (1 if is_extremum else None)

    # 6. Construct validated operations
    operations: list[ProposedOperation] = []
    required_cols: list[RequiredColumnRef] = []
    step = 1

    if group_col is not None:
        # Grouped analysis
        required_cols = [
            RequiredColumnRef(column_id=group_col.column_id, name=group_col.name, expected_type=group_col.inferred_type),
            RequiredColumnRef(column_id=metric_col.column_id, name=metric_col.name, expected_type=metric_col.inferred_type),
        ]
        # For grouped extremum, we aggregate sum or mean first, then sort and take top N
        group_agg = "sum" if agg in {"max", "min", "sum"} else agg
        operations.append(
            ProposedOperation(
                step_number=step,
                operation="GROUP_AGGREGATE",
                group_by_columns=(group_col.column_id,),
                target_columns=(metric_col.column_id,),
                aggregation=group_agg,
                rationale=f"Aggregate {group_agg} of {metric_col.name} grouped by {group_col.name}.",
            )
        )
        step += 1

        sort_dir = "desc" if is_desc else "asc"
        operations.append(
            ProposedOperation(
                step_number=step,
                operation="SORT_VALUES",
                target_columns=(metric_col.column_id,),
                sort_direction=sort_dir,
                rationale=f"Sort total {metric_col.name} {sort_dir}ending.",
            )
        )
        step += 1

        if limit_rows is not None:
            operations.append(
                ProposedOperation(
                    step_number=step,
                    operation="TOP_N",
                    target_columns=(metric_col.column_id,),
                    sort_direction=sort_dir,
                    limit_rows=limit_rows,
                    rationale=f"Select top {limit_rows} {group_col.name} records by {metric_col.name}.",
                )
            )
            step += 1
            result_type: ExpectedResultType = "RANKED_TABLE"
            intent_summary = f"Find top {limit_rows} {group_col.name} by {metric_col.name}."
        else:
            result_type = "BAR_CHART" if group_col.inferred_type != "date" else "LINE_CHART"
            intent_summary = f"Calculate {group_agg} of {metric_col.name} grouped by {group_col.name}."

    else:
        # Scalar summary across the dataset
        required_cols = [
            RequiredColumnRef(column_id=metric_col.column_id, name=metric_col.name, expected_type=metric_col.inferred_type)
        ]
        operations.append(
            ProposedOperation(
                step_number=step,
                operation="SUMMARY_STATS",
                target_columns=(metric_col.column_id,),
                aggregation=agg,
                rationale=f"Compute {agg} of {metric_col.name} across all rows.",
            )
        )
        result_type = "SCALAR_METRIC"
        intent_summary = f"Compute the {agg} of {metric_col.name}."

    plan = AIAnalysisPlan(
        version=1,
        schema_sha256=schema.schema_sha256,
        intent_summary=intent_summary,
        required_columns=tuple(required_cols),
        operations=tuple(operations),
        expected_result_type=result_type,
    )
    return AIPlanningEnvelope(version=1, status="PLAN_READY", plan=plan)


def execute_deterministic_dataframe_analysis(
    *,
    csv_bytes: bytes,
    delimiter: str,
    plan: AIAnalysisPlan,
    schema: ValidatedDatasetSchema,
) -> RealDataAnalysisResult:
    """Execute approved deterministic dataframe operations on real CSV bytes.

    Uses pandas in safe non-evaluating mode. Never executes arbitrary Python,
    SQL, shell commands, or eval expressions.
    """
    col_by_id = schema.column_map()
    col_name_to_id = {col.name: col.column_id for col in schema.columns}
    col_id_to_name = {col.column_id: col.name for col in schema.columns}

    effective_delimiter = delimiter if delimiter in (",", ";", "\t") else ","

    try:
        df = pd.read_csv(
            io.BytesIO(csv_bytes),
            sep=effective_delimiter,
            quotechar='"',
            doublequote=True,
            dtype=str,
            keep_default_na=False,
            na_filter=False,
            engine="python",
        )
    except Exception as exc:
        raise InferenceError(InferenceCode.INVALID_PLAN_CONTRACT) from exc

    # Map column names in df to column IDs for strict operation binding
    canonical_cols: list[str] = []
    for col_name in df.columns:
        clean_name = str(col_name).strip()
        canonical_cols.append(col_name_to_id.get(clean_name, clean_name))
    df.columns = canonical_cols

    # Cast column types safely based on validated schema
    for col in schema.columns:
        cid = col.column_id
        if cid in df.columns:
            if col.inferred_type in {"integer", "number"}:
                df[cid] = pd.to_numeric(df[cid].replace("", pd.NA), errors="coerce")
            else:
                df[cid] = df[cid].replace("", pd.NA)

    scalar_result: float | int | None = None
    df_work = df.copy()

    for op in plan.operations:
        if op.operation == "SELECT_COLUMNS":
            valid_targets = [c for c in op.target_columns if c in df_work.columns]
            df_work = df_work[valid_targets]

        elif op.operation == "DROP_MISSING":
            valid_targets = [c for c in op.target_columns if c in df_work.columns]
            df_work = df_work.dropna(subset=valid_targets)

        elif op.operation == "GROUP_AGGREGATE":
            g_cols = [c for c in op.group_by_columns if c in df_work.columns]
            t_cols = [c for c in op.target_columns if c in df_work.columns]
            agg_type = op.aggregation or "sum"
            agg_map = {
                "sum": "sum",
                "mean": "mean",
                "count": "count",
                "min": "min",
                "max": "max",
                "median": "median",
                "std": "std",
            }
            func = agg_map.get(agg_type, "sum")
            df_work = df_work.groupby(g_cols, as_index=False)[t_cols].agg(func)

        elif op.operation == "SUMMARY_STATS":
            t_cols = [c for c in op.target_columns if c in df_work.columns]
            agg_type = op.aggregation or "sum"
            summary_dict: dict[str, list[Any]] = {}
            for cid in t_cols:
                s = pd.to_numeric(df_work[cid], errors="coerce").dropna()
                if agg_type == "sum":
                    val = float(s.sum())
                elif agg_type == "mean":
                    val = float(s.mean()) if len(s) > 0 else 0.0
                elif agg_type == "min":
                    val = float(s.min()) if len(s) > 0 else 0.0
                elif agg_type == "max":
                    val = float(s.max()) if len(s) > 0 else 0.0
                elif agg_type == "count":
                    val = int(s.count())
                else:
                    val = float(s.sum())
                summary_dict[cid] = [val]
            df_work = pd.DataFrame(summary_dict)

        elif op.operation == "SORT_VALUES":
            valid_targets = [c for c in op.target_columns if c in df_work.columns]
            ascending = (op.sort_direction == "asc")
            df_work = df_work.sort_values(by=valid_targets, ascending=ascending, na_position="last")

        elif op.operation == "TOP_N":
            limit = min(op.limit_rows or 1, 1000)
            df_work = df_work.head(limit)

    # Format human-readable answer and structured response
    output_headers = {cid: col_id_to_name.get(cid, cid) for cid in df_work.columns}
    user_columns = tuple(output_headers[cid] for cid in df_work.columns)

    formatted_rows: list[dict[str, Any]] = []
    for record in df_work.to_dict(orient="records"):
        clean_row: dict[str, Any] = {}
        for cid, val in record.items():
            col_name = output_headers.get(cid, cid)
            if pd.isna(val) or val is None:
                clean_row[col_name] = None
            elif isinstance(val, float):
                clean_row[col_name] = round(val, 4) if math.isfinite(val) else None
            else:
                clean_row[col_name] = val
        formatted_rows.append(clean_row)

    answer_text = ""
    chart_kind: Literal["BAR", "LINE", "NONE"] = "NONE"
    chart_series: list[ChartPointPreview] = []
    chart_x_label: str | None = None
    chart_y_label: str | None = None

    if plan.expected_result_type == "SCALAR_METRIC" or (len(df_work) == 1 and len(df_work.columns) == 1):
        raw_val = df_work.iloc[0, 0] if len(df_work) > 0 else 0.0
        scalar_result = float(raw_val) if isinstance(raw_val, (int, float)) else 0.0
        target_name = user_columns[0] if user_columns else "value"
        op_agg = plan.operations[0].aggregation or "computed"
        answer_text = f"The {op_agg} {target_name} is {scalar_result:,.2f}."

    elif plan.expected_result_type == "RANKED_TABLE" and len(df_work) == 1 and len(user_columns) >= 2:
        g_name = user_columns[0]
        m_name = user_columns[1]
        g_val = formatted_rows[0].get(g_name, "")
        raw_m = formatted_rows[0].get(m_name, 0.0)
        scalar_result = float(raw_m) if isinstance(raw_m, (int, float)) else 0.0
        answer_text = f"{g_val} has the highest {m_name} ({scalar_result:,.2f})."

    else:
        target_summary = plan.intent_summary or "Analysis complete"
        answer_text = f"{target_summary} computed across {len(df_work)} rows."
        if len(user_columns) >= 2 and len(formatted_rows) > 1:
            x_col = user_columns[0]
            y_col = user_columns[1]
            chart_kind = "LINE" if plan.expected_result_type in {"LINE_CHART", "TIME_SERIES_TABLE"} else "BAR"
            chart_x_label = x_col
            chart_y_label = y_col
            for r in formatted_rows[:100]:
                x_val = r.get(x_col)
                y_val = r.get(y_col)
                if x_val is not None and isinstance(y_val, (int, float)):
                    chart_series.append(ChartPointPreview(x=str(x_val), y=float(y_val)))

    return RealDataAnalysisResult(
        answer_text=answer_text,
        scalar_value=scalar_result,
        result_type=plan.expected_result_type,
        columns=user_columns,
        column_headers=output_headers,
        rows=tuple(formatted_rows),
        row_count=len(formatted_rows),
        chart_kind=chart_kind,
        chart_x_label=chart_x_label,
        chart_y_label=chart_y_label,
        chart_series=tuple(chart_series),
        execution_mode="DETERMINISTIC_DATAFRAME_HOST",
        ai_code_executed=False,
    )

