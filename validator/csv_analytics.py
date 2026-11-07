"""Deterministic, validated pandas CSV analytics engine.

Security and architectural invariants:
- Uses only deterministic, validated pandas operations on UTF-8 CSV inputs that
  have passed strict structural profiling (`profile_csv_fixture`).
- Never executes AI-generated Python code, `eval`, `exec`, `compile`, or dynamic imports.
- Enforces strict file size (`MAX_CSV_UPLOAD_BYTES`), `.csv` filename validation,
  UTF-8 encoding, header/row/column bounds, and formula-injection neutralization.
"""

from enum import StrEnum
import hashlib
import io
import math
from typing import Literal
import unicodedata

import pandas as pd
from pydantic import BaseModel, ConfigDict, Field

from ingestion.contracts import (
    DatasetMetadata,
    DatasetProfile,
    IngestionCode,
    IngestionError,
    IngestionRequest,
)
from parser_worker.csv_parser import profile_csv_fixture


MAX_CSV_UPLOAD_BYTES = 2 * 1024 * 1024  # 2 MiB bounded upload payload
MAX_CSV_PREVIEW_ROWS = 5
MAX_CSV_CHART_POINTS = 25
MAX_PREVIEW_CELL_CHARS = 120
MAX_CHART_LABEL_CHARS = 80

_FORMULA_TRIGGER_PREFIXES = (
    "=",
    "+",
    "-",
    "@",
    "|",
    "\t",
    "\r",
    "\n",
    "\uff1d",
    "\uff0b",
    "\uff0d",
    "\uff20",
    "\uff5c",
)


class CsvAnalyticsCode(StrEnum):
    EMPTY_CSV_UPLOAD = "EMPTY_CSV_UPLOAD"
    CSV_PAYLOAD_TOO_LARGE = "CSV_PAYLOAD_TOO_LARGE"
    INVALID_CSV_FILENAME = "INVALID_CSV_FILENAME"
    INVALID_UTF8_ENCODING = "INVALID_UTF8_ENCODING"
    MALFORMED_CSV_CONTENT = "MALFORMED_CSV_CONTENT"
    AMBIGUOUS_CSV_DELIMITER = "AMBIGUOUS_CSV_DELIMITER"
    CSV_SCHEMA_LIMIT_EXCEEDED = "CSV_SCHEMA_LIMIT_EXCEEDED"


class CsvAnalyticsError(Exception):
    """Typed validation or parsing failure during deterministic CSV analytics."""

    def __init__(self, code: CsvAnalyticsCode, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class StrictCsvAnalyticsContract(BaseModel):
    model_config = ConfigDict(
        strict=True,
        frozen=True,
        extra="forbid",
        hide_input_in_errors=True,
    )


class UploadedCsvColumnInfo(StrictCsvAnalyticsContract):
    """Per-column schema, pandas dtype, and missing-value summary."""

    column_id: str = Field(pattern=r"^col_[0-9]{3}$")
    name: str = Field(min_length=1, max_length=128)
    inferred_type: Literal[
        "empty", "text", "integer", "number", "boolean", "date", "mixed"
    ]
    pandas_dtype: str = Field(min_length=1, max_length=64)
    missing_count: int = Field(ge=0)
    present_count: int = Field(ge=0)
    completeness_pct: float = Field(ge=0.0, le=100.0)


class UploadedCsvNumericSummary(StrictCsvAnalyticsContract):
    """Deterministic pandas numerical summary for a numeric column."""

    column_id: str = Field(pattern=r"^col_[0-9]{3}$")
    column_name: str = Field(min_length=1, max_length=128)
    pandas_dtype: str = Field(min_length=1, max_length=64)
    non_null_count: int = Field(ge=0)
    null_count: int = Field(ge=0)
    total_sum: float
    mean_value: float
    median_value: float
    std_value: float = Field(ge=0.0)
    min_value: float
    max_value: float


class UploadedCsvChartPoint(StrictCsvAnalyticsContract):
    """Single coordinate point in the deterministic uploaded CSV chart."""

    x: str | int | float | bool
    y: float


class UploadedCsvChartSpec(StrictCsvAnalyticsContract):
    """Deterministic chart specification computed from the uploaded CSV via pandas."""

    chart_kind: Literal["BAR", "LINE"]
    chart_title: str = Field(min_length=1, max_length=160)
    x_label: str = Field(min_length=1, max_length=128)
    y_label: str = Field(min_length=1, max_length=128)
    aggregation: Literal["sum", "value", "count"]
    series: tuple[UploadedCsvChartPoint, ...]


class ValidatedCsvAnalyticsBundle(StrictCsvAnalyticsContract):
    """Complete deterministic pandas analytics bundle for a validated CSV upload."""

    filename: str = Field(min_length=5, max_length=128)
    byte_count: int = Field(ge=1, le=MAX_CSV_UPLOAD_BYTES)
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    delimiter: Literal[",", ";", "\t"]
    row_count: int = Field(ge=1)
    column_count: int = Field(ge=1, le=100)
    nonempty_cells: int = Field(ge=1)
    total_missing_cells: int = Field(ge=0)
    dataset_completeness_pct: float = Field(ge=0.0, le=100.0)
    profile: DatasetProfile
    columns: tuple[UploadedCsvColumnInfo, ...]
    preview_headers: tuple[str, ...]
    preview_rows: tuple[tuple[str, ...], ...]
    numeric_summaries: tuple[UploadedCsvNumericSummary, ...]
    chart: UploadedCsvChartSpec
    warnings: tuple[str, ...] = ()


def _sanitize_control_chars(text: str) -> str:
    return "".join(
        " " if unicodedata.category(ch) in {"Cc", "Cf", "Zl", "Zp"} else ch
        for ch in text
    )


def neutralize_csv_cell(value: str | int | float | bool | None) -> str:
    """Format a cell for safe display while neutralizing spreadsheet formula prefixes."""
    if value is None:
        return ""
    if type(value) is bool:
        return "TRUE" if value else "FALSE"
    if type(value) in (int, float):
        return str(value)
    raw = str(value)
    text = _sanitize_control_chars(raw)
    stripped = text.lstrip()
    if raw[:1] != text[:1] or stripped.startswith(_FORMULA_TRIGGER_PREFIXES):
        return f"'{text}"
    return text


def validate_csv_filename(filename: str) -> str:
    """Validate that the uploaded file name is a safe `.csv` basename."""
    if type(filename) is not str:
        raise CsvAnalyticsError(
            CsvAnalyticsCode.INVALID_CSV_FILENAME,
            "Filename must be a valid .csv file name.",
        )
    cleaned = filename.strip()
    if not (5 <= len(cleaned) <= 128):
        raise CsvAnalyticsError(
            CsvAnalyticsCode.INVALID_CSV_FILENAME,
            "Filename must be between 5 and 128 characters and end with .csv.",
        )
    if any(
        unicodedata.category(ch) in {"Cc", "Cf", "Zl", "Zp"} for ch in cleaned
    ):
        raise CsvAnalyticsError(
            CsvAnalyticsCode.INVALID_CSV_FILENAME,
            "Filename contains disallowed control characters.",
        )
    if (
        "/" in cleaned
        or "\\" in cleaned
        or ".." in cleaned
        or ":" in cleaned
        or "\x00" in cleaned
    ):
        raise CsvAnalyticsError(
            CsvAnalyticsCode.INVALID_CSV_FILENAME,
            "Filename must not contain path separators or traversal sequences.",
        )
    if not cleaned.lower().endswith(".csv"):
        raise CsvAnalyticsError(
            CsvAnalyticsCode.INVALID_CSV_FILENAME,
            "Only .csv files are supported for CSV analytics.",
        )
    stem = cleaned[:-4].strip()
    if not stem:
        raise CsvAnalyticsError(
            CsvAnalyticsCode.INVALID_CSV_FILENAME,
            "Filename must include a non-empty name before .csv.",
        )
    return cleaned


def _map_ingestion_error(error: IngestionError) -> CsvAnalyticsError:
    mapping: dict[IngestionCode, tuple[CsvAnalyticsCode, str]] = {
        IngestionCode.EMPTY_SOURCE: (
            CsvAnalyticsCode.EMPTY_CSV_UPLOAD,
            "Uploaded CSV file is empty or contains no data rows.",
        ),
        IngestionCode.SOURCE_TOO_LARGE: (
            CsvAnalyticsCode.CSV_PAYLOAD_TOO_LARGE,
            f"Uploaded CSV file exceeds maximum size ({MAX_CSV_UPLOAD_BYTES} bytes).",
        ),
        IngestionCode.INVALID_ENCODING: (
            CsvAnalyticsCode.INVALID_UTF8_ENCODING,
            "Uploaded CSV file must be valid UTF-8 text.",
        ),
        IngestionCode.AMBIGUOUS_DELIMITER: (
            CsvAnalyticsCode.AMBIGUOUS_CSV_DELIMITER,
            "CSV delimiter is ambiguous; specify comma, semicolon, or tab.",
        ),
        IngestionCode.RECORD_LIMIT: (
            CsvAnalyticsCode.CSV_SCHEMA_LIMIT_EXCEEDED,
            "Uploaded CSV exceeds record length limits.",
        ),
        IngestionCode.CELL_LIMIT: (
            CsvAnalyticsCode.CSV_SCHEMA_LIMIT_EXCEEDED,
            "Uploaded CSV exceeds cell length limits.",
        ),
        IngestionCode.ROW_LIMIT: (
            CsvAnalyticsCode.CSV_SCHEMA_LIMIT_EXCEEDED,
            "Uploaded CSV exceeds maximum row count.",
        ),
        IngestionCode.COLUMN_LIMIT: (
            CsvAnalyticsCode.CSV_SCHEMA_LIMIT_EXCEEDED,
            "Uploaded CSV exceeds maximum column count.",
        ),
        IngestionCode.NONEMPTY_LIMIT: (
            CsvAnalyticsCode.CSV_SCHEMA_LIMIT_EXCEEDED,
            "Uploaded CSV exceeds maximum cell count.",
        ),
        IngestionCode.INVALID_HEADER: (
            CsvAnalyticsCode.MALFORMED_CSV_CONTENT,
            "Uploaded CSV has invalid or empty column headers.",
        ),
        IngestionCode.MALFORMED_CSV: (
            CsvAnalyticsCode.MALFORMED_CSV_CONTENT,
            "Uploaded CSV file is malformed, has inconsistent columns, or invalid headers.",
        ),
        IngestionCode.UNSUPPORTED_CONTENT: (
            CsvAnalyticsCode.MALFORMED_CSV_CONTENT,
            "Uploaded file format is not a valid CSV.",
        ),
    }
    code, msg = mapping.get(
        error.code,
        (
            CsvAnalyticsCode.MALFORMED_CSV_CONTENT,
            "Uploaded CSV file failed validation.",
        ),
    )
    return CsvAnalyticsError(code, msg)


def compute_validated_csv_analytics(
    *,
    filename: str,
    raw_bytes: bytes,
    delimiter: str | None = None,
) -> ValidatedCsvAnalyticsBundle:
    """Validate raw CSV bytes and compute deterministic analytics via pandas."""
    clean_filename = validate_csv_filename(filename)

    if delimiter is not None and delimiter not in (",", ";", "\t"):
        raise CsvAnalyticsError(
            CsvAnalyticsCode.MALFORMED_CSV_CONTENT,
            "Delimiter must be comma (','), semicolon (';'), or tab ('\\t').",
        )

    if type(raw_bytes) is not bytes:
        raise CsvAnalyticsError(
            CsvAnalyticsCode.MALFORMED_CSV_CONTENT,
            "CSV payload must be raw bytes.",
        )

    byte_count = len(raw_bytes)
    if byte_count == 0 or not raw_bytes.strip():
        raise CsvAnalyticsError(
            CsvAnalyticsCode.EMPTY_CSV_UPLOAD,
            "Uploaded CSV file is empty.",
        )
    if byte_count > MAX_CSV_UPLOAD_BYTES:
        raise CsvAnalyticsError(
            CsvAnalyticsCode.CSV_PAYLOAD_TOO_LARGE,
            f"Uploaded CSV file exceeds maximum size ({MAX_CSV_UPLOAD_BYTES} bytes).",
        )
    if b"\x00" in raw_bytes:
        raise CsvAnalyticsError(
            CsvAnalyticsCode.INVALID_UTF8_ENCODING,
            "Uploaded CSV file contains binary NUL bytes.",
        )

    try:
        decoded_text = raw_bytes.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError:
        raise CsvAnalyticsError(
            CsvAnalyticsCode.INVALID_UTF8_ENCODING,
            "Uploaded CSV file must be valid UTF-8 text.",
        ) from None

    source_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    try:
        metadata = DatasetMetadata(
            filename=clean_filename,
            file_type="csv",
            byte_count=byte_count,
            sha256=source_sha256,
            delimiter=delimiter,
        )
        ingestion_req = IngestionRequest(
            dataset_id="0" * 32,
            session_id="0" * 32,
            object_id="0" * 32,
            metadata=metadata,
        )
        parsed = profile_csv_fixture(raw_bytes, ingestion_req)
    except IngestionError as exc:
        raise _map_ingestion_error(exc) from None
    except Exception:
        raise CsvAnalyticsError(
            CsvAnalyticsCode.MALFORMED_CSV_CONTENT,
            "Uploaded CSV metadata or content failed validation.",
        ) from None

    profile = parsed.profile
    if profile.row_count < 1:
        raise CsvAnalyticsError(
            CsvAnalyticsCode.EMPTY_CSV_UPLOAD,
            "Uploaded CSV file contains no data rows.",
        )
    if (
        "DUPLICATE_COLUMNS" in profile.warnings
        or len({col.name for col in profile.columns}) != len(profile.columns)
    ):
        raise CsvAnalyticsError(
            CsvAnalyticsCode.MALFORMED_CSV_CONTENT,
            "Uploaded CSV contains duplicate column headers.",
        )
    effective_delimiter: Literal[",", ";", "\t"] = (
        profile.delimiter if profile.delimiter in (",", ";", "\t") else ","
    )

    # Parse with pandas using deterministic string mode after structural verification
    try:
        df_raw = pd.read_csv(
            io.StringIO(decoded_text),
            sep=effective_delimiter,
            quotechar='"',
            doublequote=True,
            dtype=str,
            keep_default_na=False,
            na_filter=False,
            skip_blank_lines=False,
            engine="python",
        )
    except Exception:
        raise CsvAnalyticsError(
            CsvAnalyticsCode.MALFORMED_CSV_CONTENT,
            "pandas failed to parse the uploaded CSV file.",
        ) from None

    if (
        int(df_raw.shape[1]) != profile.column_count
        or int(df_raw.shape[0]) != profile.row_count
        or int(df_raw.shape[0]) < 1
    ):
        raise CsvAnalyticsError(
            CsvAnalyticsCode.MALFORMED_CSV_CONTENT,
            "Uploaded CSV dimensions did not match validated profile.",
        )

    canonical_headers = [col.name for col in profile.columns]
    df_raw.columns = canonical_headers
    df_clean = df_raw.replace("", pd.NA)

    row_count = int(df_clean.shape[0])
    column_count = int(df_clean.shape[1])
    missing_series = df_clean.isna().sum()

    columns_info: list[UploadedCsvColumnInfo] = []
    numeric_summaries: list[UploadedCsvNumericSummary] = []

    for col_prof in profile.columns:
        col_s = df_clean[col_prof.name]
        missing_cnt = int(missing_series[col_prof.name])
        present_cnt = max(0, row_count - missing_cnt)
        completeness_pct = (
            round((present_cnt / row_count) * 100.0, 2) if row_count > 0 else 100.0
        )

        if col_prof.inferred_type == "integer":
            try:
                num_non_null = pd.to_numeric(col_s.dropna(), errors="raise")
                typed_int = pd.to_numeric(col_s, errors="coerce").astype(
                    "Int64" if missing_cnt > 0 else "int64"
                )
            except Exception:
                raise CsvAnalyticsError(
                    CsvAnalyticsCode.MALFORMED_CSV_CONTENT,
                    f"Column {col_prof.name} failed integer validation.",
                ) from None
            pandas_dtype = str(typed_int.dtype)
            float_s = num_non_null.astype("float64")
        elif col_prof.inferred_type == "number":
            try:
                float_s = pd.to_numeric(col_s.dropna(), errors="raise").astype(
                    "float64"
                )
            except Exception:
                raise CsvAnalyticsError(
                    CsvAnalyticsCode.MALFORMED_CSV_CONTENT,
                    f"Column {col_prof.name} failed numeric validation.",
                ) from None
            if not bool(float_s.map(math.isfinite).all()):
                raise CsvAnalyticsError(
                    CsvAnalyticsCode.MALFORMED_CSV_CONTENT,
                    f"Column {col_prof.name} contains non-finite numeric values.",
                )
            pandas_dtype = "float64"
        elif col_prof.inferred_type == "boolean":
            pandas_dtype = "boolean"
            float_s = None
        elif col_prof.inferred_type == "date":
            pandas_dtype = "date[ISO-8601]"
            float_s = None
        elif col_prof.inferred_type == "empty":
            pandas_dtype = "object (empty)"
            float_s = None
        else:
            non_null_str = col_s.dropna().astype(str)
            if len(non_null_str) > 0 and bool(
                non_null_str.str.match(r"^\d{4}-\d{2}-\d{2}$").all()
            ):
                pandas_dtype = "date[ISO-8601]"
            else:
                pandas_dtype = str(col_s.astype("string").dtype)
            float_s = None

        columns_info.append(
            UploadedCsvColumnInfo(
                column_id=col_prof.column_id,
                name=canonical_label(col_prof.name),
                inferred_type=col_prof.inferred_type,
                pandas_dtype=pandas_dtype,
                missing_count=missing_cnt,
                present_count=present_cnt,
                completeness_pct=completeness_pct,
            )
        )

        if float_s is not None and len(float_s) > 0:
            non_null_cnt = int(float_s.count())
            null_cnt = max(0, row_count - non_null_cnt)
            total_sum = round(float(float_s.sum()), 6)
            mean_val = round(float(float_s.mean()), 6)
            median_val = round(float(float_s.median()), 6)
            std_val = round(max(0.0, float(float_s.std(ddof=0))), 6)
            min_val = round(float(float_s.min()), 6)
            max_val = round(float(float_s.max()), 6)
            numeric_summaries.append(
                UploadedCsvNumericSummary(
                    column_id=col_prof.column_id,
                    column_name=canonical_label(col_prof.name),
                    pandas_dtype=pandas_dtype,
                    non_null_count=non_null_cnt,
                    null_count=null_cnt,
                    total_sum=total_sum,
                    mean_value=mean_val,
                    median_value=median_val,
                    std_value=std_val,
                    min_value=min_val,
                    max_value=max_val,
                )
            )

    # First few rows (preview_rows) using pandas .head()
    head_df = df_raw.head(MAX_CSV_PREVIEW_ROWS)
    preview_rows = tuple(
        tuple(
            neutralize_csv_cell(str(cell))[:MAX_PREVIEW_CELL_CHARS]
            for cell in row
        )
        for row in head_df.itertuples(index=False, name=None)
    )
    preview_headers = tuple(canonical_label(name) for name in canonical_headers)

    chart = _build_deterministic_chart(df_clean, tuple(columns_info))

    total_cells = row_count * column_count
    total_missing_cells = int(sum(col.missing_count for col in columns_info))
    dataset_completeness_pct = (
        round(((total_cells - total_missing_cells) / total_cells) * 100.0, 2)
        if total_cells > 0
        else 100.0
    )

    return ValidatedCsvAnalyticsBundle(
        filename=clean_filename,
        byte_count=byte_count,
        source_sha256=source_sha256,
        delimiter=effective_delimiter,
        row_count=row_count,
        column_count=column_count,
        nonempty_cells=profile.nonempty_cells,
        total_missing_cells=total_missing_cells,
        dataset_completeness_pct=dataset_completeness_pct,
        profile=profile,
        columns=tuple(columns_info),
        preview_headers=preview_headers,
        preview_rows=preview_rows,
        numeric_summaries=tuple(numeric_summaries),
        chart=chart,
        warnings=profile.warnings,
    )


def canonical_label(name: str) -> str:
    return _sanitize_control_chars(name).strip()[:128] or "column"


def _build_deterministic_chart(
    df_clean: pd.DataFrame,
    columns_info: tuple[UploadedCsvColumnInfo, ...],
) -> UploadedCsvChartSpec:
    """Build one deterministic chart from the uploaded DataFrame using pandas."""
    numeric_cols = [
        c for c in columns_info if c.inferred_type in ("number", "integer")
    ]
    date_cols = [
        c
        for c in columns_info
        if c.inferred_type == "date" or c.pandas_dtype == "date[ISO-8601]"
    ]
    category_cols = [
        c
        for c in columns_info
        if c.inferred_type in ("text", "boolean", "mixed")
        and c.pandas_dtype != "date[ISO-8601]"
    ]

    if numeric_cols and (date_cols or category_cols):
        metric_col = numeric_cols[0]
        if date_cols:
            group_col = date_cols[0]
            chart_kind: Literal["BAR", "LINE"] = "LINE"
        else:
            group_col = category_cols[0]
            chart_kind = "BAR"

        work_df = pd.DataFrame(
            {
                "x": df_clean[group_col.name].fillna("(Missing)").astype(str),
                "y": pd.to_numeric(df_clean[metric_col.name], errors="coerce"),
            }
        ).dropna(subset=["y"])

        if len(work_df) > 0:
            grouped_df = work_df.groupby("x", sort=False, as_index=False)["y"].sum()
            if chart_kind == "LINE":
                grouped_df = grouped_df.sort_values(
                    by="x", ascending=True, kind="mergesort"
                ).head(MAX_CSV_CHART_POINTS)
            else:
                grouped_df = grouped_df.sort_values(
                    by=["y", "x"], ascending=[False, True], kind="mergesort"
                ).head(MAX_CSV_CHART_POINTS)

            pts = tuple(
                UploadedCsvChartPoint(
                    x=neutralize_csv_cell(str(row["x"]))[:MAX_CHART_LABEL_CHARS],
                    y=round(float(row["y"]), 6),
                )
                for _, row in grouped_df.iterrows()
            )
            return UploadedCsvChartSpec(
                chart_kind=chart_kind,
                chart_title=f"Total {canonical_label(metric_col.name)} by {canonical_label(group_col.name)}",
                x_label=canonical_label(group_col.name),
                y_label=canonical_label(metric_col.name),
                aggregation="sum",
                series=pts,
            )

    if numeric_cols:
        metric_col = numeric_cols[0]
        num_s = (
            pd.to_numeric(df_clean[metric_col.name], errors="coerce")
            .dropna()
            .head(MAX_CSV_CHART_POINTS)
        )
        pts = tuple(
            UploadedCsvChartPoint(
                x=f"Row {idx + 1}",
                y=round(float(val), 6),
            )
            for idx, val in enumerate(num_s.tolist())
        )
        return UploadedCsvChartSpec(
            chart_kind="BAR",
            chart_title=f"{canonical_label(metric_col.name)} by Row (First {len(pts)} Non-Null Rows)",
            x_label="Row",
            y_label=canonical_label(metric_col.name),
            aggregation="value",
            series=pts,
        )

    # Fallback when dataset has only non-numeric columns: pandas value_counts() bar chart
    target_col = columns_info[0]
    vc = (
        df_clean[target_col.name]
        .fillna("(Missing)")
        .astype(str)
        .value_counts(dropna=False)
        .head(MAX_CSV_CHART_POINTS)
    )
    pts = tuple(
        UploadedCsvChartPoint(
            x=neutralize_csv_cell(str(k))[:MAX_CHART_LABEL_CHARS],
            y=float(v),
        )
        for k, v in vc.items()
    )
    return UploadedCsvChartSpec(
        chart_kind="BAR",
        chart_title=f"Row Count by {canonical_label(target_col.name)}",
        x_label=canonical_label(target_col.name),
        y_label="row_count",
        aggregation="count",
        series=pts,
    )
