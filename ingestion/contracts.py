"""Bounded internal contracts, not upload admission or parser trust evidence."""

from enum import StrEnum
import json
from typing import Annotated, Literal, Protocol
import unicodedata

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator


MAX_SOURCE_BYTES = 20 * 1024**2
MAX_PARSED_BYTES = 100 * 1024**2
MAX_ROWS = 100_000  # Data rows, excluding the explicit first-row header.
MAX_COLUMNS = 100
MAX_NONEMPTY_CELLS = 2_000_000  # Conservatively includes header cells.
MAX_SHEETS = 10
MAX_ZIP_ENTRIES = 1000
MAX_COMPRESSION_RATIO = 100
MAX_PROFILE_BYTES = 128 * 1024
MAX_PREVIEW_ROWS = 5
MAX_PREVIEW_CHARS = 160
MAX_PREVIEW_BYTES = 16 * 1024
MAX_HEADER_CHARS = 128
MAX_CELL_CHARS = 32_768
MAX_RECORD_CHARS = 1024**2
PARSER_SECONDS = 20.0  # Cooperative checks only; future external watchdog required.

Identifier = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$", min_length=32, max_length=32)]
Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$", min_length=64, max_length=64)]
WarningCode = Literal["DUPLICATE_COLUMNS", "PREVIEW_TRUNCATED", "SINGLE_COLUMN_CSV",
    "CSV_FORMULA_LIKE_TEXT", "FORMULA_CACHED_VALUES", "FORMULA_VALUES_MISSING", "EXCEL_ERROR_VALUES"]


class IngestionCode(StrEnum):
    INVALID_METADATA = "INVALID_METADATA"
    SOURCE_TOO_LARGE = "SOURCE_TOO_LARGE"
    SOURCE_INTEGRITY = "SOURCE_INTEGRITY"
    EMPTY_SOURCE = "EMPTY_SOURCE"
    INVALID_ENCODING = "INVALID_ENCODING"
    MALFORMED_CSV = "MALFORMED_CSV"
    AMBIGUOUS_DELIMITER = "AMBIGUOUS_DELIMITER"
    INVALID_HEADER = "INVALID_HEADER"
    RECORD_LIMIT = "RECORD_LIMIT"
    CELL_LIMIT = "CELL_LIMIT"
    ROW_LIMIT = "ROW_LIMIT"
    COLUMN_LIMIT = "COLUMN_LIMIT"
    NONEMPTY_LIMIT = "NONEMPTY_LIMIT"
    MALFORMED_XLSX = "MALFORMED_XLSX"
    UNSUPPORTED_CONTENT = "UNSUPPORTED_CONTENT"
    ARCHIVE_LIMIT = "ARCHIVE_LIMIT"
    UNSAFE_ARCHIVE = "UNSAFE_ARCHIVE"
    INVALID_WORKSHEET = "INVALID_WORKSHEET"
    SHEET_LIMIT = "SHEET_LIMIT"
    INVALID_PROFILE = "INVALID_PROFILE"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"
    INTERRUPTED = "INTERRUPTED"
    STORAGE_UNAVAILABLE = "STORAGE_UNAVAILABLE"
    PARSER_UNAVAILABLE = "PARSER_UNAVAILABLE"
    STATE_CONFLICT = "STATE_CONFLICT"


class IngestionError(ValueError):
    """Only a reviewed code; no filename, cell, SQL, path or underlying exception."""

    def __init__(self, code: IngestionCode):
        self.code = code
        super().__init__(f"Dataset ingestion failed: {code.value}.")


class Contract(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid", hide_input_in_errors=True)


def safe_label(value: str) -> bool:
    return bool(value.strip()) and not any(unicodedata.category(c) in {"Cc", "Cf", "Cs"} for c in value)


class DatasetMetadata(Contract):
    """Caller declarations only; never accepts identities, paths or parser flags."""

    filename: str = Field(min_length=1, max_length=128, repr=False)
    file_type: Literal["csv", "xlsx"]
    byte_count: int = Field(ge=1, le=MAX_SOURCE_BYTES)
    sha256: Digest
    worksheet: str | None = Field(default=None, max_length=31, repr=False)
    delimiter: Literal[",", ";", "\t"] | None = None

    @model_validator(mode="after")
    def consistent(self):
        if (not safe_label(self.filename) or self.filename != self.filename.strip()
                or any(c in self.filename for c in "/\\:")
                or not self.filename.lower().endswith("." + self.file_type)
                or len(self.filename) <= len(self.file_type) + 1):
            raise ValueError("Invalid file declaration")
        if self.file_type == "csv":
            if self.worksheet is not None:
                raise ValueError("CSV has no worksheet")
        elif (self.worksheet is None or not safe_label(self.worksheet)
                or any(c in self.worksheet for c in "[]:*?/\\") or self.delimiter is not None):
            raise ValueError("Explicit worksheet required")
        return self


def metadata_from_mapping(raw: object) -> DatasetMetadata:
    try:
        if type(raw) is not dict:
            raise ValueError()
        return DatasetMetadata.model_validate(raw)
    except (ValueError, TypeError):
        raise IngestionError(IngestionCode.INVALID_METADATA) from None


class IngestionRequest(Contract):
    """Constructed by the control plane from owned, sealed storage metadata.

    Shape/opaque IDs alone never authenticate ownership. No credential or path
    is delivered to the future parser. The current adapter is always disabled.
    """

    dataset_id: Identifier
    session_id: Identifier
    object_id: Identifier
    version: Literal[1] = 1
    state: Literal["PENDING"] = "PENDING"
    metadata: DatasetMetadata = Field(repr=False)

    @field_validator("version", mode="before")
    @classmethod
    def strict_version(cls, value):
        if type(value) is not int:
            raise ValueError("Invalid version")
        return value


class ColumnProfile(Contract):
    column_id: str = Field(pattern=r"^col_[0-9]{3}$", max_length=7)
    name: str = Field(min_length=1, max_length=MAX_HEADER_CHARS, repr=False)
    inferred_type: Literal["empty", "text", "integer", "number", "boolean", "date", "mixed"]
    missing_count: int = Field(ge=0, le=MAX_ROWS)
    formula_count: int = Field(default=0, ge=0, le=MAX_ROWS)
    unavailable_formula_count: int = Field(default=0, ge=0, le=MAX_ROWS)


PreviewCell = Annotated[str, StringConstraints(max_length=MAX_PREVIEW_CHARS)] | None


class DatasetProfile(Contract):
    selected_worksheet: str | None = Field(default=None, max_length=31, repr=False)
    delimiter: Literal[",", ";", "\t"] | None = None
    row_count: int = Field(ge=0, le=MAX_ROWS)
    column_count: int = Field(ge=1, le=MAX_COLUMNS)
    nonempty_cells: int = Field(ge=1, le=MAX_NONEMPTY_CELLS)
    columns: tuple[ColumnProfile, ...] = Field(min_length=1, max_length=MAX_COLUMNS, repr=False)
    preview: tuple[tuple[PreviewCell, ...], ...] = Field(max_length=MAX_PREVIEW_ROWS, repr=False)
    warnings: tuple[WarningCode, ...] = Field(default=(), max_length=7)

    @model_validator(mode="after")
    def consistent(self):
        if len(self.columns) != self.column_count or len(self.preview) != min(self.row_count, MAX_PREVIEW_ROWS):
            raise ValueError("Invalid profile shape")
        if any(len(row) != self.column_count for row in self.preview):
            raise ValueError("Invalid preview shape")
        if sum(len((cell or "").encode("utf-8")) for row in self.preview for cell in row) > MAX_PREVIEW_BYTES:
            raise ValueError("Preview budget exceeded")
        if len(set(self.warnings)) != len(self.warnings):
            raise ValueError("Duplicate warning")
        for number, column in enumerate(self.columns, 1):
            if column.column_id != f"col_{number:03}" or not safe_label(column.name):
                raise ValueError("Invalid column identity")
            if (column.missing_count > self.row_count or column.formula_count > self.row_count
                    or column.unavailable_formula_count > min(column.formula_count, column.missing_count)):
                raise ValueError("Invalid missing count")
            if (column.inferred_type == "empty") != (column.missing_count == self.row_count):
                raise ValueError("Invalid inferred type")
        expected = self.row_count * self.column_count - sum(c.missing_count - c.unavailable_formula_count for c in self.columns) + self.column_count
        if self.nonempty_cells != expected:
            raise ValueError("Invalid nonempty count")
        duplicate = len({c.name for c in self.columns}) != self.column_count
        if duplicate != ("DUPLICATE_COLUMNS" in self.warnings):
            raise ValueError("Missing duplicate-column evidence")
        if bool(sum(c.formula_count for c in self.columns)) != ("FORMULA_CACHED_VALUES" in self.warnings):
            raise ValueError("Missing formula evidence")
        if bool(sum(c.unavailable_formula_count for c in self.columns)) != ("FORMULA_VALUES_MISSING" in self.warnings):
            raise ValueError("Missing formula-cache evidence")
        return self


class ParserResult(Contract):
    dataset_id: Identifier
    session_id: Identifier
    source_sha256: Digest
    source_byte_count: int = Field(ge=1, le=MAX_SOURCE_BYTES)
    state: Literal["PROFILED_SYNTHETIC", "NEEDS_CLARIFICATION"]
    profile: DatasetProfile = Field(repr=False)


class ParserFailure(Contract):
    state: Literal["FAILED", "CANCELLED", "TIMED_OUT", "INTERRUPTED"]
    code: IngestionCode

    @model_validator(mode="after")
    def consistent(self):
        expected = self.code.value if self.code in {IngestionCode.CANCELLED, IngestionCode.TIMED_OUT,
            IngestionCode.INTERRUPTED} else "FAILED"
        if self.state != expected:
            raise ValueError("Inconsistent failure state")
        return self


def validate_profile_result(encoded: object, request: IngestionRequest) -> ParserResult:
    """Bounded structural check of untrusted output, never provenance/validation."""
    try:
        if type(encoded) is not bytes or not 0 < len(encoded) <= MAX_PROFILE_BYTES:
            raise ValueError()
        def unique(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ValueError()
                result[key] = value
            return result
        def invalid_constant(_):
            raise ValueError()
        json.loads(encoded, object_pairs_hook=unique, parse_constant=invalid_constant)
        result = ParserResult.model_validate_json(encoded)
        if (result.dataset_id != request.dataset_id or result.session_id != request.session_id
                or result.source_sha256 != request.metadata.sha256
                or result.source_byte_count != request.metadata.byte_count
                or result.profile.selected_worksheet != request.metadata.worksheet):
            raise ValueError()
        if request.metadata.file_type == "xlsx":
            if result.profile.delimiter is not None:
                raise ValueError()
        elif result.profile.delimiter not in {",", ";", "\t"} or (
                request.metadata.delimiter is not None and result.profile.delimiter != request.metadata.delimiter):
            raise ValueError()
        clarify = any(w in result.profile.warnings for w in ("DUPLICATE_COLUMNS", "FORMULA_VALUES_MISSING"))
        if (result.state == "NEEDS_CLARIFICATION") != clarify:
            raise ValueError()
        return result
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise IngestionError(IngestionCode.INVALID_PROFILE) from None


class ParserSandbox(Protocol):
    """Future separately restricted worker; output remains untrusted bytes."""

    def profile(self, request: IngestionRequest, source: bytes) -> bytes: ...


class UnavailableParserSandbox:
    def profile(self, request: IngestionRequest, source: bytes) -> bytes:
        raise IngestionError(IngestionCode.PARSER_UNAVAILABLE)
