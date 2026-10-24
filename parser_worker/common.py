"""Streaming profile primitives; no database, paths, secrets or runtime access."""

from collections.abc import Callable, Sequence
from dataclasses import dataclass
import hashlib
import math
import re
import time

from ingestion.contracts import (
    ColumnProfile, DatasetProfile, IngestionCode as Code, IngestionError, IngestionRequest,
    MAX_CELL_CHARS, MAX_COLUMNS, MAX_HEADER_CHARS, MAX_NONEMPTY_CELLS, MAX_PARSED_BYTES,
    MAX_PREVIEW_BYTES, MAX_PREVIEW_CHARS, MAX_PREVIEW_ROWS, MAX_ROWS, MAX_SOURCE_BYTES,
    PARSER_SECONDS, ParserResult, safe_label, validate_profile_result,
)


class ParseControl:
    """Cooperative timeout/cancel contract, NOT an OS watchdog or DB authority.

    A future sandbox supervisor must independently preempt blocked library calls
    and enforce current session/lease authorization and the remaining job budget.
    """

    def __init__(self, *, clock: Callable[[], float] = time.monotonic,
            cancelled: Callable[[], bool] = lambda: False,
            interrupted: Callable[[], bool] = lambda: False):
        self._clock, self._cancelled, self._interrupted = clock, cancelled, interrupted
        self._previous = self._start = self._now()

    def _now(self):
        value = self._clock()
        if type(value) not in (int, float) or not math.isfinite(value):
            raise IngestionError(Code.TIMED_OUT)
        return value

    def check(self):
        now = self._now()
        if now < self._previous or now - self._start >= PARSER_SECONDS:
            raise IngestionError(Code.TIMED_OUT)
        self._previous = now
        if self._cancelled():
            raise IngestionError(Code.CANCELLED)
        if self._interrupted():
            raise IngestionError(Code.INTERRUPTED)


def verify_source(source: bytes, request: IngestionRequest, control: ParseControl):
    control.check()
    if type(source) is not bytes:
        raise IngestionError(Code.SOURCE_INTEGRITY)
    if not source:
        raise IngestionError(Code.EMPTY_SOURCE)
    if len(source) > MAX_SOURCE_BYTES:
        raise IngestionError(Code.SOURCE_TOO_LARGE)
    if len(source) != request.metadata.byte_count or hashlib.sha256(source).hexdigest() != request.metadata.sha256:
        raise IngestionError(Code.SOURCE_INTEGRITY)
    control.check()


@dataclass(frozen=True, slots=True)
class Cell:
    text: str | None
    kind: str = "text"
    formula: bool = False


_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]*)\Z")
_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\Z")


def csv_cell(value: str) -> Cell:
    if value == "":
        return Cell(None)
    # Inference labels never convert/rewrite source text, dates or currencies.
    kind = "text"
    if len(value) <= 128:
        if _INTEGER.fullmatch(value):
            kind = "integer"
        elif _NUMBER.fullmatch(value):
            kind = "number"
    return Cell(value, kind)


class ProfileAccumulator:
    def __init__(self, headers: Sequence[str], control: ParseControl):
        control.check()
        if not headers:
            raise IngestionError(Code.EMPTY_SOURCE)
        if len(headers) > MAX_COLUMNS:
            raise IngestionError(Code.COLUMN_LIMIT)
        if any(type(h) is not str or len(h) > MAX_HEADER_CHARS or not safe_label(h) for h in headers):
            raise IngestionError(Code.INVALID_HEADER)
        self.headers, self.control = tuple(headers), control
        self.rows, self.nonempty = 0, len(headers)
        self.missing = [0] * len(headers)
        self.formulas, self.unavailable = [0] * len(headers), [0] * len(headers)
        self.types = [set() for _ in headers]
        self.preview, self.preview_bytes = [], 0
        self.parsed_bytes = sum(len(h.encode("utf-8")) + 1 for h in headers)
        self.warnings = set()
        if len(set(headers)) != len(headers):
            self.warnings.add("DUPLICATE_COLUMNS")

    def add(self, cells: Sequence[Cell]):
        self.control.check()
        if self.rows >= MAX_ROWS:
            raise IngestionError(Code.ROW_LIMIT)
        if len(cells) != len(self.headers):
            raise IngestionError(Code.MALFORMED_CSV)
        preview = []
        for index, cell in enumerate(cells):
            text = cell.text
            missing = text is None or text == ""
            if text is not None and (len(text) > MAX_CELL_CHARS or "\x00" in text):
                raise IngestionError(Code.CELL_LIMIT)
            self.missing[index] += missing
            self.nonempty += not missing or cell.formula
            self.formulas[index] += cell.formula
            self.unavailable[index] += cell.formula and missing
            if cell.formula:
                self.warnings.add("FORMULA_CACHED_VALUES")
                if missing:
                    self.warnings.add("FORMULA_VALUES_MISSING")
            if not missing:
                self.types[index].add(cell.kind)
            self.parsed_bytes += len((text or "").encode("utf-8")) + 1
            if self.nonempty > MAX_NONEMPTY_CELLS:
                raise IngestionError(Code.NONEMPTY_LIMIT)
            if self.parsed_bytes > MAX_PARSED_BYTES:
                raise IngestionError(Code.ARCHIVE_LIMIT)
            if self.rows < MAX_PREVIEW_ROWS:
                value = None if missing else text[:MAX_PREVIEW_CHARS].encode("utf-8")[:
                    MAX_PREVIEW_BYTES - self.preview_bytes].decode("utf-8", errors="ignore")
                if not missing and value != text:
                    self.warnings.add("PREVIEW_TRUNCATED")
                self.preview_bytes += len((value or "").encode("utf-8"))
                preview.append(value)
        if self.rows < MAX_PREVIEW_ROWS:
            self.preview.append(tuple(preview))
        self.rows += 1

    def finish(self, request: IngestionRequest, *, delimiter: str | None) -> ParserResult:
        def inferred(kinds):
            if not kinds:
                return "empty"
            if kinds <= {"integer", "number"}:
                return "number" if "number" in kinds else "integer"
            return next(iter(kinds)) if len(kinds) == 1 else "mixed"
        self.control.check()
        columns = tuple(ColumnProfile(column_id=f"col_{i+1:03}", name=name,
            inferred_type=inferred(self.types[i]), missing_count=self.missing[i],
            formula_count=self.formulas[i], unavailable_formula_count=self.unavailable[i])
            for i, name in enumerate(self.headers))
        profile = DatasetProfile(selected_worksheet=request.metadata.worksheet, delimiter=delimiter,
            row_count=self.rows, column_count=len(columns), nonempty_cells=self.nonempty,
            columns=columns, preview=tuple(self.preview), warnings=tuple(sorted(self.warnings)))
        clarify = bool(self.warnings & {"DUPLICATE_COLUMNS", "FORMULA_VALUES_MISSING"})
        result = ParserResult(dataset_id=request.dataset_id, session_id=request.session_id,
            source_sha256=request.metadata.sha256, source_byte_count=request.metadata.byte_count,
            state="NEEDS_CLARIFICATION" if clarify else "PROFILED_SYNTHETIC", profile=profile)
        encoded = result.model_dump_json().encode("utf-8")
        checked = validate_profile_result(encoded, request)
        self.control.check()
        return checked
