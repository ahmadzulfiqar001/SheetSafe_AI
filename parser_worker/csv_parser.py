"""Deterministic CSV worker internals. Synthetic fixtures only until isolation.

No path input, encoding fallback, header guessing, evaluation or table cache.
"""

import csv
from io import BytesIO, TextIOWrapper

from ingestion.contracts import IngestionCode as Code, IngestionError, IngestionRequest, MAX_RECORD_CHARS
from parser_worker.common import ParseControl, ProfileAccumulator, csv_cell, verify_source


class _Lines:
    def __init__(self, stream, delimiter, control):
        self.stream, self.delimiter, self.control = stream, delimiter, control
        self.record_chars, self.state = 0, "start"

    def __iter__(self):
        return self

    def __next__(self):
        self.control.check()
        line = self.stream.readline(MAX_RECORD_CHARS + 1)
        if not line:
            raise StopIteration
        self.record_chars += len(line)
        if self.record_chars > MAX_RECORD_CHARS:
            raise IngestionError(Code.RECORD_LIMIT)
        # csv.strict catches unterminated/post-quote records but permits quotes
        # inside unquoted fields. Reject those too, without changing its dialect.
        for character in line:
            if self.state == "quoted":
                if character == '"':
                    self.state = "after_quote"
            elif character == '"':
                if self.state == "plain":
                    raise IngestionError(Code.MALFORMED_CSV)
                self.state = "quoted"
            elif character == self.delimiter or character in "\r\n":
                self.state = "start"
            elif self.state == "after_quote":
                raise IngestionError(Code.MALFORMED_CSV)
            else:
                self.state = "plain"
        return line


def _delimiter(stream):
    position = stream.tell()
    header = stream.readline(64 * 1024 + 1)
    stream.seek(position)
    if len(header) > 64 * 1024:
        raise IngestionError(Code.RECORD_LIMIT)
    plausible = []
    for candidate in (",", ";", "\t"):
        try:
            fields = next(csv.reader([header], delimiter=candidate, strict=True))
        except (csv.Error, StopIteration):
            continue
        if len(fields) > 1:
            plausible.append(candidate)
    if len(plausible) > 1:
        raise IngestionError(Code.AMBIGUOUS_DELIMITER)
    return plausible[0] if plausible else ","


def profile_csv_fixture(source: bytes, request: IngestionRequest,
        *, control: ParseControl | None = None):
    """Tests call this with reviewed synthetic bytes; no production caller exists."""
    control = control if control is not None else ParseControl()
    verify_source(source, request, control)
    if request.metadata.file_type != "csv":
        raise IngestionError(Code.UNSUPPORTED_CONTENT)
    try:
        with TextIOWrapper(BytesIO(source), encoding="utf-8-sig", errors="strict", newline="") as stream:
            delimiter = request.metadata.delimiter or _delimiter(stream)
            lines = _Lines(stream, delimiter, control)
            reader = csv.reader(lines, delimiter=delimiter, strict=True)
            headers = next(reader, [])
            lines.record_chars = 0
            profile = ProfileAccumulator(headers, control)
            if any(value.startswith(("=", "+", "-", "@")) for value in headers):
                profile.warnings.add("CSV_FORMULA_LIKE_TEXT")
            if len(headers) == 1:
                profile.warnings.add("SINGLE_COLUMN_CSV")
            for row in reader:
                lines.record_chars = 0
                if any(value.startswith(("=", "+", "-", "@")) and csv_cell(value).kind == "text" for value in row):
                    profile.warnings.add("CSV_FORMULA_LIKE_TEXT")
                profile.add(tuple(csv_cell(value) for value in row))
            return profile.finish(request, delimiter=delimiter)
    except UnicodeError:
        raise IngestionError(Code.INVALID_ENCODING) from None
    except csv.Error as error:
        if str(error).startswith("field larger than field limit"):
            raise IngestionError(Code.CELL_LIMIT) from None
        raise IngestionError(Code.MALFORMED_CSV) from None
    except InterruptedError:
        raise IngestionError(Code.INTERRUPTED) from None
