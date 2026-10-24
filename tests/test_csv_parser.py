"""CSV algorithms run locally only on synthetic fixtures, never user uploads."""

import pytest

from ingestion.contracts import IngestionCode as Code, IngestionError, MAX_SOURCE_BYTES
from ingestion_fixtures import request
from parser_worker.common import ParseControl
from parser_worker.csv_parser import profile_csv_fixture


def parse(data, **options):
    return profile_csv_fixture(data, request(data, **options))


def fails(code, data, **options):
    with pytest.raises(IngestionError) as error:
        parse(data, **options)
    assert error.value.code is code


@pytest.mark.parametrize("delimiter", [",", ";", "\t"])
@pytest.mark.parametrize("bom", [b"", b"\xef\xbb\xbf"])
def test_utf8_delimiters_missing_numeric_and_original_text(delimiter, bom):
    data = bom + f"name{delimiter}value\r\nاسلام{delimiter}-12\r\nother{delimiter}\r\n".encode()
    result = parse(data)
    assert result.profile.delimiter == delimiter and result.profile.row_count == 2
    assert result.profile.preview == (("اسلام", "-12"), ("other", None))
    assert result.profile.columns[1].inferred_type == "integer"
    assert result.profile.columns[1].missing_count == 1
    assert result.profile.nonempty_cells == 5
    assert result.source_sha256 == request(data).metadata.sha256


def test_duplicates_are_preserved_with_stable_ids_and_need_clarification():
    result = parse(b"name,name\n1,2\n")
    assert result.state == "NEEDS_CLARIFICATION"
    assert [c.name for c in result.profile.columns] == ["name", "name"]
    assert [c.column_id for c in result.profile.columns] == ["col_001", "col_002"]
    assert "DUPLICATE_COLUMNS" in result.profile.warnings
    assert result.profile.preview == (("1", "2"),)


def test_quoting_multiline_and_deterministic_bounded_profile():
    data = b'name,value\n"a,b","line1\nline2"\n"a""b",3.5\n'
    first = parse(data)
    assert first.profile.preview == (("a,b", "line1\nline2"), ('a"b', "3.5"))
    assert first.profile.columns[1].inferred_type == "mixed"
    assert first.profile == parse(data).profile
    bounded = parse(b"name\n" + b"x" * 200 + b"\n" + b"y\n" * 10)
    assert len(bounded.profile.preview) == 5 and len(bounded.profile.preview[0][0]) == 160
    assert "PREVIEW_TRUNCATED" in bounded.profile.warnings


@pytest.mark.parametrize("data,code", [
    (b"\xef\xbb\xbf", Code.EMPTY_SOURCE), (b"\n", Code.EMPTY_SOURCE),
    (b"a\n\xff\n", Code.INVALID_ENCODING), (b"a\n\xe9\n", Code.INVALID_ENCODING),
    (b"a\x00\n1\n", Code.INVALID_HEADER), (b"a,\n1,2\n", Code.INVALID_HEADER),
    (b"a\n\"unfinished", Code.MALFORMED_CSV), (b'a\n"x"junk\n', Code.MALFORMED_CSV),
    (b'a\nx"y\n', Code.MALFORMED_CSV), (b"a,b\n1\n", Code.MALFORMED_CSV),
    (b"a,b\n1,2,3\n", Code.MALFORMED_CSV), (b"a,b;c\n1,2;3\n", Code.AMBIGUOUS_DELIMITER),
    (b"a\n" + b"x" * 32769 + b"\n", Code.CELL_LIMIT),
    (b"a\n" + b"x" * (1024**2 + 1), Code.RECORD_LIMIT),
    (b"a\n" + b'"' + b"a\n" * (1024**2 // 2) + b'"', Code.CELL_LIMIT),
    (b"x" * 129 + b"\n1\n", Code.INVALID_HEADER),
    ((b"a," * 100) + b"last\n", Code.COLUMN_LIMIT),
], ids=lambda value: value.value if isinstance(value, Code) else "fixture")
def test_rejects_malformed_or_excessive_records(data, code):
    fails(code, data, delimiter="," if code != Code.AMBIGUOUS_DELIMITER else None)


def test_header_only_and_explicit_delimiter_do_not_guess_interpretation():
    assert parse(b"a,b\n").profile.row_count == 0
    assert parse(b"a,b;c\n1,2;3\n", delimiter=";").profile.preview == (("1,2", "3"),)


def test_formula_like_text_and_leading_zero_values_are_not_executed_or_coerced(tmp_path):
    data = b"name,value\na,__import__('os').system('false')\nb,=1+2\nc,0012\n"
    result = parse(data)
    assert result.profile.preview[0][1] == "__import__('os').system('false')"
    assert result.profile.preview[1][1] == "=1+2" and result.profile.preview[2][1] == "0012"
    assert "CSV_FORMULA_LIKE_TEXT" in result.profile.warnings
    assert not list(tmp_path.iterdir())


def test_real_row_and_nonempty_limits():
    allowed = parse(b"a\n" + b"1\n" * 100000)
    assert allowed.profile.row_count == 100000
    fails(Code.ROW_LIMIT, b"a\n" + b"1\n" * 100001)
    header = ",".join(f"c{i}" for i in range(100)).encode() + b"\n"
    row = b",".join([b"1"] * 100) + b"\n"
    assert parse(header + row * 19999).profile.nonempty_cells == 2000000
    fails(Code.NONEMPTY_LIMIT, header + row * 20000)


def test_integrity_size_and_cooperative_terminal_states():
    source = b"a\n1\n"
    expected = request(source)
    for data, code in ((b"", Code.EMPTY_SOURCE), (b"a\n2\n", Code.SOURCE_INTEGRITY),
            (b"x" * (MAX_SOURCE_BYTES + 1), Code.SOURCE_TOO_LARGE)):
        with pytest.raises(IngestionError) as error:
            profile_csv_fixture(data, expected)
        assert error.value.code is code
    for options, code in (({"cancelled": lambda: True}, Code.CANCELLED),
            ({"interrupted": lambda: True}, Code.INTERRUPTED)):
        with pytest.raises(IngestionError) as error:
            profile_csv_fixture(source, expected, control=ParseControl(**options))
        assert error.value.code is code
    ticks = iter([0, 0, 0, 21])
    with pytest.raises(IngestionError) as error:
        profile_csv_fixture(source, expected, control=ParseControl(clock=lambda: next(ticks)))
    assert error.value.code is Code.TIMED_OUT


def test_preview_total_byte_limit_and_no_private_logs(caplog):
    header = ",".join(f"c{i}" for i in range(100)).encode() + b"\n"
    data = header + (b",".join([("ح" * 200).encode()] * 100) + b"\n") * 5
    profile = parse(data).profile
    assert sum(len((c or "").encode()) for row in profile.preview for c in row) <= 16 * 1024
    assert "PREVIEW_TRUNCATED" in profile.warnings
    assert len(profile.model_dump_json().encode()) < 128 * 1024
    assert not caplog.records
