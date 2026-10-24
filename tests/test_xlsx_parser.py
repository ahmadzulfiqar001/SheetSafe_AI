"""Only bounded synthetic workbooks and deliberately malformed package fixtures."""

from datetime import date
from io import BytesIO
import re
import socket
import stat
import struct
import subprocess
from types import SimpleNamespace
from zipfile import ZIP_STORED, ZipFile, ZipInfo

import pytest

from ingestion.contracts import IngestionCode as Code, IngestionError
from ingestion_fixtures import repack, request, xlsx
from parser_worker.common import ParseControl
from parser_worker.xlsx_archive import _ExpandedReader
from parser_worker.xlsx_parser import profile_xlsx_fixture


def parse(data, **options):
    return profile_xlsx_fixture(data, request(data, "xlsx", **options))


def fails(code, data, **options):
    with pytest.raises(IngestionError) as error:
        parse(data, **options)
    assert error.value.code is code
    assert "synthetic" not in str(error.value) and "workbook.xml" not in str(error.value)


def part(data, name):
    with ZipFile(BytesIO(data)) as archive:
        return archive.read(name)


def central(data, name, *, flags=None, expanded=None):
    """Corrupt declarations without executing/extracting anything."""
    result = bytearray(data)
    offset = 0
    while True:
        offset = result.find(b"PK\x01\x02", offset)
        assert offset >= 0
        length = struct.unpack_from("<H", result, offset + 28)[0]
        actual = bytes(result[offset + 46:offset + 46 + length]).decode()
        if actual == name:
            if flags is not None:
                struct.pack_into("<H", result, offset + 8, flags)
            if expanded is not None:
                struct.pack_into("<I", result, offset + 24, expanded)
            return bytes(result)
        offset += 46 + length


def test_selected_worksheet_numeric_missing_dates_and_stable_profile():
    data = xlsx([["name", "value", "date"], ["synthetic", -12, date(2026, 10, 1)], ["other", None, None]],
        extra_sheets=(("Other", [["wrong"], [999]]),))
    result = parse(data)
    assert result.profile.row_count == 2 and result.profile.column_count == 3
    assert result.profile.preview[0] == ("synthetic", "-12", "2026-10-01T00:00:00")
    assert result.profile.columns[1].missing_count == 1 and result.profile.columns[1].inferred_type == "integer"
    assert result.profile.columns[2].inferred_type == "date"
    assert result.profile.selected_worksheet == "Data" and result.profile.delimiter is None
    assert result.profile == parse(data).profile
    assert parse(data, worksheet="Other").profile.preview == (("999",),)
    fails(Code.INVALID_WORKSHEET, data, worksheet="Missing")


def test_formulas_use_only_existing_cache_and_missing_cache_needs_values_export():
    data = xlsx([["value"], ["=1+2"]])
    missing = parse(data)
    assert missing.state == "NEEDS_CLARIFICATION" and missing.profile.preview == ((None,),)
    assert missing.profile.columns[0].formula_count == missing.profile.columns[0].unavailable_formula_count == 1
    assert missing.profile.nonempty_cells == 2
    assert {"FORMULA_CACHED_VALUES", "FORMULA_VALUES_MISSING"} <= set(missing.profile.warnings)
    xml = part(data, "xl/worksheets/sheet1.xml")
    empty_cache = br"<f>1\+2</f><v(?:\s*/>|></v>)"
    assert re.search(empty_cache, xml)
    cached = repack(data, {"xl/worksheets/sheet1.xml": re.sub(empty_cache, b"<f>1+2</f><v>999</v>", xml, count=1)})
    result = parse(cached)
    # Deliberately stale cache proves no formula calculation: 999 is preserved.
    assert result.profile.preview == (("999",),) and result.state == "PROFILED_SYNTHETIC"
    assert "FORMULA_VALUES_MISSING" not in result.profile.warnings


def test_duplicate_headers_and_inert_code_like_cells():
    data = xlsx([["same", "same"], ["__import__('os').system('false')", "=WEBSERVICE(\"https://example.invalid\")"]])
    result = parse(data)
    assert result.state == "NEEDS_CLARIFICATION" and "DUPLICATE_COLUMNS" in result.profile.warnings
    assert [c.column_id for c in result.profile.columns] == ["col_001", "col_002"]
    assert result.profile.preview[0][0] == "__import__('os').system('false')"


def test_source_integrity_and_renamed_formats():
    data = xlsx()
    expected = request(data, "xlsx")
    with pytest.raises(IngestionError) as error:
        profile_xlsx_fixture(data + b"tamper", expected)
    assert error.value.code is Code.SOURCE_INTEGRITY
    fails(Code.UNSUPPORTED_CONTENT, b"name,value\nsynthetic,1\n")
    fails(Code.UNSUPPORTED_CONTENT, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1synthetic")
    fails(Code.MALFORMED_XLSX, b"PK\x03\x04broken zip")
    fails(Code.UNSUPPORTED_CONTENT, repack(data, {"xl/workbook.xml": b"<broken>"}))
    fails(Code.MALFORMED_XLSX, repack(data, {"xl/workbook.xml":
        b'<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'}))


@pytest.mark.parametrize("name", ["../outside", "/absolute", "C:/private", "xl\\escape.xml", "xl//empty.xml",
    "xl/./dot.xml", "xl/%2e%2e/escape.xml", "xl/../escape.xml"])
def test_unsafe_archive_paths_are_rejected_without_extraction(name, tmp_path):
    canary = tmp_path / "outside"
    canary.write_text("unchanged")
    data = repack(xlsx(), additions=((name, b"synthetic"),))
    if "\\" in name:
        # ZipInfo normalizes Windows separators while writing. Put the unsafe
        # bytes into BOTH actual ZIP headers so the fixture tests the reader.
        normalized = name.replace("\\", "/").encode()
        assert data.count(normalized) == 2
        data = data.replace(normalized, name.encode())
    fails(Code.UNSAFE_ARCHIVE, data)
    assert canary.read_text() == "unchanged" and len(list(tmp_path.iterdir())) == 1


def test_duplicate_case_colliding_symlink_and_corrupt_entries():
    data = xlsx()
    with pytest.warns(UserWarning, match="Duplicate name"):
        duplicate = repack(data, additions=(("xl/workbook.xml", b"<untrusted/>"),))
    fails(Code.UNSAFE_ARCHIVE, duplicate)
    fails(Code.UNSAFE_ARCHIVE, repack(data, additions=(("XL/WORKBOOK.XML", b"<untrusted/>"),)))
    link = ZipInfo("xl/link")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    fails(Code.UNSAFE_ARCHIVE, repack(data, additions=((link, b"/outside"),)))
    corrupt = bytearray(data)
    with ZipFile(BytesIO(data)) as archive:
        info = archive.getinfo("xl/workbook.xml")
        location = info.header_offset
        name_size, extra_size = struct.unpack_from("<HH", data, location + 26)
        corrupt[location + 30 + name_size + extra_size] ^= 0xff
    with pytest.raises(IngestionError):
        parse(bytes(corrupt))


@pytest.mark.parametrize("name", ["xl/vbaProject.bin", "xl/externalLinks/externalLink1.xml",
    "xl/embeddings/oleObject1.bin", "xl/activeX/activeX1.xml", "xl/connections.xml"])
def test_macro_external_embedded_content_rejected(name):
    fails(Code.UNSUPPORTED_CONTENT, repack(xlsx(), additions=((name, b"untrusted"),)))


def test_macro_content_type_encryption_and_external_relationships():
    data = xlsx()
    manifest = part(data, "[Content_Types].xml").replace(
        b"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
        b"application/vnd.ms-excel.sheet.macroEnabled.main+xml")
    fails(Code.UNSUPPORTED_CONTENT, repack(data, {"[Content_Types].xml": manifest}))
    fails(Code.UNSUPPORTED_CONTENT, central(data, "xl/workbook.xml", flags=1))
    relationship = b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="x" Type="external" TargetMode="External" Target="https://example.invalid/private"/></Relationships>'
    fails(Code.UNSUPPORTED_CONTENT, repack(data, {"_rels/.rels": relationship}))
    fails(Code.UNSAFE_ARCHIVE, repack(data, {"_rels/.rels": relationship.replace(
        b'TargetMode="External" Target="https://example.invalid/private"', b'Target="../outside"')}))


@pytest.mark.parametrize("declaration", [b'<!DOCTYPE workbook [<!ENTITY x "expanded">]>',
    b'<!DOCTYPE workbook SYSTEM "file:///outside-secret">'])
def test_dtd_entities_and_external_entities_rejected(declaration):
    data = xlsx()
    xml = part(data, "xl/workbook.xml")
    fails(Code.UNSAFE_ARCHIVE, repack(data, {"xl/workbook.xml": declaration + xml}))


def test_entry_declared_actual_expansion_and_ratio_limits():
    data = xlsx()
    fails(Code.ARCHIVE_LIMIT, repack(data, additions=tuple((f"parts/{i}.txt", b"x") for i in range(1001))))
    fails(Code.ARCHIVE_LIMIT, central(data, "xl/workbook.xml", expanded=100 * 1024**2 + 1))
    fails(Code.ARCHIVE_LIMIT, repack(data, additions=(("parts/compressed.txt", b"x" * 200000),)))
    # Actual byte enforcement is separate from declarations, with bounded reads.
    reader = _ExpandedReader(BytesIO(b"12345"), SimpleNamespace(file_size=4, compress_size=5), [0], ParseControl())
    with pytest.raises(IngestionError) as error:
        reader.read()
    assert error.value.code is Code.ARCHIVE_LIMIT
    reader = _ExpandedReader(BytesIO(b"12"), SimpleNamespace(file_size=2, compress_size=2), [100 * 1024**2], ParseControl())
    with pytest.raises(IngestionError) as error:
        reader.read()
    assert error.value.code is Code.ARCHIVE_LIMIT
    with pytest.raises(IngestionError):
        parse(central(data, "xl/workbook.xml", expanded=10))


def test_sheet_and_selected_table_limits_and_dimension_lies():
    fails(Code.SHEET_LIMIT, xlsx(extra_sheets=tuple((f"S{i}", [["a"], [1]]) for i in range(10))))
    data = xlsx([["a"], [1]])
    xml = part(data, "xl/worksheets/sheet1.xml")
    false_dimension = re.sub(br'<dimension ref="[^"]+"', b'<dimension ref="A1:A1"', xml)
    assert parse(repack(data, {"xl/worksheets/sheet1.xml": false_dimension})).profile.row_count == 1
    far_row = xml.replace(b'r="2"', b'r="100002"').replace(b'r="A2"', b'r="A100002"')
    fails(Code.ROW_LIMIT, repack(data, {"xl/worksheets/sheet1.xml": far_row}))
    far_column = xml.replace(b'r="A2"', b'r="CW2"')
    fails(Code.COLUMN_LIMIT, repack(data, {"xl/worksheets/sheet1.xml": far_column}))
    fails(Code.INVALID_HEADER, xlsx([["=1+2"], [3]]))
    fails(Code.EMPTY_SOURCE, xlsx([]))


def test_xlsx_uses_common_nonempty_and_preview_limits(monkeypatch):
    monkeypatch.setattr("parser_worker.common.MAX_NONEMPTY_CELLS", 3)
    fails(Code.NONEMPTY_LIMIT, xlsx([["a", "b"], [1, 2]]))
    monkeypatch.setattr("parser_worker.common.MAX_NONEMPTY_CELLS", 2000000)
    profile = parse(xlsx([["text"]] + [["x" * 200] for _ in range(7)])).profile
    assert len(profile.preview) == 5 and len(profile.preview[0][0]) == 160
    assert "PREVIEW_TRUNCATED" in profile.warnings


def test_library_handles_close_and_terminal_controls(tmp_path, monkeypatch):
    from parser_worker import xlsx_parser
    data = xlsx([["value"], ["=1+2"]])
    original = xlsx_parser.load_workbook
    closed, options = [], []
    def observed(*args, **kwargs):
        options.append(kwargs)
        workbook = original(*args, **kwargs)
        close = workbook.close
        def close_and_record():
            close()
            closed.append(True)
        workbook.close = close_and_record
        return workbook
    monkeypatch.setattr(xlsx_parser, "load_workbook", observed)
    def prohibited(*args, **kwargs):
        raise AssertionError("No network/subprocess is allowed")
    monkeypatch.setattr(socket, "create_connection", prohibited)
    monkeypatch.setattr(subprocess, "Popen", prohibited)
    assert parse(data).state == "NEEDS_CLARIFICATION"
    assert len(closed) == 2 and {o["data_only"] for o in options} == {True, False}
    assert all(o["read_only"] and not o["keep_links"] and not o["keep_vba"] for o in options)
    with pytest.raises(IngestionError) as error:
        profile_xlsx_fixture(data, request(data, "xlsx"), control=ParseControl(cancelled=lambda: True))
    assert error.value.code is Code.CANCELLED
    ticks = iter([0, 0, 0, 21])
    with pytest.raises(IngestionError) as error:
        profile_xlsx_fixture(data, request(data, "xlsx"), control=ParseControl(clock=lambda: next(ticks)))
    assert error.value.code is Code.TIMED_OUT
    assert not list(tmp_path.iterdir())
