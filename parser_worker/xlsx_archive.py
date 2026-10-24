"""Bounded in-memory OOXML inspection inside the future parser boundary only.

Never extracts a file. Central-directory declarations are untrusted: every entry
is read through a second actual-byte counter/CRC check. These checks do not cap
native library allocation or preempt a blocked call; OS containment is required.
"""

from dataclasses import dataclass
from io import BytesIO
import posixpath
import re
import stat
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZipFile

from defusedxml.ElementTree import iterparse

from ingestion.contracts import (
    IngestionCode as Code, IngestionError, MAX_CELL_CHARS, MAX_COMPRESSION_RATIO,
    MAX_PARSED_BYTES, MAX_SHEETS, MAX_ZIP_ENTRIES, safe_label,
)
from parser_worker.common import ParseControl


_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_DOC_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_PACKAGE_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
_CONTENT = "http://schemas.openxmlformats.org/package/2006/content-types"
_WORKBOOK_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"
_CELL = re.compile(r"([A-Z]{1,3})([1-9][0-9]{0,6})\Z")
_ACTIVE = ("macroenabled", "vbaproject", "macrosheet", "externallink", "oleobject", "activex")


@dataclass(frozen=True, slots=True)
class SheetLayout:
    name: str
    part: str
    rows: int
    columns: int
    formulas: int


def _archive_name(info):
    name = info.filename
    mode = stat.S_IFMT(info.external_attr >> 16)
    parts = name.rstrip("/").split("/")
    if (not name or name != info.orig_filename or len(name.encode("utf-8")) > 512
            or not safe_label(name) or name.startswith("/") or any(c in name for c in "\\:%?#")
            or len(parts) > 16 or any(p in {"", ".", ".."} for p in parts)
            or mode not in {0, stat.S_IFREG, stat.S_IFDIR}
            or (mode == stat.S_IFDIR) != info.is_dir() and mode != 0):
        raise IngestionError(Code.UNSAFE_ARCHIVE)
    lower = name.lower()
    if (any(piece in lower for piece in _ACTIVE) or "/embeddings/" in lower
            or "/querytables/" in lower or lower.endswith((".bin", "/connections.xml"))):
        raise IngestionError(Code.UNSUPPORTED_CONTENT)


def _target(part, target):
    if not target or len(target) > 512 or not safe_label(target) or any(c in target for c in "\\:%?#"):
        raise IngestionError(Code.UNSAFE_ARCHIVE)
    base = "" if part == "_rels/.rels" else posixpath.dirname(posixpath.dirname(part))
    normalized = posixpath.normpath(target.lstrip("/") if target.startswith("/") else posixpath.join(base, target))
    if normalized in {".", ".."} or normalized.startswith("../"):
        raise IngestionError(Code.UNSAFE_ARCHIVE)
    return normalized


class _ExpandedReader:
    def __init__(self, raw, info, total, control):
        self.raw, self.info, self.total, self.control = raw, info, total, control
        self.seen = 0

    def read(self, size=-1):
        self.control.check()
        data = self.raw.read(min(size if size >= 0 else 64 * 1024, 64 * 1024))
        self.seen += len(data)
        self.total[0] += len(data)
        if (self.seen > self.info.file_size or self.total[0] > MAX_PARSED_BYTES
                or self.seen > MAX_COMPRESSION_RATIO * self.info.compress_size):
            raise IngestionError(Code.ARCHIVE_LIMIT)
        self.control.check()
        return data


def inspect_xlsx_archive(source: bytes, control: ParseControl) -> tuple[SheetLayout, ...]:
    control.check()
    with ZipFile(BytesIO(source)) as archive:
        entries = archive.infolist()
        if not 1 <= len(entries) <= MAX_ZIP_ENTRIES:
            raise IngestionError(Code.ARCHIVE_LIMIT)
        names, folded, declared = set(), set(), 0
        for info in entries:
            control.check()
            _archive_name(info)
            if info.filename.casefold() in folded:
                raise IngestionError(Code.UNSAFE_ARCHIVE)
            folded.add(info.filename.casefold())
            if not info.is_dir():
                names.add(info.filename)
            allowed_flags = 0x800 | 0x8 | (0x6 if info.compress_type == ZIP_DEFLATED else 0)
            if info.flag_bits & ~allowed_flags:
                raise IngestionError(Code.UNSUPPORTED_CONTENT)
            if info.compress_type not in {ZIP_STORED, ZIP_DEFLATED}:
                raise IngestionError(Code.UNSUPPORTED_CONTENT)
            declared += info.file_size
            if (info.file_size < 0 or info.compress_size < 0 or declared > MAX_PARSED_BYTES
                    or info.file_size > MAX_COMPRESSION_RATIO * info.compress_size
                    or info.is_dir() and info.file_size != 0):
                raise IngestionError(Code.ARCHIVE_LIMIT)
        required = {"[Content_Types].xml", "_rels/.rels", "xl/workbook.xml", "xl/_rels/workbook.xml.rels"}
        if not required <= names:
            raise IngestionError(Code.MALFORMED_XLSX)
        sheets, relationships, extents = [], {}, {}
        relation_targets, total, workbook_type = [], [0], False
        for info in entries:
            with archive.open(info) as raw:
                reader = _ExpandedReader(raw, info, total, control)
                if info.filename.endswith((".xml", ".rels")):
                    stack, row_number, previous_row, previous_column = [], 0, 0, 0
                    max_row, max_column, formulas = 0, 0, 0
                    worksheet = info.filename.startswith("xl/worksheets/") and info.filename.endswith(".xml")
                    for event, element in iterparse(reader, events=("start", "end"),
                            forbid_dtd=True, forbid_entities=True, forbid_external=True):
                        control.check()
                        if event == "start":
                            stack.append(element)
                            if len(stack) > 64 or any(len(v) > MAX_CELL_CHARS for v in element.attrib.values()):
                                raise IngestionError(Code.ARCHIVE_LIMIT)
                            if len(stack) == 1:
                                expected_root = (f"{{{_MAIN}}}worksheet" if worksheet else
                                    f"{{{_MAIN}}}workbook" if info.filename == "xl/workbook.xml" else
                                    f"{{{_CONTENT}}}Types" if info.filename == "[Content_Types].xml" else
                                    f"{{{_PACKAGE_REL}}}Relationships" if info.filename.endswith(".rels") else None)
                                if expected_root is not None and element.tag != expected_root:
                                    raise IngestionError(Code.UNSUPPORTED_CONTENT)
                            if worksheet and element.tag == f"{{{_MAIN}}}row":
                                index = element.get("r", "")
                                if not index.isascii() or not index.isdecimal() or not 1 <= int(index) <= 1048576 or int(index) <= previous_row:
                                    raise IngestionError(Code.MALFORMED_XLSX)
                                row_number = previous_row = int(index)
                                previous_column = 0
                                max_row = max(max_row, row_number)
                            elif worksheet and element.tag == f"{{{_MAIN}}}c":
                                match = _CELL.fullmatch(element.get("r", ""))
                                if match is None:
                                    raise IngestionError(Code.MALFORMED_XLSX)
                                column = 0
                                for char in match[1]:
                                    column = column * 26 + ord(char) - ord("A") + 1
                                if int(match[2]) != row_number or not previous_column < column <= 16384:
                                    raise IngestionError(Code.MALFORMED_XLSX)
                                previous_column = column
                                max_column = max(max_column, column)
                            elif worksheet and element.tag == f"{{{_MAIN}}}f":
                                formulas += 1
                            continue
                        if element.text is not None and len(element.text) > MAX_CELL_CHARS:
                            raise IngestionError(Code.CELL_LIMIT)
                        if element.tag == f"{{{_PACKAGE_REL}}}Relationship":
                            if element.get("TargetMode", "Internal") != "Internal" or any(
                                    piece in element.get("Type", "").lower() for piece in _ACTIVE):
                                raise IngestionError(Code.UNSUPPORTED_CONTENT)
                            target = _target(info.filename, element.get("Target", ""))
                            if target not in names:
                                raise IngestionError(Code.MALFORMED_XLSX)
                            relation_targets.append(target)
                            if len(relation_targets) > 4000:
                                raise IngestionError(Code.ARCHIVE_LIMIT)
                            if info.filename == "xl/_rels/workbook.xml.rels":
                                identity = element.get("Id", "")
                                if not identity or identity in relationships:
                                    raise IngestionError(Code.MALFORMED_XLSX)
                                relationships[identity] = (target, element.get("Type"))
                        elif info.filename == "[Content_Types].xml" and element.tag in {
                                f"{{{_CONTENT}}}Override", f"{{{_CONTENT}}}Default"}:
                            content_type = element.get("ContentType", "")
                            if any(piece in content_type.lower() for piece in _ACTIVE):
                                raise IngestionError(Code.UNSUPPORTED_CONTENT)
                            if element.get("PartName") == "/xl/workbook.xml":
                                if workbook_type or content_type != _WORKBOOK_TYPE:
                                    raise IngestionError(Code.UNSUPPORTED_CONTENT)
                                workbook_type = True
                        elif info.filename == "xl/workbook.xml" and element.tag == f"{{{_MAIN}}}sheet":
                            name = element.get("name", "")
                            if (not safe_label(name) or len(name) > 31 or any(c in name for c in "[]:*?/\\")
                                    or any(previous[0].casefold() == name.casefold() for previous in sheets)):
                                raise IngestionError(Code.INVALID_WORKSHEET)
                            sheets.append((name, element.get(f"{{{_DOC_REL}}}id", "")))
                            if len(sheets) > MAX_SHEETS:
                                raise IngestionError(Code.SHEET_LIMIT)
                        if worksheet and element.tag == f"{{{_MAIN}}}row":
                            row_number = 0
                        if len(stack) > 1:
                            stack[-2].remove(element)
                        stack.pop()
                        element.clear()
                    if worksheet:
                        extents[info.filename] = (max_row, max_column, formulas)
                else:
                    while reader.read(64 * 1024):
                        pass
                if reader.seen != info.file_size:
                    raise IngestionError(Code.ARCHIVE_LIMIT)
        if not workbook_type or not sheets:
            raise IngestionError(Code.MALFORMED_XLSX)
        layouts = []
        for name, identity in sheets:
            relation = relationships.get(identity)
            if relation is None or relation[1] != _DOC_REL + "/worksheet" or relation[0] not in extents:
                raise IngestionError(Code.UNSUPPORTED_CONTENT)
            layouts.append(SheetLayout(name, relation[0], *extents[relation[0]]))
        if len({layout.part for layout in layouts}) != len(layouts):
            raise IngestionError(Code.INVALID_WORKSHEET)
        control.check()
        return tuple(layouts)
