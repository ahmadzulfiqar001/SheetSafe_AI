"""Reviewed synthetic builders, never production upload adapters."""

import hashlib
from io import BytesIO
from uuid import uuid4
from zipfile import ZIP_DEFLATED, ZipFile

from ingestion.contracts import DatasetMetadata, IngestionRequest


def metadata(data, file_type="csv", **options):
    result = dict(filename="synthetic." + file_type, file_type=file_type,
        byte_count=len(data), sha256=hashlib.sha256(data).hexdigest())
    if file_type == "xlsx":
        result["worksheet"] = "Data"
    result.update(options)
    return result


def request(data, file_type="csv", **options):
    return IngestionRequest(dataset_id=uuid4().hex, session_id=uuid4().hex, object_id=uuid4().hex,
        metadata=DatasetMetadata.model_validate(metadata(data, file_type, **options)))


def result_fields(request):
    return dict(dataset_id=request.dataset_id, session_id=request.session_id,
        source_sha256=request.metadata.sha256, source_byte_count=request.metadata.byte_count,
        state="PROFILED_SYNTHETIC", profile=dict(selected_worksheet=request.metadata.worksheet,
            delimiter="," if request.metadata.file_type == "csv" else None,
            row_count=1, column_count=1, nonempty_cells=2,
            columns=[dict(column_id="col_001", name="name", inferred_type="text", missing_count=0)],
            preview=[["synthetic"]], warnings=[]))


def xlsx(rows=None, *, extra_sheets=()):
    from openpyxl import Workbook
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Data"
    for row in rows if rows is not None else [["name", "value"], ["synthetic", 12], ["missing", None]]:
        sheet.append(row)
    for name, values in extra_sheets:
        sheet = workbook.create_sheet(name)
        for row in values:
            sheet.append(row)
    stream = BytesIO()
    workbook.save(stream)
    workbook.close()
    return stream.getvalue()


def repack(data, changes=None, additions=()):
    stream = BytesIO()
    with ZipFile(BytesIO(data)) as original, ZipFile(stream, "w", compression=ZIP_DEFLATED) as result:
        for info in original.infolist():
            value = (changes or {}).get(info.filename, original.read(info))
            if value is not None:
                result.writestr(info.filename, value)
        for name, value in additions:
            result.writestr(name, value)
    return stream.getvalue()
