"""Strict metadata/output checks over synthetic bytes; no parser execution."""

import ast
import json
from pathlib import Path
import sqlite3

import pytest

from backend import ingestion as service
from backend.main import create_app
from backend.security.sessions import SessionError
from ingestion.contracts import (
    IngestionCode as Code, IngestionError, MAX_PROFILE_BYTES, UnavailableParserSandbox,
    metadata_from_mapping, validate_profile_result,
)
from ingestion_fixtures import metadata, request, result_fields
from test_storage import env, location, put


DATA = b"name\nsynthetic\n"


def fails(code, action):
    with pytest.raises(IngestionError) as error:
        action()
    assert error.value.code is code
    assert DATA.decode().strip() not in str(error.value)


@pytest.mark.parametrize("change", [
    {"dataset_id": "a" * 32}, {"session_id": "b" * 32}, {"state": "READY"}, {"path": "/etc/passwd"},
    {"parser_args": {}}, {"file_type": "xls"}, {"file_type": "xlsm"}, {"file_type": "CSV"},
    {"byte_count": True}, {"byte_count": "20"}, {"byte_count": 0}, {"byte_count": 20 * 1024**2 + 1},
    {"sha256": "a" * 63}, {"sha256": "A" * 64}, {"filename": "../private.csv"},
    {"filename": "C:\\private.csv"}, {"filename": "secret\n.csv"}, {"filename": "x" * 129 + ".csv"},
    {"filename": "book.xlsx"}, {"worksheet": "Data"}, {"delimiter": "|"}, {"delimiter": 1},
])
def test_metadata_rejects_unsupported_and_caller_overrides(change):
    fails(Code.INVALID_METADATA, lambda: metadata_from_mapping({**metadata(DATA), **change}))


@pytest.mark.parametrize("change", [{"worksheet": None}, {"worksheet": ""}, {"worksheet": "a" * 32},
    {"worksheet": "../Data"}, {"worksheet": "Data\x00"}, {"delimiter": ","}, {"filename": "book.xlsm"}])
def test_xlsx_requires_one_explicit_bounded_sheet(change):
    fails(Code.INVALID_METADATA, lambda: metadata_from_mapping({**metadata(b"synthetic", "xlsx"), **change}))


def test_output_is_immutable_strict_bounded_and_bound_to_request():
    expected = request(DATA)
    result = validate_profile_result(json.dumps(result_fields(expected)).encode(), expected)
    assert result.profile.columns[0].column_id == "col_001"
    assert isinstance(result.profile.preview, tuple)
    with pytest.raises(ValueError):
        result.state = "READY"
    for value in (b"{}", b"x" * (MAX_PROFILE_BYTES + 1), b'{"state":NaN}', b'{"a":1,"a":2}', b'\xff'):
        fails(Code.INVALID_PROFILE, lambda: validate_profile_result(value, expected))
    fields = result_fields(expected)
    for field, value in (("source_sha256", "f" * 64), ("dataset_id", "c" * 32),
            ("session_id", "d" * 32), ("state", "READY"), ("unexpected", True), ("source_byte_count", True)):
        fails(Code.INVALID_PROFILE, lambda: validate_profile_result(json.dumps({**fields, field: value}).encode(), expected))


@pytest.mark.parametrize("field,value", [
    ("row_count", 100001), ("column_count", 101), ("nonempty_cells", 2000001),
    ("preview", [["x" * 161]]), ("preview", [["a", "b"]]), ("warnings", ["arbitrary warning"]),
    ("columns", [dict(column_id="col_002", name="name", inferred_type="python", missing_count=0)]),
    ("columns", [dict(column_id="col_001", name="name", inferred_type="text", missing_count=2)]),
    ("selected_worksheet", "Other"), ("delimiter", ";"),
])
def test_invalid_profile_shapes_are_rejected(field, value):
    expected = request(DATA, delimiter=",")
    fields = result_fields(expected)
    fields["profile"][field] = value
    fails(Code.INVALID_PROFILE, lambda: validate_profile_result(json.dumps(fields).encode(), expected))


def test_pending_reservation_reuses_storage_and_dataset_relationships(env):
    _, _, db, storage, _, _, first, _ = env
    stored = put(storage, first.principal, DATA)
    prepared = service.prepare_synthetic_request(db, first.principal, stored.object_id, metadata(DATA))
    replay = service.prepare_synthetic_request(db, first.principal, stored.object_id, metadata(DATA))
    assert replay == prepared and len(prepared.dataset_id) == 32 and prepared.dataset_id != stored.object_id
    with db.connection() as connection:
        assert connection.execute("SELECT count(*) FROM datasets").fetchone()[0] == 1
        record = connection.execute("SELECT * FROM dataset_versions").fetchone()
        assert record["session_id"] == first.principal.session_id and record["state"] == "PENDING"
        assert record["profile_json"] == "{}"
        events = connection.execute("SELECT details_json FROM audit_events WHERE event_type='DATASET_CREATED'").fetchall()
        assert len(events) == 1 and "filename" not in events[0][0] and "synthetic.csv" not in events[0][0]
    fields = result_fields(prepared)
    checked = service.check_synthetic_result(db, first.principal, prepared, json.dumps(fields).encode())
    assert checked.state == "PROFILED_SYNTHETIC"
    with db.connection() as connection:
        assert connection.execute("SELECT state FROM dataset_versions").fetchone()[0] == "PENDING"
    fails(Code.STATE_CONFLICT, lambda: service.prepare_synthetic_request(db, first.principal,
        stored.object_id, {**metadata(DATA), "delimiter": ";"}))


def test_ownership_and_storage_integrity_are_rechecked(env):
    _, _, db, storage, _, _, first, second = env
    stored = put(storage, first.principal, DATA)
    with pytest.raises(SessionError) as error:
        service.prepare_synthetic_request(db, second.principal, stored.object_id, metadata(DATA))
    assert error.value.status_code == 404
    fails(Code.SOURCE_INTEGRITY, lambda: service.prepare_synthetic_request(db, first.principal,
        stored.object_id, {**metadata(DATA), "sha256": "f" * 64}))
    prepared = service.prepare_synthetic_request(db, first.principal, stored.object_id, metadata(DATA))
    with pytest.raises(SessionError) as error:
        service.check_synthetic_result(db, second.principal, prepared, json.dumps(result_fields(prepared)).encode())
    assert error.value.status_code == 404
    location(db, storage, stored.object_id).write_bytes(b"tampered")
    with pytest.raises(SessionError) as error:
        storage.read(first.principal, stored.object_id)
    assert error.value.status_code == 503


@pytest.mark.parametrize("mode", ["revoked", "expired", "during_check", "version_cancelled"])
def test_inactive_or_cancelled_work_never_passes_result_check(env, monkeypatch, mode):
    clock, _, db, storage, _, sessions, first, _ = env
    stored = put(storage, first.principal, DATA)
    prepared = service.prepare_synthetic_request(db, first.principal, stored.object_id, metadata(DATA))
    encoded = json.dumps(result_fields(prepared)).encode()
    if mode == "during_check":
        original = service.validate_profile_result
        def revoked_between_checks(*args):
            result = original(*args)
            sessions.revoke(first.credential, first.principal.session_id)
            return result
        monkeypatch.setattr(service, "validate_profile_result", revoked_between_checks)
    elif mode == "expired":
        clock[0] = first.principal.expires_at
    elif mode == "version_cancelled":
        with db.transaction() as connection:
            connection.execute("UPDATE dataset_versions SET state='FAILED' WHERE dataset_id=?", (prepared.dataset_id,))
        fails(Code.STATE_CONFLICT, lambda: service.check_synthetic_result(db, first.principal, prepared, encoded))
        return
    else:
        sessions.revoke(first.credential, first.principal.session_id)
    with pytest.raises(SessionError) as error:
        service.check_synthetic_result(db, first.principal, prepared, encoded)
    assert error.value.status_code == 401


def test_database_failure_is_sanitized_and_reservation_rolls_back(env, monkeypatch):
    _, _, db, storage, _, _, first, _ = env
    stored = put(storage, first.principal, DATA)
    def fail(*args, **kwargs):
        raise sqlite3.OperationalError("private SQL and secret path")
    with monkeypatch.context() as patch:
        patch.setattr(db, "append_audit_event", fail)
        fails(Code.STORAGE_UNAVAILABLE, lambda: service.prepare_synthetic_request(db, first.principal, stored.object_id, metadata(DATA)))
    with db.connection() as connection:
        assert connection.execute("SELECT count(*) FROM datasets").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM dataset_versions").fetchone()[0] == 0


def test_no_production_parser_path_or_upload_route():
    for source in Path("backend").rglob("*.py"):
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            modules = ([a.name for a in node.names] if isinstance(node, ast.Import)
                else [node.module or ""] if isinstance(node, ast.ImportFrom) else [])
            assert not any(m.split(".")[0] in {"parser_worker", "openpyxl", "pandas", "csv", "zipfile"} for m in modules)
    assert set(create_app().openapi()["paths"]).issubset({"/api/v1/health", "/api/v1/ready",
        "/api/v1/sessions", "/api/v1/sessions/{session_id}",
        "/api/v1/planning/synthetic-dataset", "/api/v1/planning/preview", "/api/v1/planning/runs"})
    fails(Code.PARSER_UNAVAILABLE, lambda: UnavailableParserSandbox().profile(request(DATA), DATA))
