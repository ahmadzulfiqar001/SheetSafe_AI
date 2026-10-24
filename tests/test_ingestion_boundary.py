"""Actual synthetic storage-to-profile checks; no public ingestion/worker wiring."""

from concurrent.futures import ThreadPoolExecutor
import asyncio

import pytest

from backend.ingestion import check_synthetic_result, prepare_synthetic_request
from backend.security.sessions import SessionError
from ingestion.contracts import (
    IngestionCode as Code, IngestionError, IngestionRequest, MAX_SOURCE_BYTES,
    ParserFailure, metadata_from_mapping,
)
from ingestion_fixtures import metadata, request, xlsx
from parser_worker.common import ParseControl, ProfileAccumulator
from parser_worker.csv_parser import profile_csv_fixture
from parser_worker.xlsx_parser import profile_xlsx_fixture
from runner.policy import RunnerNotReady, SandboxPolicy, require_execution_ready
from test_storage import env, put


@pytest.mark.parametrize("file_type", ["csv", "xlsx"])
def test_synthetic_roundtrip_stays_pending_and_cannot_publish(env, file_type, caplog):
    _, _, db, storage, _, _, first, _ = env
    data = b"name,value\nsynthetic,12\n" if file_type == "csv" else xlsx([["name", "value"], ["synthetic", 12]])
    stored = put(storage, first.principal, data, file_type=file_type)
    prepared = prepare_synthetic_request(db, first.principal, stored.object_id, metadata(data, file_type))
    # Unit-test-only direct parser invocation; there is no application adapter.
    parser = profile_csv_fixture if file_type == "csv" else profile_xlsx_fixture
    result = parser(storage.read(first.principal, stored.object_id), prepared)
    encoded = result.model_dump_json().encode()
    checked = check_synthetic_result(db, first.principal, prepared, encoded)
    assert checked.profile.preview == (("synthetic", "12"),)
    for secret in (first.credential, first.principal.auth_token_hash, first.principal.csrf_token):
        assert secret not in encoded.decode() and secret not in caplog.text
    with db.connection() as connection:
        record = connection.execute("SELECT * FROM dataset_versions WHERE dataset_id=?", (prepared.dataset_id,)).fetchone()
        assert record["state"] == "PENDING" and record["profile_json"] == "{}"
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 6
    assert storage.read(first.principal, stored.object_id) == data
    with pytest.raises(SessionError) as error:
        storage.publish(first.principal, stored.object_id)
    assert error.value.status_code == 409
    assert SandboxPolicy().execution_enabled is False and len(SandboxPolicy().unverified_controls) == 10
    with pytest.raises(RunnerNotReady):
        require_execution_ready()


def test_expired_session_rejects_even_a_complete_synthetic_profile(env):
    clock, _, db, storage, _, _, first, _ = env
    data = b"name\nsynthetic\n"
    stored = put(storage, first.principal, data)
    prepared = prepare_synthetic_request(db, first.principal, stored.object_id, metadata(data))
    result = profile_csv_fixture(data, prepared)
    clock[0] = first.principal.expires_at
    with pytest.raises(SessionError) as error:
        check_synthetic_result(db, first.principal, prepared, result.model_dump_json().encode())
    assert error.value.status_code == 401
    with db.connection() as connection:
        assert connection.execute("SELECT state FROM dataset_versions").fetchone()[0] == "PENDING"


def test_session_cleanup_removes_new_metadata_and_preserves_other_owner(env):
    _, _, db, storage, lifecycle, sessions, first, second = env
    data = b"name\nsynthetic\n"
    requests = []
    for issued in (first, second):
        stored = put(storage, issued.principal, data)
        requests.append(prepare_synthetic_request(db, issued.principal, stored.object_id, metadata(data)))
    sessions.revoke(first.credential, first.principal.session_id)
    asyncio.run(lifecycle.run_once())
    with db.connection() as connection:
        remaining = connection.execute("SELECT dataset_id FROM datasets").fetchall()
        versions = connection.execute("SELECT dataset_id FROM dataset_versions").fetchall()
        assert [r[0] for r in remaining] == [requests[1].dataset_id]
        assert [r[0] for r in versions] == [requests[1].dataset_id]
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    assert storage.read(second.principal, requests[1].object_id) == data


def test_cancel_during_rows_never_returns_partial_profile(monkeypatch):
    data = b"name\n" + b"synthetic\n" * 100
    calls, records = [0], []
    def cancelled():
        calls[0] += 1
        return calls[0] >= 25
    original = ProfileAccumulator.add
    def observe(self, cells):
        original(self, cells)
        records.append(self.rows)
    monkeypatch.setattr(ProfileAccumulator, "add", observe)
    with pytest.raises(IngestionError) as error:
        profile_csv_fixture(data, request(data), control=ParseControl(cancelled=cancelled))
    assert error.value.code is Code.CANCELLED and 0 < len(records) < 100


@pytest.mark.parametrize("clock,code", [(lambda: float("nan"), Code.TIMED_OUT),
    (lambda: float("inf"), Code.TIMED_OUT), (lambda: True, Code.TIMED_OUT)])
def test_invalid_clock_never_authorizes_a_profile(clock, code):
    with pytest.raises(IngestionError) as error:
        ParseControl(clock=clock)
    assert error.value.code is code


def test_backward_clock_and_interrupted_xlsx_fail_closed():
    data = xlsx()
    ticks = iter([2, 1])
    for control, code in ((ParseControl(clock=lambda: next(ticks)), Code.TIMED_OUT),
            (ParseControl(interrupted=lambda: True), Code.INTERRUPTED)):
        with pytest.raises(IngestionError) as error:
            profile_xlsx_fixture(data, request(data, "xlsx"), control=control)
        assert error.value.code is code


def test_typed_terminal_state_and_strict_request_version():
    assert metadata_from_mapping({**metadata(b"x"), "byte_count": MAX_SOURCE_BYTES}).byte_count == MAX_SOURCE_BYTES
    assert ParserFailure(state="TIMED_OUT", code=Code.TIMED_OUT).state == "TIMED_OUT"
    with pytest.raises(ValueError):
        ParserFailure(state="FAILED", code=Code.CANCELLED)
    fields = request(b"name\nx\n").model_dump()
    with pytest.raises(ValueError):
        IngestionRequest.model_validate({**fields, "version": True})


def test_competing_metadata_reservations_are_idempotent(env):
    _, _, db, storage, _, _, first, _ = env
    data = b"name\nsynthetic\n"
    stored = put(storage, first.principal, data)
    # This checks reservation idempotency, not guaranteed success under a lock.
    # The existing 100ms test DB may legitimately reject a competing writer.
    def reserve():
        try:
            return prepare_synthetic_request(db, first.principal, stored.object_id, metadata(data))
        except IngestionError as error:
            assert error.code is Code.STORAGE_UNAVAILABLE
            return None
    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(lambda _: reserve(), range(2)))
    authoritative = prepare_synthetic_request(db, first.principal, stored.object_id, metadata(data))
    assert all(result is None or result == authoritative for result in results)
    with db.connection() as connection:
        assert connection.execute("SELECT count(*) FROM datasets").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM dataset_versions").fetchone()[0] == 1
