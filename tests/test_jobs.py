"""Real SQLite claims, controlled clocks/failures; no daemon or execution."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
import socket
import sqlite3
import subprocess
from threading import Barrier
import time

import pytest

from backend.config import Settings
from backend.security import sessions
from backend.security.lifecycle import LifecycleCoordinator
from backend.security.sessions import SessionError, SessionService
from backend.storage.database import Database
from backend.storage.jobs import JobCode, JobError, JobStore, SYNTHETIC_PAYLOAD
from backend.storage.schema import MIGRATIONS
from runner.durable_preparation import prepare_synthetic
from runner.policy import SandboxPolicy
from runner.transport_protocol import (
    FrameValidator, InputManifest, JobBinding, PayloadEvidence, encode_frame,
)
from runner.transport_state import PreparationState as State


class Clock:
    def __init__(self):
        self.value = int(time.time())

    def __call__(self):
        return self.value


@pytest.fixture(autouse=True)
def forbid_runtime_io(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("No subprocess or network transport is permitted")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


@pytest.fixture
def setup(tmp_path, monkeypatch):
    clock = Clock()
    monkeypatch.setattr(sessions, "utc_now", clock)
    settings = Settings(_env_file=None, database_path=tmp_path / "metadata.sqlite3",
        database_busy_timeout_ms=100)
    database = Database(settings, clock=clock)
    database.initialize()
    service = SessionService(database, settings)
    first = service.create("127.0.0.1")
    second = service.create("127.0.0.2")
    with database.transaction() as connection:
        for index, issued in enumerate((first, second)):
            owner = issued.principal.session_id
            connection.execute(
                """INSERT INTO datasets(dataset_id,session_id,source_sha256,storage_ref,
                    file_type,byte_count,idempotency_key,request_sha256) VALUES (?,?,?,?,?,?,?,?)""",
                (f"dataset_{index}", owner, "a" * 64, "synthetic-reference", "csv", 1, "sample", "b" * 64))
            connection.execute("INSERT INTO dataset_versions(dataset_id,version,session_id) VALUES (?,1,?)",
                (f"dataset_{index}", owner))
            for suffix in ("a", "b"):
                run_id = f"run_{index}_{suffix}"
                connection.execute(
                    """INSERT INTO runs(run_id,session_id,dataset_id,dataset_version,question,state,
                        idempotency_key,request_sha256,created_at,updated_at) VALUES (?,?,?,1,?,'QUEUED',?,?,?,?)""",
                    (run_id, owner, f"dataset_{index}", "Fixed sample", suffix, "c" * 64, clock(), clock()))
    return database, JobStore(database), clock, first, second, service, settings


def register(setup):
    return setup[1].register(setup[3].principal, "run_0_a")


def row(database, job_id):
    with database.connection() as connection:
        return dict(connection.execute("SELECT * FROM runs WHERE runner_job_id=?", (job_id,)).fetchone())


def count_events(database):
    with database.connection() as connection:
        return connection.execute("SELECT count(*) FROM audit_events").fetchone()[0]


def assert_code(code, callback):
    with pytest.raises(JobError) as caught:
        callback()
    assert caught.value.code is code
    assert str(caught.value) == f"Synthetic preparation failed: {code.value}."


def evidence(manifest):
    validator = FrameValidator(manifest)
    validator.feed(encode_frame(manifest, 0, SYNTHETIC_PAYLOAD))
    return validator.finish()


class FakeTransport:
    def __init__(self, chunks, action=None):
        self.chunks = iter(chunks)
        self.action = action
        self.reads = self.closes = 0

    def receive(self, *, max_bytes, timeout):
        self.reads += 1
        if self.action is not None:
            action, self.action = self.action, None
            action()
        assert max_bytes > 0 and timeout > 0
        return next(self.chunks)

    def close(self):
        self.closes += 1


def test_registration_is_durable_fixed_owned_and_not_an_execution(setup):
    database, store, clock, first, *_ = setup
    job_id = register(setup)
    record = row(database, job_id)
    assert len(job_id) == 32 and job_id != "run_0_a"
    assert record["prep_state"] == "CREATED" and record["lease_epoch"] == 0
    assert record["prep_payload_length"] == len(SYNTHETIC_PAYLOAD)
    assert record["prep_fixture_id"] == "smoke-v1" and record["prep_protocol_version"] == 1
    reopened = Database(setup[-1], clock=clock)
    assert JobStore(reopened).snapshot(first.principal, job_id).execution_enabled is False
    with database.connection() as connection:
        assert connection.execute("SELECT count(*) FROM attempts").fetchone()[0] == 0
    before = count_events(database)
    assert_code(JobCode.DUPLICATE, lambda: store.register(first.principal, "run_0_a"))
    assert count_events(database) == before


def test_cross_session_registration_read_and_cancel_rejected(setup):
    _, store, _, first, second, *_ = setup
    for principal, run in ((first.principal, "run_1_a"), (second.principal, "run_0_a")):
        with pytest.raises(SessionError) as caught:
            store.register(principal, run)
        assert caught.value.status_code == 404
    job_id = register(setup)
    for method in (store.snapshot, store.cancel):
        with pytest.raises(SessionError):
            method(second.principal, job_id)
    with pytest.raises(SessionError):
        store.register(replace(first.principal, auth_token_hash="d" * 64), "run_0_b")


@pytest.mark.parametrize("assignment", ["state='COMPLETE',validation_status='PASSED',cleanup_status='CONFIRMED'",
    "state='BLOCKED_POLICY'", "state='EXECUTE'", "cleanup_status='FAILED'", "cancel_requested_at=unixepoch()",
    "candidate_versions=1"])
def test_registration_rejects_ineligible_run(setup, assignment):
    database, store, _, first, *_ = setup
    with database.transaction() as connection:
        connection.execute(f"UPDATE runs SET {assignment} WHERE run_id='run_0_a'")
    assert_code(JobCode.BLOCKED, lambda: store.register(first.principal, "run_0_a"))


@pytest.mark.parametrize("assignment", ["runner_job_id=NULL", "prep_fixture_id='other'",
    "prep_payload_length=1", "prep_payload_sha256='" + "d" * 64 + "'", "prep_protocol_version=2",
    "prep_created_at=prep_created_at+1", "prep_state=NULL", "lease_epoch=-1"])
def test_manifest_and_schema_guards(setup, assignment):
    database = setup[0]
    job_id = register(setup)
    before = row(database, job_id)
    with pytest.raises(sqlite3.IntegrityError):
        with database.transaction() as connection:
            connection.execute(f"UPDATE runs SET {assignment} WHERE runner_job_id=?", (job_id,))
    assert row(database, job_id) == before


def test_claim_restart_exact_expiry_and_fencing(setup):
    database, store, clock, *_ = setup
    job_id = register(setup)
    lease = store.claim(job_id)
    old_manifest = store.manifest(lease)
    assert lease.epoch == 1 and lease.owner not in repr(lease)
    restarted = JobStore(Database(setup[-1], clock=clock))
    clock.value = lease.expires_at - 1
    assert_code(JobCode.OWNED, lambda: restarted.claim(job_id))
    clock.value = lease.expires_at
    successor = restarted.claim(job_id)
    assert successor.epoch == 2 and successor.owner != lease.owner
    assert row(database, job_id)["prep_state"] == "CREATED"
    assert_code(JobCode.STALE, lambda: store.renew(lease))
    assert_code(JobCode.STALE, lambda: store.advance(lease, State.CREATED, State.RECEIVING))
    fresh_manifest = restarted.manifest(successor)
    assert fresh_manifest.binding.job_id == old_manifest.binding.job_id
    assert fresh_manifest.binding_digest != old_manifest.binding_digest


@pytest.mark.parametrize("iteration", range(10))
def test_two_concurrent_workers_have_one_winner(setup, iteration):
    database, _, clock, *_ = setup
    job_id = register(setup)
    gate = Barrier(2)
    def compete():
        local = JobStore(Database(setup[-1], clock=clock))
        gate.wait(timeout=5)
        try:
            return local.claim(job_id)
        except JobError as error:
            return error.code
    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(lambda _: compete(), range(2)))
    assert sum(not isinstance(result, JobCode) for result in results) == 1
    assert JobCode.OWNED in results
    assert row(database, job_id)["lease_epoch"] == 1
    with database.connection() as connection:
        assert connection.execute("SELECT count(*) FROM audit_events WHERE event_type='JOB_CLAIMED'").fetchone()[0] == 1


def test_renewal_is_bounded_and_cannot_revive_expired_lease(setup):
    database, store, clock, *_ = setup
    job_id = register(setup)
    lease = store.claim(job_id)
    start = clock()
    assert_code(JobCode.DEADLINE, lambda: store.renew(lease))
    for offset in (9, 18, 27):
        clock.value = start + offset
        lease = store.renew(lease)
    assert lease.expires_at == start + 30
    assert row(database, job_id)["deadline_at"] == start + 180
    clock.value = start + 28
    assert_code(JobCode.DEADLINE, lambda: store.renew(lease))
    clock.value = lease.expires_at
    assert_code(JobCode.STALE, lambda: store.renew(lease))


def test_session_end_caps_lease(setup):
    database, store, clock, first, *_ = setup
    job_id = register(setup)
    with database.transaction() as connection:
        connection.execute("UPDATE sessions SET expires_at=? WHERE session_id=?", (clock() + 5, first.principal.session_id))
    lease = store.claim(job_id)
    assert lease.expires_at == clock() + 5
    clock.value += 5
    assert_code(JobCode.BLOCKED, lambda: store.renew(lease))
    assert_code(JobCode.BLOCKED, lambda: store.claim(job_id))


def test_reclaims_are_bounded_and_do_not_extend_deadline(setup):
    database, store, clock, *_ = setup
    job_id = register(setup)
    lease = store.claim(job_id)
    deadline = row(database, job_id)["deadline_at"]
    for _ in range(2):
        clock.value = lease.expires_at
        lease = store.claim(job_id)
    clock.value = lease.expires_at
    assert_code(JobCode.EXHAUSTED, lambda: store.claim(job_id))
    assert row(database, job_id)["deadline_at"] == deadline


def test_reclaim_at_run_deadline_and_backward_clock_fail_closed(setup):
    database, store, clock, *_ = setup
    job_id = register(setup)
    lease = store.claim(job_id)
    started = clock()
    clock.value -= 1
    assert_code(JobCode.STALE, lambda: store.renew(lease))
    assert_code(JobCode.OWNED, lambda: store.claim(job_id))
    clock.value = started + 180
    assert_code(JobCode.DEADLINE, lambda: store.claim(job_id))
    assert row(database, job_id)["lease_epoch"] == 1


@pytest.mark.parametrize("change", [{"epoch": 0}, {"epoch": True}, {"epoch": 2}, {"owner": "f" * 64},
    {"owner": "secret-nonascii-\u2603"}, {"run_id": "run_1_a"}, {"session_id": "foreign"}])
def test_forged_or_stale_lease_rejected(setup, change):
    _, store, *_ = setup
    job_id = register(setup)
    lease = store.claim(job_id)
    assert_code(JobCode.STALE, lambda: store.renew(replace(lease, **change)))


def test_ordered_transitions_require_current_epoch_evidence_and_no_replay(setup):
    database, store, *_ = setup
    job_id = register(setup)
    lease = store.claim(job_id)
    proof = evidence(store.manifest(lease))
    assert_code(JobCode.STATE, lambda: store.advance(lease, State.CREATED, State.READY_FOR_EXECUTION))
    store.advance(lease, State.CREATED, State.RECEIVING)
    before = count_events(database)
    assert_code(JobCode.STATE, lambda: store.advance(lease, State.CREATED, State.RECEIVING))
    assert count_events(database) == before
    for bad in (None, replace(proof, sha256="e" * 64), replace(proof, received_bytes=True),
            replace(proof, job_id="e" * 32), replace(proof, lease_epoch=2)):
        assert_code(JobCode.EVIDENCE, lambda: store.advance(lease, State.RECEIVING, State.INPUT_VERIFIED, bad))
    store.advance(lease, State.RECEIVING, State.INPUT_VERIFIED, proof)
    store.advance(lease, State.INPUT_VERIFIED, State.READY_FOR_EXECUTION)
    before = count_events(database)
    assert_code(JobCode.STATE, lambda: store.advance(lease, State.INPUT_VERIFIED, State.READY_FOR_EXECUTION))
    assert_code(JobCode.STATE, lambda: store.claim(job_id))
    assert count_events(database) == before
    record = row(database, job_id)
    assert record["prep_state"] == "READY_FOR_EXECUTION" and record["state"] == "QUEUED"
    assert record["lease_owner"] is None and record["prep_verified_epoch"] == 1
    assert SandboxPolicy().execution_enabled is False


@pytest.mark.parametrize("crash_state", [State.CREATED, State.RECEIVING, State.INPUT_VERIFIED])
def test_restart_revalidates_from_start_and_rejects_old_frames(setup, crash_state):
    database, store, clock, *_ = setup
    job_id = register(setup)
    lease = store.claim(job_id)
    old = store.manifest(lease)
    if crash_state is not State.CREATED:
        store.advance(lease, State.CREATED, State.RECEIVING)
    if crash_state is State.INPUT_VERIFIED:
        store.advance(lease, State.RECEIVING, State.INPUT_VERIFIED, evidence(old))
    clock.value = lease.expires_at
    restarted = JobStore(Database(setup[-1], clock=clock))
    fresh = restarted.claim(job_id)
    assert row(database, job_id)["prep_verified_epoch"] is None
    manifest = restarted.manifest(fresh)
    transport = FakeTransport([encode_frame(old, 0, SYNTHETIC_PAYLOAD), None])
    result = prepare_synthetic(restarted, fresh, manifest.to_bytes(), transport)
    assert result.persisted_state == "FAILED" and transport.reads == 1
    assert row(database, job_id)["prep_state"] == "FAILED"


def test_successful_fake_preparation_commits_all_stages_without_holding_io_transaction(setup):
    database, store, _, first, *_ = setup
    job_id = register(setup)
    lease = store.claim(job_id)
    manifest = store.manifest(lease)
    def independent_write():
        with database.transaction() as connection:
            connection.execute("UPDATE runs SET state_version=state_version+1 WHERE run_id='run_0_b'")
    transport = FakeTransport([encode_frame(manifest, 0, SYNTHETIC_PAYLOAD), None], independent_write)
    result = prepare_synthetic(store, lease, manifest.to_bytes(), transport)
    assert result.persisted_state == "READY_FOR_EXECUTION"
    assert result.execution_enabled is False and result.simulation.cleanup_verified is False
    assert transport.closes == 1 and store.snapshot(first.principal, job_id).execution_enabled is False
    assert_code(JobCode.STATE, lambda: prepare_synthetic(store, lease, manifest.to_bytes(), FakeTransport([])))


def test_different_jobs_with_same_payload_cannot_exchange_frames(setup):
    database, store, _, first, *_ = setup
    first_job = register(setup)
    second_job = store.register(first.principal, "run_0_b")
    first_lease, second_lease = store.claim(first_job), store.claim(second_job)
    first_manifest, second_manifest = store.manifest(first_lease), store.manifest(second_lease)
    transport = FakeTransport([encode_frame(first_manifest, 0, SYNTHETIC_PAYLOAD), None])
    result = prepare_synthetic(store, second_lease, second_manifest.to_bytes(), transport)
    assert result.persisted_state == "FAILED"
    assert row(database, first_job)["prep_state"] == "CREATED"
    assert row(database, second_job)["prep_state"] == "FAILED"


def test_late_revocation_after_verified_input_still_blocks_readiness(setup):
    database, store, _, first, _, service, _ = setup
    job_id = register(setup)
    lease = store.claim(job_id)
    manifest = store.manifest(lease)
    class RevokingClose(FakeTransport):
        def close(self):
            assert row(database, job_id)["prep_state"] == "INPUT_VERIFIED"
            service.revoke(first.credential, first.principal.session_id)
            super().close()
    transport = RevokingClose([encode_frame(manifest, 0, SYNTHETIC_PAYLOAD), None])
    assert_code(JobCode.BLOCKED, lambda: prepare_synthetic(store, lease, manifest.to_bytes(), transport))
    assert row(database, job_id)["prep_state"] == "CANCELLED" and transport.closes == 1


def test_process_crash_during_preparation_keeps_recoverable_committed_state(setup):
    database, store, clock, *_ = setup
    job_id = register(setup)
    lease = store.claim(job_id)
    manifest = store.manifest(lease)
    def crash():
        raise KeyboardInterrupt()
    transport = FakeTransport([], crash)
    with pytest.raises(KeyboardInterrupt):
        prepare_synthetic(store, lease, manifest.to_bytes(), transport)
    assert row(database, job_id)["prep_state"] == "RECEIVING" and transport.closes == 1
    clock.value = lease.expires_at
    successor = JobStore(Database(setup[-1], clock=clock)).claim(job_id)
    fresh = store.manifest(successor)
    result = prepare_synthetic(store, successor, fresh.to_bytes(),
        FakeTransport([encode_frame(fresh, 0, SYNTHETIC_PAYLOAD), None]))
    assert result.persisted_state == "READY_FOR_EXECUTION" and successor.epoch == 2


@pytest.mark.parametrize("delivery", ["duplicate_frame", "missing_frame", "interrupted", "wrong_manifest"])
def test_fake_delivery_failures_never_persist_ready(setup, delivery):
    database, store, *_ = setup
    job_id = register(setup)
    lease = store.claim(job_id)
    manifest = store.manifest(lease)
    frame = encode_frame(manifest, 0, SYNTHETIC_PAYLOAD)
    chunks = [frame, frame, None] if delivery == "duplicate_frame" else [None]
    def interrupt():
        raise InterruptedError("private transport text")
    transport = FakeTransport(chunks, interrupt if delivery == "interrupted" else None)
    result = prepare_synthetic(store, lease, b"{}" if delivery == "wrong_manifest" else manifest.to_bytes(), transport)
    assert result.persisted_state in ("FAILED", "INTERRUPTED")
    assert row(database, job_id)["prep_state"] == result.persisted_state
    assert "private" not in repr(result)


def test_revocation_during_io_cancels_durably_and_does_not_extend_cleanup(setup):
    database, store, clock, first, _, service, _ = setup
    job_id = register(setup)
    lease = store.claim(job_id)
    manifest = store.manifest(lease)
    transport = FakeTransport([encode_frame(manifest, 0, SYNTHETIC_PAYLOAD), None],
        lambda: service.revoke(first.credential, first.principal.session_id))
    assert_code(JobCode.BLOCKED, lambda: prepare_synthetic(store, lease, manifest.to_bytes(), transport))
    assert row(database, job_id)["prep_state"] == "CANCELLED"
    assert_code(JobCode.BLOCKED, lambda: store.claim(job_id))
    with database.transaction() as connection:
        receipt = service.lifecycle.request_cleanup(connection, first.principal.session_id, reason="REVOKED", now=clock())
    with database.connection() as connection:
        cleanup = connection.execute("SELECT * FROM cleanup_requests WHERE request_id=?", (receipt,)).fetchone()
        assert cleanup["deadline_at"] == clock() + 300 and cleanup["state"] == "PENDING"


def test_expiry_during_io_rejects_transition_then_coordinator_cancels(setup):
    database, store, clock, first, _, service, _ = setup
    job_id = register(setup)
    lease = store.claim(job_id)
    manifest = store.manifest(lease)
    transport = FakeTransport([encode_frame(manifest, 0, SYNTHETIC_PAYLOAD), None],
        lambda: setattr(clock, "value", first.principal.expires_at))
    assert_code(JobCode.BLOCKED, lambda: prepare_synthetic(store, lease, manifest.to_bytes(), transport))
    service.lifecycle._discover_and_recover()
    assert row(database, job_id)["prep_state"] == "CANCELLED"


@pytest.mark.parametrize("iteration", range(5))
def test_cancellation_racing_renewal_is_irreversible(setup, iteration):
    database, store, clock, first, *_ = setup
    job_id = register(setup)
    lease = store.claim(job_id)
    clock.value += 1
    gate = Barrier(2)
    def renew():
        gate.wait(timeout=5)
        try:
            return store.renew(lease)
        except JobError as error:
            return error.code
    def cancel():
        gate.wait(timeout=5)
        store.cancel(first.principal, job_id)
    with ThreadPoolExecutor(max_workers=2) as workers:
        renewal = workers.submit(renew)
        cancellation = workers.submit(cancel)
        renewal.result(timeout=5)
        cancellation.result(timeout=5)
    record = row(database, job_id)
    assert record["prep_state"] == "CANCELLED" and record["lease_owner"] is None
    before = count_events(database)
    store.cancel(first.principal, job_id)
    assert count_events(database) == before
    assert_code(JobCode.BLOCKED, lambda: store.renew(lease))


@pytest.mark.parametrize("operation", ["registration", "claim", "transition", "renewal"])
def test_transaction_failure_rolls_back_state_and_audit(setup, monkeypatch, operation):
    database, store, clock, first, *_ = setup
    job_id = None if operation == "registration" else register(setup)
    lease = store.claim(job_id) if operation in ("transition", "renewal") else None
    clock.value += 1
    before = row(database, job_id) if job_id else None
    events = count_events(database)
    def broken(*args, **kwargs):
        raise sqlite3.OperationalError("private SQL path token")
    monkeypatch.setattr(database, "append_audit_event", broken)
    callbacks = {"registration": lambda: store.register(first.principal, "run_0_a"),
        "claim": lambda: store.claim(job_id),
        "transition": lambda: store.advance(lease, State.CREATED, State.RECEIVING),
        "renewal": lambda: store.renew(lease)}
    assert_code(JobCode.DATABASE_FAILURE, callbacks[operation])
    assert count_events(database) == events
    if job_id:
        assert row(database, job_id) == before
    else:
        with database.connection() as connection:
            assert connection.execute("SELECT runner_job_id FROM runs WHERE run_id='run_0_a'").fetchone()[0] is None


def test_commit_boundary_failure_is_not_reported_as_success(setup, monkeypatch):
    database, store, *_ = setup
    job_id = register(setup)
    original = database.transaction
    @contextmanager
    def broken_commit():
        with original() as connection:
            yield connection
            raise sqlite3.OperationalError("simulated commit failure")
    monkeypatch.setattr(database, "transaction", broken_commit)
    assert_code(JobCode.DATABASE_FAILURE, lambda: store.claim(job_id))
    assert row(database, job_id)["lease_epoch"] == 0


def test_locked_database_is_visible_without_unbounded_retry(setup):
    database, store, *_ = setup
    job_id = register(setup)
    with database.transaction():
        assert_code(JobCode.DATABASE_BUSY, lambda: store.claim(job_id))
    assert row(database, job_id)["lease_epoch"] == 0
    assert store.claim(job_id).epoch == 1


def test_ready_commit_failure_keeps_input_verified_and_never_returns_ready(setup, monkeypatch):
    database, store, *_ = setup
    job_id = register(setup)
    lease = store.claim(job_id)
    manifest = store.manifest(lease)
    original = database.append_audit_event
    def fail_ready(connection, **kwargs):
        state = connection.execute("SELECT prep_state FROM runs WHERE runner_job_id=?", (job_id,)).fetchone()[0]
        if state == "READY_FOR_EXECUTION":
            raise sqlite3.OperationalError("private transition failure")
        return original(connection, **kwargs)
    monkeypatch.setattr(database, "append_audit_event", fail_ready)
    transport = FakeTransport([encode_frame(manifest, 0, SYNTHETIC_PAYLOAD), None])
    assert_code(JobCode.DATABASE_FAILURE, lambda: prepare_synthetic(store, lease, manifest.to_bytes(), transport))
    assert row(database, job_id)["prep_state"] == "INPUT_VERIFIED" and transport.closes == 1


@pytest.mark.parametrize("terminal", ["FAILED", "TIMED_OUT", "INTERRUPTED", "BLOCKED_EXTERNAL", "CANCELLED"])
def test_terminal_jobs_cannot_restart_or_be_recreated(setup, terminal):
    database, store, clock, first, *_ = setup
    job_id = register(setup)
    lease = store.claim(job_id)
    store.fail(lease, terminal)
    clock.value += 10
    assert_code(JobCode.STATE, lambda: store.claim(job_id))
    assert_code(JobCode.DUPLICATE, lambda: store.register(first.principal, "run_0_a"))
    with pytest.raises(sqlite3.IntegrityError):
        with database.transaction() as connection:
            connection.execute("UPDATE runs SET prep_state='CREATED' WHERE runner_job_id=?", (job_id,))


@pytest.mark.parametrize("blocked_external", [False, True])
def test_cleanup_failure_and_restart_preserve_unresolved_evidence(setup, blocked_external):
    import asyncio
    database, store, clock, first, _, service, settings = setup
    job_id = register(setup)
    lease = store.claim(job_id)
    if blocked_external:
        store.fail(lease, "BLOCKED_EXTERNAL")
    receipt = service.revoke(first.credential, first.principal.session_id)
    coordinator = LifecycleCoordinator(database, settings)
    asyncio.run(coordinator.run_once())
    with database.connection() as connection:
        record = dict(connection.execute("SELECT * FROM cleanup_requests WHERE request_id=?", (receipt,)).fetchone())
    assert record["state"] == "BLOCKED" and record["failure_recorded"] == 1
    assert record["last_error_code"] == ("RUNNER_REQUIRED" if blocked_external else "STORAGE_REQUIRED")
    assert record["deadline_at"] == clock() + 300
    restarted = LifecycleCoordinator(Database(settings, clock=clock), settings)
    asyncio.run(restarted.run_once())
    with database.connection() as connection:
        current = dict(connection.execute("SELECT * FROM cleanup_requests WHERE request_id=?", (receipt,)).fetchone())
    assert current == record
    assert row(database, job_id)["prep_state"] == ("BLOCKED_EXTERNAL" if blocked_external else "CANCELLED")


def test_populated_v4_migrates_without_reset_or_prior_migration_edits(tmp_path, monkeypatch):
    import backend.storage.database as module
    settings = Settings(_env_file=None, database_path=tmp_path / "old.sqlite3")
    database = Database(settings)
    with monkeypatch.context() as patch:
        patch.setattr(module, "SCHEMA_VERSION", 4)
        database.initialize()
        with database.transaction() as connection:
            connection.execute("INSERT INTO sessions(session_id,auth_token_hash,audit_pseudonym) VALUES ('old',?,'old')", ("a" * 64,))
            connection.execute("INSERT INTO audit_events(event_id,session_pseudonym,event_type,build_version) VALUES ('old','old','SESSION_CREATED','test')")
            connection.execute("""INSERT INTO datasets(dataset_id,session_id,source_sha256,storage_ref,file_type,
                byte_count,idempotency_key,request_sha256) VALUES ('old','old',?,'fixture','csv',1,'old',?)""", ("a" * 64, "b" * 64))
            connection.execute("INSERT INTO dataset_versions(dataset_id,version,session_id) VALUES ('old',1,'old')")
            connection.execute("""INSERT INTO runs(run_id,session_id,dataset_id,dataset_version,question,
                idempotency_key,request_sha256) VALUES ('old','old','old',1,'Sample','old',?)""", ("c" * 64,))
            connection.execute("""INSERT INTO attempts(attempt_id,run_id,candidate_version,code_ref,code_sha256)
                VALUES ('old','old',1,'fixture',?)""", ("d" * 64,))
    database.initialize()
    database.initialize()
    database.check_ready(full_integrity=True)
    with database.connection() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 5
        assert connection.execute("SELECT session_id FROM sessions").fetchone()[0] == "old"
        assert connection.execute("SELECT event_id FROM audit_events").fetchone()[0] == "old"
        assert connection.execute("SELECT dataset_id FROM datasets").fetchone()[0] == "old"
        assert connection.execute("SELECT attempt_id FROM attempts").fetchone()[0] == "old"
        run = connection.execute("SELECT * FROM runs").fetchone()
        assert run["state"] == "PLAN_AND_CODE" and run["runner_job_id"] is None and run["lease_epoch"] == 0
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_v5_failure_rolls_back_columns_and_version(tmp_path, monkeypatch):
    import backend.storage.database as module
    database = Database(Settings(_env_file=None, database_path=tmp_path / "old.sqlite3"))
    with monkeypatch.context() as patch:
        patch.setattr(module, "SCHEMA_VERSION", 4)
        database.initialize()
    with monkeypatch.context() as patch:
        patch.setitem(MIGRATIONS, 5, (*MIGRATIONS[5], "INVALID SQL"))
        with pytest.raises(sqlite3.OperationalError):
            database.initialize()
    with sqlite3.connect(database.path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 4
        assert "runner_job_id" not in {column[1] for column in connection.execute("PRAGMA table_info(runs)")}
    database.initialize()
    database.check_ready(full_integrity=True)
