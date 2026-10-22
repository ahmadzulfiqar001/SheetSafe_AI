"""Controlled-clock retention tests; storage verification fixtures are test-only."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from pathlib import Path
import sqlite3
from threading import Event
import time

from fastapi.testclient import TestClient
import pytest

from backend.config import Settings
from backend.main import create_app
from backend.security.lifecycle import (
    CleanupVerification, LifecycleCoordinator, RetryableCleanupError, _LeaseLost,
)
from backend.security.sessions import SessionError, SessionService
from backend.storage.database import Database, DatabaseReadinessError


@pytest.fixture
def environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    clock = [int(time.time())]
    monkeypatch.setattr("backend.security.sessions.utc_now", lambda: clock[0])
    settings = Settings(
        _env_file=None, environment="test", database_path=tmp_path / "retention.sqlite3",
        database_busy_timeout_ms=25, allowed_origins=("https://testserver",),
        cleanup_adapter_timeout_seconds=0.01,
    )
    database = Database(settings, clock=lambda: clock[0])
    database.initialize()
    coordinator = LifecycleCoordinator(database, settings)
    service = SessionService(database, settings, coordinator)
    return clock, settings, database, coordinator, service


def job_row(database: Database, session_id: str):
    with database.connection() as connection:
        row = connection.execute("SELECT * FROM cleanup_requests WHERE session_id=?", (session_id,)).fetchone()
        return dict(row) if row is not None else None


def table_count(database: Database, table: str) -> int:
    # Table is a fixed test constant, never request input.
    with database.connection() as connection:
        return connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def register_dataset(database: Database, session_id: str, *, run: bool = False, runtime: bool = False) -> None:
    with database.transaction() as connection:
        connection.execute(
            """INSERT INTO datasets(dataset_id, session_id, source_sha256, storage_ref, file_type,
                byte_count, idempotency_key, request_sha256, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("data_" + session_id, session_id, "a" * 64, "server_ref_" + session_id, "csv", 12,
             "upload", "b" * 64, database.now()),
        )
        connection.execute(
            "INSERT INTO dataset_versions(dataset_id, version, session_id, created_at) VALUES (?, 1, ?, ?)",
            ("data_" + session_id, session_id, database.now()),
        )
        if run or runtime:
            connection.execute(
                """INSERT INTO runs(run_id, session_id, dataset_id, dataset_version, question,
                    idempotency_key, request_sha256, state, created_at, updated_at)
                    VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?)""",
                ("run_" + session_id, session_id, "data_" + session_id, "synthetic private question",
                 "run", "c" * 64, "EXECUTE" if runtime else "PLAN_AND_CODE", database.now(), database.now()),
            )


class FixtureStorage:
    """Actually remove known synthetic files; no production storage adapter exists."""
    def __init__(self, root: Path, files: dict[str, Path]):
        self.root, self.files, self.calls = root.resolve(), files, []

    async def remove_and_verify(self, context):
        self.calls.append(context.session_id)
        source = self.files[context.session_id]
        assert source.resolve().is_relative_to(self.root)
        assert not source.is_symlink()
        source.unlink(missing_ok=True)
        return CleanupVerification(context.session_id, not source.exists())


def test_normal_expiry_reclaims_metadata_and_never_accepts_old_credential(environment) -> None:
    clock, _, database, coordinator, service = environment
    issued = service.create("192.0.2.1")
    clock[0] = issued.principal.expires_at
    with pytest.raises(SessionError) as error:
        service.authenticate(issued.credential)
    assert error.value.status_code == 401
    asyncio.run(coordinator.run_once())
    job = job_row(database, issued.principal.session_id)
    assert job["state"] == "COMPLETE"
    assert job["deadline_at"] == issued.principal.expires_at + 300
    assert job["storage_status"] == job["runtime_status"] == "NONE_REGISTERED"
    assert table_count(database, "sessions") == 0
    assert table_count(database, "cleanup_daily_metrics") == 1
    with pytest.raises(SessionError):
        service.authenticate(issued.credential)


def test_manual_request_and_cleanup_are_idempotent(environment) -> None:
    clock, _, database, coordinator, service = environment
    issued = service.create("192.0.2.1")
    receipt = service.revoke(issued.credential, issued.principal.session_id)
    clock[0] += 1
    with database.transaction() as connection:
        repeated = coordinator.request_cleanup(connection, issued.principal.session_id, reason="MANUAL", now=clock[0])
    assert repeated == receipt
    deadline = job_row(database, issued.principal.session_id)["deadline_at"]
    asyncio.run(coordinator.run_once())
    asyncio.run(coordinator.run_once())
    with database.transaction() as connection:
        assert coordinator.request_cleanup(connection, issued.principal.session_id, reason="MANUAL", now=clock[0]) == receipt
    job = job_row(database, issued.principal.session_id)
    assert job["deadline_at"] == deadline and job["attempts"] == 1
    with database.connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM audit_events WHERE event_type='CLEANUP_COMPLETED'").fetchone()[0] == 1
        assert connection.execute("SELECT value FROM cleanup_daily_metrics WHERE metric='COMPLETED'").fetchone()[0] == 1


def test_actual_fixture_storage_cleanup_is_scoped_and_verified(environment, tmp_path: Path) -> None:
    _, _, database, coordinator, service = environment
    first, second = service.create("192.0.2.1"), service.create("192.0.2.2")
    files = {}
    for issued in (first, second):
        owner = issued.principal.session_id
        register_dataset(database, owner, run=True)
        files[owner] = tmp_path / (owner + ".csv")
        files[owner].write_text("synthetic fixture\n", encoding="utf-8")
    coordinator.storage = FixtureStorage(tmp_path, files)
    service.revoke(first.credential, first.principal.session_id)
    asyncio.run(coordinator.run_once())
    assert not files[first.principal.session_id].exists()
    assert files[second.principal.session_id].exists()
    assert job_row(database, first.principal.session_id)["storage_status"] == "VERIFIED"
    assert table_count(database, "sessions") == table_count(database, "datasets") == table_count(database, "runs") == 1
    assert service.authenticate(second.credential).session_id == second.principal.session_id
    with database.connection() as connection:
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


@pytest.mark.parametrize("runtime,expected", [(False, "STORAGE_REQUIRED"), (True, "RUNNER_REQUIRED")])
def test_missing_adapters_block_without_claiming_removal(environment, runtime: bool, expected: str) -> None:
    _, _, database, coordinator, service = environment
    issued = service.create("192.0.2.1")
    register_dataset(database, issued.principal.session_id, runtime=runtime)
    service.revoke(issued.credential, issued.principal.session_id)
    asyncio.run(coordinator.run_once())
    job = job_row(database, issued.principal.session_id)
    assert job["state"] == "BLOCKED" and job["last_error_code"] == expected
    assert job["completed_at"] is None
    assert table_count(database, "datasets") == table_count(database, "sessions") == 1
    with pytest.raises(SessionError) as error:
        service.create("192.0.2.2")
    assert error.value.status_code == 503


def test_unverified_or_wrong_owner_receipt_cannot_purge(environment) -> None:
    _, _, database, coordinator, service = environment
    issued = service.create("192.0.2.1")

    class WrongOwner:
        async def remove_and_verify(self, context):
            return CleanupVerification("different_session", True)

    coordinator.storage = WrongOwner()
    service.revoke(issued.credential, issued.principal.session_id)
    asyncio.run(coordinator.run_once())
    assert job_row(database, issued.principal.session_id)["last_error_code"] == "UNVERIFIED"
    assert table_count(database, "sessions") == 1


def test_transient_retry_can_recover_but_never_restores_access(environment, tmp_path: Path) -> None:
    clock, _, database, coordinator, service = environment
    issued = service.create("192.0.2.1")
    path = tmp_path / "owned.csv"
    path.write_text("synthetic", encoding="utf-8")
    register_dataset(database, issued.principal.session_id)

    class TransientStorage(FixtureStorage):
        async def remove_and_verify(self, context):
            if not self.calls:
                self.calls.append("transient_failure")
                raise RetryableCleanupError("synthetic private error")
            return await super().remove_and_verify(context)

    coordinator.storage = TransientStorage(tmp_path, {issued.principal.session_id: path})
    service.revoke(issued.credential, issued.principal.session_id)
    asyncio.run(coordinator.run_once())
    assert job_row(database, issued.principal.session_id)["state"] == "RETRY"
    assert path.exists()
    with pytest.raises(SessionError):
        service.authenticate(issued.credential)
    clock[0] += 3
    asyncio.run(coordinator.run_once())
    assert job_row(database, issued.principal.session_id)["state"] == "COMPLETE"
    assert not path.exists()


def test_adapter_timeout_retry_budget_is_bounded(environment) -> None:
    clock, settings, database, _, _ = environment
    limited = settings.model_copy(update={"cleanup_max_attempts": 2})
    coordinator = LifecycleCoordinator(database, limited)
    service = SessionService(database, limited, coordinator)
    issued = service.create("192.0.2.1")

    class SlowStorage:
        async def remove_and_verify(self, context):
            await asyncio.sleep(10)

    coordinator.storage = SlowStorage()
    service.revoke(issued.credential, issued.principal.session_id)
    asyncio.run(coordinator.run_once())
    assert job_row(database, issued.principal.session_id)["last_error_code"] == "ADAPTER_TIMEOUT"
    clock[0] += 3
    asyncio.run(coordinator.run_once())
    job = job_row(database, issued.principal.session_id)
    assert job["state"] == "BLOCKED" and job["last_error_code"] == "RETRY_EXHAUSTED"
    clock[0] += 100
    asyncio.run(coordinator.run_once())
    assert job_row(database, issued.principal.session_id)["attempts"] == 2
    assert not coordinator.resume_blocked(job["request_id"])


def test_resume_after_installing_storage_keeps_admissions_paused_until_verified(environment, tmp_path: Path) -> None:
    _, _, database, coordinator, service = environment
    issued = service.create("192.0.2.1")
    register_dataset(database, issued.principal.session_id)
    service.revoke(issued.credential, issued.principal.session_id)
    asyncio.run(coordinator.run_once())
    job = job_row(database, issued.principal.session_id)
    path = tmp_path / "owned.csv"
    path.write_text("synthetic", encoding="utf-8")
    coordinator.storage = FixtureStorage(tmp_path, {issued.principal.session_id: path})
    assert coordinator.resume_blocked(job["request_id"])
    with database.connection() as connection:
        assert coordinator.admissions_paused(connection)
    asyncio.run(coordinator.run_once())
    assert job_row(database, issued.principal.session_id)["state"] == "COMPLETE"
    with database.connection() as connection:
        assert not coordinator.admissions_paused(connection)


def test_request_transaction_failure_does_not_partially_revoke(environment, monkeypatch: pytest.MonkeyPatch) -> None:
    _, _, database, _, service = environment
    issued = service.create("192.0.2.1")

    def fail(*args, **kwargs):
        raise sqlite3.OperationalError("synthetic private detail")

    monkeypatch.setattr(database, "append_audit_event", fail)
    with pytest.raises(SessionError) as error:
        service.revoke(issued.credential, issued.principal.session_id)
    assert error.value.status_code == 503
    assert table_count(database, "cleanup_requests") == 0
    assert service.authenticate(issued.credential).session_id == issued.principal.session_id


def test_database_purge_failure_rolls_back_and_retries(environment) -> None:
    clock, _, database, coordinator, service = environment
    issued = service.create("192.0.2.1")
    service.revoke(issued.credential, issued.principal.session_id)
    with database.transaction() as connection:
        connection.execute("""CREATE TRIGGER fixture_failure BEFORE DELETE ON sessions
            BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END""")
    asyncio.run(coordinator.run_once())
    assert job_row(database, issued.principal.session_id)["state"] == "RETRY"
    assert table_count(database, "sessions") == 1
    with database.transaction() as connection:
        connection.execute("DROP TRIGGER fixture_failure")
    clock[0] += 3
    asyncio.run(coordinator.run_once())
    assert job_row(database, issued.principal.session_id)["state"] == "COMPLETE"


def test_checkpoint_waits_for_real_reader_and_recovers(environment) -> None:
    clock, _, database, coordinator, service = environment
    issued = service.create("192.0.2.1")
    with database.connection() as reader:
        reader.execute("SELECT * FROM sessions").fetchall()  # Pins old WAL snapshot.
        service.revoke(issued.credential, issued.principal.session_id)
        with pytest.raises(DatabaseReadinessError):
            asyncio.run(coordinator.run_once())
        job = job_row(database, issued.principal.session_id)
        assert job["phase"] == "CHECKPOINT" and job["state"] == "RETRY"
        assert job["completed_at"] is None
        assert table_count(database, "sessions") == 0
    clock[0] += 3
    asyncio.run(coordinator.run_once())
    assert job_row(database, issued.principal.session_id)["state"] == "COMPLETE"
    assert issued.principal.auth_token_hash.encode() not in database.path.read_bytes()


def test_restart_recovers_expired_lease_and_stale_owner_cannot_complete(environment) -> None:
    clock, settings, database, coordinator, service = environment
    issued = service.create("192.0.2.1")
    service.revoke(issued.credential, issued.principal.session_id)
    old_claim = coordinator._claim()
    clock[0] += 31
    recovered = LifecycleCoordinator(database, settings)
    asyncio.run(recovered.run_once())
    assert job_row(database, issued.principal.session_id)["state"] == "COMPLETE"
    with pytest.raises(_LeaseLost):
        coordinator._complete(old_claim)
    assert table_count(database, "cleanup_daily_metrics") == 1


def test_concurrent_delete_and_internal_requests_have_one_durable_receipt(environment) -> None:
    clock, _, database, coordinator, service = environment
    issued = service.create("192.0.2.1")

    def revoke(_):
        try:
            return service.revoke(issued.credential, issued.principal.session_id)
        except SessionError as error:
            return error.status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(revoke, range(2)))
    assert outcomes.count(401) == 1
    assert table_count(database, "cleanup_requests") == 1

    def repeat(_):
        with database.transaction() as connection:
            return coordinator.request_cleanup(connection, issued.principal.session_id, reason="MANUAL", now=clock[0])

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert len(set(pool.map(repeat, range(2)))) == 1
    assert table_count(database, "audit_events") == 3


@pytest.mark.parametrize("pin_reader", [False, True], ids=["competing-checkpoints", "pinned-reader"])
def test_competing_coordinators_cannot_double_complete(
    environment, pin_reader: bool, monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock, settings, database, coordinator, service = environment
    issued = service.create("192.0.2.1")
    service.revoke(issued.credential, issued.principal.session_id)
    deadline = job_row(database, issued.principal.session_id)["deadline_at"]
    database_errors = []

    # Observe and re-raise real errors. A retry must never conceal corruption,
    # invalid SQL, I/O failures or other errors unrelated to this contention test.
    def observe_scope(manager):
        @contextmanager
        def scope():
            try:
                with manager() as connection:
                    yield connection
            except sqlite3.Error as error:
                database_errors.append(error)
                raise
        return scope

    checkpoint = database.verify_checkpoint

    def observe_checkpoint():
        try:
            checkpoint()
        except sqlite3.Error as error:
            database_errors.append(error)
            raise

    monkeypatch.setattr(database, "transaction", observe_scope(database.transaction))
    monkeypatch.setattr(database, "connection", observe_scope(database.connection))
    monkeypatch.setattr(database, "verify_checkpoint", observe_checkpoint)

    async def compete():
        return await asyncio.gather(coordinator.run_once(), LifecycleCoordinator(database, settings).run_once(),
                                    return_exceptions=True)

    with ExitStack() as resources:
        if pin_reader:
            # Real SQLite snapshot, not a mocked checkpoint error. Keep the old
            # frames pinned until both coordinators have finished their sweeps.
            reader = resources.enter_context(database.connection())
            reader.execute("SELECT * FROM sessions").fetchall()
        results = asyncio.run(compete())
    assert all(result is None or isinstance(result, (DatabaseReadinessError, sqlite3.OperationalError)) for result in results)
    assert all((error.sqlite_errorcode & 0xFF) == sqlite3.SQLITE_BUSY for error in database_errors)
    pending = job_row(database, issued.principal.session_id)
    assert pending["state"] in {"COMPLETE", "PENDING", "RETRY", "RUNNING"}
    if pin_reader:
        assert pending["state"] != "COMPLETE"
        assert any(result is not None for result in results)
    due_at = None
    if pending["state"] == "RETRY":
        if pending["last_error_code"] == "CHECKPOINT_BUSY":
            assert pending["phase"] == "CHECKPOINT"
        else:
            assert pending["last_error_code"] == "DATABASE_FAILURE" and database_errors
        assert pending["attempts"] == 1 and pending["completed_at"] is None
        assert pending["lease_token"] is None and pending["lease_expires_at"] is None
        due_at = pending["next_attempt_at"]
        with database.connection() as connection:
            assert coordinator.admissions_paused(connection)
    elif pending["state"] == "RUNNING":
        # A busy writer can also prevent persisting _fail(). That exception must
        # remain visible; the existing fenced lease then governs crash recovery.
        assert any(isinstance(result, sqlite3.OperationalError) for result in results)
        assert database_errors and pending["attempts"] == 1
        assert pending["lease_token"] is not None
        due_at = pending["lease_expires_at"]
    elif pending["state"] == "PENDING":
        assert database_errors and pending["attempts"] == 0

    if pending["state"] != "COMPLETE":
        assert pending["completed_at"] is None
        with database.connection() as connection:
            assert connection.execute(
                "SELECT COUNT(*) FROM audit_events WHERE event_type='CLEANUP_COMPLETED'",
            ).fetchone()[0] == 0
        with pytest.raises(SessionError):
            service.authenticate(issued.credential)

    if due_at is not None:
        assert clock[0] < due_at < deadline
        # Clearing the lock waives neither durable backoff nor a live lease.
        # An early sweep cannot reclaim the job or consume another attempt.
        asyncio.run(coordinator.run_once())
        assert job_row(database, issued.principal.session_id) == pending
        clock[0] = due_at

    # A fresh coordinator models restart recovery at the exact eligible time.
    # One bounded sweep must complete after contention ends; no sleep/retry loop.
    recovered = LifecycleCoordinator(database, settings)
    asyncio.run(recovered.run_once())
    complete = job_row(database, issued.principal.session_id)
    assert complete["state"] == "COMPLETE" and complete["phase"] == "CHECKPOINT"
    assert complete["deadline_at"] == deadline and complete["completed_at"] < deadline
    assert complete["attempts"] <= 2
    assert complete["lease_token"] is None and complete["lease_expires_at"] is None
    if pending["state"] == "RUNNING":
        with pytest.raises(_LeaseLost):
            coordinator._complete(pending)  # The recovered lease retires its old owner.
    with pytest.raises(SessionError):
        service.authenticate(issued.credential)
    asyncio.run(coordinator.run_once())  # Completion must remain idempotent.
    with database.connection() as connection:
        assert connection.execute("SELECT value FROM cleanup_daily_metrics WHERE metric='COMPLETED'").fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM audit_events WHERE event_type='CLEANUP_COMPLETED'",
        ).fetchone()[0] == 1
        assert not recovered.admissions_paused(connection)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_deadline_miss_is_sticky_visible_and_counted_once(environment) -> None:
    clock, _, database, coordinator, service = environment
    issued = service.create("192.0.2.1")
    register_dataset(database, issued.principal.session_id)
    receipt = service.revoke(issued.credential, issued.principal.session_id)
    original_deadline = job_row(database, issued.principal.session_id)["deadline_at"]
    clock[0] = original_deadline + 1
    asyncio.run(coordinator.run_once())
    asyncio.run(coordinator.run_once())
    with database.transaction() as connection:
        assert coordinator.request_cleanup(connection, issued.principal.session_id, reason="MANUAL", now=clock[0]) == receipt
    job = job_row(database, issued.principal.session_id)
    assert job["deadline_at"] == original_deadline
    assert job["deadline_missed_at"] is not None and job["state"] == "BLOCKED"
    with database.connection() as connection:
        assert coordinator.admissions_paused(connection)
        assert connection.execute("SELECT value FROM cleanup_daily_metrics WHERE metric='DEADLINE_MISSED'").fetchone()[0] == 1


def test_bounded_batch_does_not_hide_overdue_undiscovered_sessions(environment) -> None:
    clock, settings, database, _, service = environment
    issued = [service.create(f"192.0.2.{i + 1}") for i in range(3)]
    clock[0] = issued[0].principal.expires_at + 301
    coordinator = LifecycleCoordinator(database, settings.model_copy(update={"cleanup_batch_size": 1}))
    asyncio.run(coordinator.run_once())
    assert table_count(database, "sessions") == 2
    with database.connection() as connection:
        assert coordinator.admissions_paused(connection)
    asyncio.run(coordinator.run_once())
    asyncio.run(coordinator.run_once())
    assert table_count(database, "sessions") == 0


def test_audit_and_receipt_retention_and_content_free_metric_expiry(environment) -> None:
    clock, _, database, coordinator, service = environment
    issued = service.create("192.0.2.1")
    service.revoke(issued.credential, issued.principal.session_id)
    asyncio.run(coordinator.run_once())
    with database.transaction() as connection:
        with pytest.raises(sqlite3.IntegrityError, match="retention"):
            connection.execute("DELETE FROM audit_events")
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute("UPDATE audit_events SET event_type='changed'")
    clock[0] += 86401
    asyncio.run(coordinator.run_once())
    assert table_count(database, "audit_events") == table_count(database, "cleanup_requests") == 0
    assert table_count(database, "cleanup_daily_metrics") == 1
    with database.connection() as connection:
        fields = {row[1] for row in connection.execute("PRAGMA table_info(cleanup_daily_metrics)")}
        assert fields == {"day_start", "metric", "value", "expires_at"}
    clock[0] += 30 * 86400
    asyncio.run(coordinator.run_once())
    assert table_count(database, "cleanup_daily_metrics") == 0


def test_failure_logs_and_status_never_store_credentials_or_private_content(environment, caplog) -> None:
    _, _, database, coordinator, service = environment
    issued = service.create("192.0.2.1")
    private = issued.credential + " synthetic.csv SELECT secret FROM private"

    class FailingAdapter:
        async def remove_and_verify(self, context):
            raise RuntimeError(private)

    coordinator.storage = FailingAdapter()
    service.revoke(issued.credential, issued.principal.session_id)
    asyncio.run(coordinator.run_once())
    assert private not in caplog.text and issued.credential not in caplog.text
    with database.connection() as connection:
        assert private not in "\n".join(connection.iterdump())
    assert job_row(database, issued.principal.session_id)["last_error_code"] == "ADAPTER_FAILURE"


def test_database_guards_reactivation_reassignment_and_publication(environment) -> None:
    clock, _, database, coordinator, service = environment
    first, second = service.create("192.0.2.1"), service.create("192.0.2.2")
    owner = first.principal.session_id
    register_dataset(database, owner, run=True)
    service.revoke(first.credential, owner)
    for query, parameters in (
        ("UPDATE sessions SET revoked_at=NULL WHERE session_id=?", (owner,)),
        ("UPDATE sessions SET deletion_requested_at=NULL WHERE session_id=?", (owner,)),
        ("UPDATE datasets SET session_id=? WHERE session_id=?", (second.principal.session_id, owner)),
        ("UPDATE runs SET state='COMPLETE', validation_status='PASSED', cleanup_status='CONFIRMED' WHERE session_id=?", (owner,)),
        ("UPDATE runs SET state='CANCELLED', question='new private content' WHERE session_id=?", (owner,)),
        ("UPDATE cleanup_requests SET deadline_at=? WHERE session_id=?", (clock[0] + 9999, owner)),
    ):
        with pytest.raises(sqlite3.IntegrityError):
            with database.transaction() as connection:
                connection.execute(query, parameters)
    asyncio.run(coordinator.run_once())  # Missing storage adapter preserves metadata.
    assert job_row(database, owner)["state"] == "BLOCKED"


def test_retired_session_id_cannot_be_reinserted_after_purge(environment) -> None:
    _, _, database, coordinator, service = environment
    issued = service.create("192.0.2.1")
    service.revoke(issued.credential, issued.principal.session_id)
    asyncio.run(coordinator.run_once())
    with pytest.raises(sqlite3.IntegrityError, match="retired"):
        with database.transaction() as connection:
            connection.execute(
                "INSERT INTO sessions(session_id, auth_token_hash, audit_pseudonym) VALUES (?, ?, ?)",
                (issued.principal.session_id, "a" * 64, "new_pseudonym"),
            )


def test_cleanup_schema_rejects_unrevoked_requests_and_unverified_success(environment) -> None:
    clock, _, database, coordinator, service = environment
    issued = service.create("192.0.2.1")
    with pytest.raises(sqlite3.IntegrityError, match="revoked"):
        with database.transaction() as connection:
            connection.execute(
                """INSERT INTO cleanup_requests(request_id, session_id, session_pseudonym, reason,
                    requested_at, deadline_at, next_attempt_at) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                ("invalid", issued.principal.session_id, issued.principal.audit_pseudonym, "MANUAL",
                 clock[0], clock[0] + 300, clock[0]),
            )
    service.revoke(issued.credential, issued.principal.session_id)
    with pytest.raises(sqlite3.IntegrityError):
        with database.transaction() as connection:
            connection.execute(
                """UPDATE cleanup_requests SET state='COMPLETE', completed_at=?, retain_until=?
                    WHERE session_id=?""", (clock[0], clock[0] + 86400, issued.principal.session_id),
            )


def test_application_restart_completes_durable_delete_and_stops_worker(tmp_path: Path) -> None:
    settings = Settings(_env_file=None, environment="test", database_path=tmp_path / "app.sqlite3",
                        allowed_origins=("https://testserver",), cleanup_interval_seconds=30)
    application = create_app(settings)
    with TestClient(application, base_url="https://testserver", client=("127.0.0.1", 1)) as client:
        data = client.post("/api/v1/sessions", json={}, headers={
            "Origin": "https://testserver", "X-SheetSafe-Request": "1",
        }).json()
        token = client.cookies.get("__Host-sheetsafe_session")
        response = client.delete("/api/v1/sessions/" + data["session_id"], headers={
            "Origin": "https://testserver", "X-CSRF-Token": data["csrf_token"],
        })
        assert response.status_code == 200
        task = application.state.cleanup_task
        assert job_row(application.state.database, data["session_id"])["state"] == "PENDING"
    assert task.done() and application.state.cleanup_task is None
    restarted = create_app(settings)
    with TestClient(restarted, base_url="https://testserver", client=("127.0.0.1", 1)) as client:
        assert job_row(restarted.state.database, data["session_id"])["state"] == "COMPLETE"
        assert client.get("/api/v1/ready").status_code == 200
        assert client.delete("/api/v1/sessions/" + data["session_id"], headers={
            "Origin": "https://testserver", "X-CSRF-Token": data["csrf_token"],
            "Cookie": "__Host-sheetsafe_session=" + token,
        }).status_code == 401


def test_background_cleanup_does_not_block_health_requests(tmp_path: Path, monkeypatch) -> None:
    entered, release = Event(), Event()
    original = LifecycleCoordinator._discover_and_recover
    calls = []

    def delayed(self):
        calls.append(1)
        if len(calls) == 2:
            entered.set()
            assert release.wait(timeout=3)
        original(self)

    monkeypatch.setattr(LifecycleCoordinator, "_discover_and_recover", delayed)
    settings = Settings(_env_file=None, database_path=tmp_path / "background.sqlite3", cleanup_interval_seconds=0.05)
    with TestClient(create_app(settings)) as client:
        try:
            assert entered.wait(timeout=2)
            assert client.get("/api/v1/health").status_code == 200
            assert client.get("/api/v1/ready").status_code == 200
        finally:
            release.set()


def test_periodic_worker_completes_delete_without_a_manual_sweep(tmp_path: Path) -> None:
    settings = Settings(_env_file=None, environment="test", database_path=tmp_path / "periodic.sqlite3",
                        allowed_origins=("https://testserver",), cleanup_interval_seconds=0.05)
    application = create_app(settings)
    with TestClient(application, base_url="https://testserver", client=("127.0.0.1", 1)) as client:
        response = client.post("/api/v1/sessions", json={}, headers={
            "Origin": "https://testserver", "X-SheetSafe-Request": "1",
        })
        assert response.status_code == 201
        data = response.json()
        assert client.delete("/api/v1/sessions/" + data["session_id"], headers={
            "Origin": "https://testserver", "X-CSRF-Token": data["csrf_token"],
        }).status_code == 200
        deadline = time.monotonic() + 3
        while job_row(application.state.database, data["session_id"])["state"] != "COMPLETE":
            assert time.monotonic() < deadline
            time.sleep(0.01)
        assert table_count(application.state.database, "sessions") == 0


def test_background_sweep_failure_is_sanitized_and_recovers(environment, monkeypatch, caplog) -> None:
    _, settings, database, coordinator, _ = environment
    coordinator.settings = settings.model_copy(update={"cleanup_interval_seconds": 0.05})
    original = coordinator._discover_and_recover
    calls = []

    def transient_failure():
        calls.append(1)
        if len(calls) == 2:
            raise sqlite3.OperationalError("synthetic-private-detail SELECT secret FROM private")
        original()

    monkeypatch.setattr(coordinator, "_discover_and_recover", transient_failure)

    async def exercise():
        await coordinator.run_once()
        stop = asyncio.Event()
        task = asyncio.create_task(coordinator.serve(stop))
        try:
            deadline = time.monotonic() + 3
            while len(calls) < 3 or not coordinator.last_sweep_ok:
                assert time.monotonic() < deadline
                await asyncio.sleep(0.01)
        finally:
            stop.set()
            await task

    asyncio.run(exercise())
    assert coordinator.last_sweep_ok and not coordinator.running
    assert "COORDINATOR_FAILURE" in caplog.text
    assert "synthetic-private-detail" not in caplog.text


def test_v3_migration_failure_preserves_v2_session_metadata(tmp_path: Path, monkeypatch) -> None:
    from backend.storage.schema import APPLICATION_ID, MIGRATIONS, SCHEMA_VERSION

    path = tmp_path / "upgrade.sqlite3"
    connection = sqlite3.connect(path)
    try:
        for version in (1, 2):
            for statement in MIGRATIONS[version]:
                connection.execute(statement)
        connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
        connection.execute("PRAGMA user_version=2")
        connection.execute(
            "INSERT INTO sessions(session_id, auth_token_hash, audit_pseudonym) VALUES (?, ?, ?)",
            ("existing", "a" * 64, "existing_pseudonym"),
        )
        connection.commit()
    finally:
        connection.close()
    database = Database(Settings(_env_file=None, database_path=path))
    with monkeypatch.context() as patch:
        patch.setitem(MIGRATIONS, 3, (*MIGRATIONS[3], "INVALID MIGRATION SQL"))
        with pytest.raises(sqlite3.OperationalError):
            database.initialize()
    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        assert connection.execute("SELECT session_id FROM sessions").fetchone()[0] == "existing"
        assert connection.execute("SELECT 1 FROM sqlite_schema WHERE name='cleanup_requests'").fetchone() is None
    finally:
        connection.close()
    database.initialize()
    with database.connection() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        assert connection.execute("SELECT session_id FROM sessions").fetchone()[0] == "existing"
