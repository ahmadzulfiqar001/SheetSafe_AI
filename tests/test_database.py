"""Real on-disk SQLite tests; every fixture uses isolated temporary storage."""

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sqlite3
from threading import Event
import time

import pytest

from backend.config import Settings
from backend.storage.database import Database, DatabaseVersionError
from backend.storage.schema import APPLICATION_ID, MIGRATIONS, SCHEMA_VERSION


@pytest.fixture
def database(tmp_path: Path) -> Database:
    store = Database(Settings(
        _env_file=None, database_path=tmp_path / "private" / "metadata.sqlite3",
        database_busy_timeout_ms=100,
    ))
    store.initialize()
    return store


def add_session(connection: sqlite3.Connection, suffix: str = "a") -> None:
    connection.execute(
        "INSERT INTO sessions(session_id, auth_token_hash, audit_pseudonym) VALUES (?, ?, ?)",
        (f"session_{suffix}", suffix * 64, f"pseudonym_{suffix}"),
    )


def add_dataset(connection: sqlite3.Connection) -> None:
    connection.execute(
        """INSERT INTO datasets(dataset_id, session_id, source_sha256, storage_ref,
            file_type, byte_count, idempotency_key, request_sha256)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        ("dataset_a", "session_a", "a" * 64, "private/input_a", "csv", 128, "upload_a", "b" * 64),
    )
    connection.execute(
        "INSERT INTO dataset_versions(dataset_id, version, session_id) VALUES (?, ?, ?)",
        ("dataset_a", 1, "session_a"),
    )


def add_run(connection: sqlite3.Connection, owner: str = "session_a") -> None:
    connection.execute(
        """INSERT INTO runs(run_id, session_id, dataset_id, dataset_version,
            question, idempotency_key, request_sha256) VALUES (?, ?, ?, ?, ?, ?, ?)""",
        ("run_a", owner, "dataset_a", 1, "Count rows", "request_a", "c" * 64),
    )


def seed_run(database: Database) -> None:
    with database.transaction() as connection:
        add_session(connection)
        add_dataset(connection)
        add_run(connection)


def test_initialization_schema_and_repeat_preserve_data(database: Database) -> None:
    seed_run(database)
    database.initialize()
    with database.connection() as connection:
        tables = {row[0] for row in connection.execute(
            "SELECT name FROM sqlite_schema WHERE type='table'"
        )}
        assert {"sessions", "datasets", "dataset_versions", "runs", "attempts", "audit_events"} <= tables
        assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        assert connection.execute("PRAGMA application_id").fetchone()[0] == APPLICATION_ID
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("SELECT state FROM runs").fetchone()[0] == "PLAN_AND_CODE"


def test_connection_settings_read_only_and_closure(database: Database) -> None:
    with database.connection() as connection:
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert connection.execute("PRAGMA recursive_triggers").fetchone()[0] == 1
        assert connection.execute("PRAGMA busy_timeout").fetchone()[0] == 100
        assert connection.execute("PRAGMA synchronous").fetchone()[0] == 2
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            add_session(connection)
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connection.execute("SELECT 1")


def test_commit_persists_in_new_store(database: Database) -> None:
    with database.transaction() as connection:
        add_session(connection)
    reopened = Database(Settings(_env_file=None, database_path=database.path))
    with reopened.connection() as reader:
        assert reader.execute("SELECT session_id FROM sessions").fetchone()[0] == "session_a"
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connection.execute("SELECT 1")


@pytest.mark.parametrize("failure", [RuntimeError, KeyboardInterrupt])
def test_exception_rolls_back_entire_unit(database: Database, failure: type[BaseException]) -> None:
    with pytest.raises(failure):
        with database.transaction() as connection:
            add_session(connection)
            add_dataset(connection)
            raise failure("synthetic failure")
    with database.connection() as reader:
        assert reader.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
        assert reader.execute("SELECT COUNT(*) FROM datasets").fetchone()[0] == 0
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connection.execute("SELECT 1")


def test_constraint_failure_rolls_back_prior_writes(database: Database) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        with database.transaction() as connection:
            add_session(connection)
            add_session(connection)
    with database.connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0


def test_foreign_keys_reject_unknown_and_cross_session_owners(database: Database) -> None:
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        with database.transaction() as connection:
            add_dataset(connection)
    with database.transaction() as connection:
        add_session(connection)
        add_session(connection, "b")
        add_dataset(connection)
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        with database.transaction() as connection:
            add_run(connection, owner="session_b")
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        with database.transaction() as connection:
            connection.execute(
                "INSERT INTO dataset_versions(dataset_id, version, session_id) VALUES (?, ?, ?)",
                ("dataset_a", 2, "session_b"),
            )


@pytest.mark.parametrize("assignment", [
    "state='UNKNOWN'", "candidate_versions=4", "execution_attempts=1",
    "state='COMPLETE'", "lease_owner='worker_a'",
    "deadline_at=1000", "admitted_at=1000, deadline_at=1181",
])
def test_run_constraints(database: Database, assignment: str) -> None:
    seed_run(database)
    with pytest.raises(sqlite3.IntegrityError):
        with database.transaction() as connection:
            # Assignment is a fixed reviewed test parameter, never user input.
            connection.execute(f"UPDATE runs SET {assignment} WHERE run_id='run_a'")


def test_run_lease_and_completion_metadata_can_persist(database: Database) -> None:
    seed_run(database)
    with database.transaction() as connection:
        now = connection.execute("SELECT unixepoch()").fetchone()[0]
        connection.execute(
            """UPDATE runs SET state='QUEUED', lease_owner=?, lease_expires_at=?,
                heartbeat_at=?, admitted_at=?, deadline_at=?, state_version=state_version+1
                WHERE run_id=? AND state_version=?""",
            ("worker_a", now + 100, now, now, now + 180, "run_a", 0),
        )
        assert connection.execute(
            "UPDATE runs SET state_version=2 WHERE run_id=? AND state_version=?", ("run_a", 0)
        ).rowcount == 0
        connection.execute(
            """UPDATE runs SET state='COMPLETE', validation_status='PASSED',
                cleanup_status='CONFIRMED', lease_owner=NULL, lease_expires_at=NULL,
                heartbeat_at=NULL WHERE run_id=?""", ("run_a",),
        )
    with database.connection() as connection:
        assert connection.execute("SELECT state_version FROM runs").fetchone()[0] == 1


@pytest.mark.parametrize("candidate,execution", [(4, None), (1, 4), (1, 2)])
def test_attempt_budgets(database: Database, candidate: int, execution: int | None) -> None:
    seed_run(database)
    with pytest.raises(sqlite3.IntegrityError):
        with database.transaction() as connection:
            connection.execute(
                """INSERT INTO attempts(attempt_id, run_id, candidate_version, execution_number,
                    code_ref, code_sha256) VALUES (?, ?, ?, ?, ?, ?)""",
                ("attempt_a", "run_a", candidate, execution, "code/candidate.py", "a" * 64),
            )


def test_attempts_persist_and_rejected_candidates_still_use_versions(database: Database) -> None:
    seed_run(database)
    with database.transaction() as connection:
        connection.execute(
            """INSERT INTO attempts(attempt_id, run_id, candidate_version, code_ref,
                code_sha256, state, finished_at) VALUES (?, ?, ?, ?, ?, ?, unixepoch())""",
            ("blocked_a", "run_a", 1, "code/one.py", "a" * 64, "BLOCKED_POLICY"),
        )
        connection.execute(
            """INSERT INTO attempts(attempt_id, run_id, candidate_version, execution_number,
                code_ref, code_sha256) VALUES (?, ?, ?, ?, ?, ?)""",
            ("candidate_b", "run_a", 2, 1, "code/two.py", "b" * 64),
        )
    with pytest.raises(sqlite3.IntegrityError, match="UNIQUE"):
        with database.transaction() as connection:
            connection.execute(
                """INSERT INTO attempts(attempt_id, run_id, candidate_version, execution_number,
                    code_ref, code_sha256) VALUES (?, ?, ?, ?, ?, ?)""",
                ("duplicate_execution", "run_a", 3, 1, "code/three.py", "c" * 64),
            )
    with database.connection() as connection:
        rows = connection.execute("SELECT * FROM attempts ORDER BY candidate_version").fetchall()
        assert len(rows) == 2
        assert rows[0]["execution_number"] is None
        assert rows[1]["execution_number"] == 1


def test_session_expiry_and_private_consent(database: Database) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        with database.transaction() as connection:
            connection.execute(
                """INSERT INTO sessions(session_id, auth_token_hash, audit_pseudonym, mode)
                    VALUES (?, ?, ?, 'private')""", ("private_a", "a" * 64, "pseudonym_a"),
            )
    with pytest.raises(sqlite3.IntegrityError):
        with database.transaction() as connection:
            connection.execute(
                """INSERT INTO sessions(session_id, auth_token_hash, audit_pseudonym,
                    created_at, expires_at) VALUES (?, ?, ?, ?, ?)""",
                ("session_a", "a" * 64, "pseudonym_a", 1000, 4601),
            )


def test_versioned_profiles_and_json_constraints(database: Database) -> None:
    seed_run(database)
    with database.transaction() as connection:
        connection.execute(
            """INSERT INTO dataset_versions(dataset_id, version, session_id, parsing_settings_json)
                VALUES (?, ?, ?, ?)""", ("dataset_a", 2, "session_a", '{"sheet_id":"sheet_2"}'),
        )
    with pytest.raises(sqlite3.IntegrityError):
        with database.transaction() as connection:
            connection.execute("UPDATE dataset_versions SET parsing_settings_json='[]'")
    with database.connection() as connection:
        assert connection.execute("SELECT dataset_version FROM runs").fetchone()[0] == 1


def test_audit_sequence_immutability_and_retention(database: Database) -> None:
    seed_run(database)
    with database.transaction() as connection:
        event_id = database.append_audit_event(
            connection, session_pseudonym="pseudonym_a", event_type="RUN_CREATED",
            build_version="test", run_id="run_a", state="PLAN_AND_CODE",
            details={"source_sha256": "a" * 64, "input_tokens": None},
        )
        database.append_audit_event(
            connection, session_pseudonym="pseudonym_a", event_type="ATTEMPT_CREATED",
            build_version="test", run_id="run_a", attempt_id="attempt_a",
            details={"candidate_version": 1},
        )
    with database.connection() as connection:
        events = connection.execute("SELECT * FROM audit_events ORDER BY sequence").fetchall()
        assert events[1]["sequence"] > events[0]["sequence"]
        assert json.loads(events[0]["details_json"])["input_tokens"] is None
    for sql in (
        "UPDATE audit_events SET event_type='changed' WHERE event_id=?",
        "DELETE FROM audit_events WHERE event_id=?",
        """INSERT OR REPLACE INTO audit_events(event_id, session_pseudonym, event_type, build_version)
            VALUES (?, 'pseudonym_a', 'RUN_CREATED', 'test')""",
    ):
        with pytest.raises(sqlite3.IntegrityError):
            with database.transaction() as connection:
                connection.execute(sql, (event_id,))
    # Session metadata may be purged without rewriting retained content-free evidence.
    with database.transaction() as connection:
        connection.execute("DELETE FROM sessions WHERE session_id=?", ("session_a",))
    with database.connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 2


def test_expired_audit_rows_can_be_pruned(database: Database) -> None:
    with database.transaction() as connection:
        connection.execute(
            """INSERT INTO audit_events(event_id, session_pseudonym, event_type, build_version,
                created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)""",
            ("expired_a", "pseudonym_a", "SESSION_CREATED", "test", 1000, 1001),
        )
        connection.execute("DELETE FROM audit_events WHERE expires_at <= unixepoch()")
    with database.connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 0


@pytest.mark.parametrize("details", [
    {"api_key": "synthetic-key"}, {"raw_cells": ["synthetic-row"]},
    {"question": "Count rows"}, {"byte_count": True}, {"code_sha256": "bad-hash"},
    {"check_passed": "yes"}, {"duration_ms": -1},
])
def test_audit_rejects_unapproved_content(database: Database, details: dict) -> None:
    with pytest.raises(ValueError):
        with database.transaction() as connection:
            database.append_audit_event(
                connection, session_pseudonym="pseudonym_a", event_type="RUN_CREATED",
                build_version="test", details=details,
            )
    with database.connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 0


def test_audit_requires_transaction(database: Database) -> None:
    connection = sqlite3.connect(database.path, isolation_level=None)
    try:
        with pytest.raises(RuntimeError, match="transaction"):
            database.append_audit_event(
                connection, session_pseudonym="pseudonym_a", event_type="RUN_CREATED", build_version="test"
            )
    finally:
        connection.close()


def test_metadata_and_audit_append_rollback_together(database: Database) -> None:
    with pytest.raises(RuntimeError):
        with database.transaction() as connection:
            add_session(connection)
            database.append_audit_event(
                connection, session_pseudonym="pseudonym_a", event_type="SESSION_CREATED",
                build_version="test",
            )
            raise RuntimeError("synthetic failure after append")
    with database.connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 0


def test_busy_writer_fails_and_recovers(database: Database) -> None:
    with database.transaction() as first:
        add_session(first)
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            with database.transaction():
                pytest.fail("Second writer must not acquire the held lock")
    with database.transaction() as connection:
        add_session(connection, "b")
    with database.connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 2


def test_waiting_writer_commits_after_lock_released(database: Database) -> None:
    waiting = Database(Settings(
        _env_file=None, database_path=database.path, database_busy_timeout_ms=2000,
    ))
    started = Event()

    def write() -> None:
        started.set()
        with waiting.transaction() as connection:
            add_session(connection, "b")

    with ThreadPoolExecutor(max_workers=1) as pool:
        with database.transaction() as connection:
            add_session(connection)
            pending = pool.submit(write)
            assert started.wait(timeout=2)
            time.sleep(0.05)
            assert not pending.done()
        pending.result(timeout=3)
    with database.connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 2


def test_failed_migration_rolls_back_schema_and_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = Database(Settings(_env_file=None, database_path=tmp_path / "migration.sqlite3"))
    with monkeypatch.context() as patch:
        patch.setitem(MIGRATIONS, 1, (*MIGRATIONS[1], "INVALID SQL"))
        with pytest.raises(sqlite3.OperationalError):
            database.initialize()
    with sqlite3.connect(database.path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
        assert connection.execute("PRAGMA application_id").fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'"
        ).fetchone()[0] == 0
    database.initialize()


@pytest.mark.parametrize("kind", ["newer", "foreign", "unversioned"])
def test_unsupported_database_is_not_modified(tmp_path: Path, kind: str) -> None:
    store = Database(Settings(_env_file=None, database_path=tmp_path / "existing.sqlite3"))
    with sqlite3.connect(store.path) as connection:
        connection.execute("CREATE TABLE sentinel(value TEXT)")
        if kind == "newer":
            connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
            connection.execute(f"PRAGMA user_version={SCHEMA_VERSION + 1}")
        elif kind == "foreign":
            connection.execute("PRAGMA application_id=1234")
    with pytest.raises(DatabaseVersionError):
        store.initialize()
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM sentinel").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM sqlite_schema WHERE type='table'").fetchone()[0] == 1


def test_missing_database_requires_explicit_initialization(tmp_path: Path) -> None:
    store = Database(Settings(_env_file=None, database_path=tmp_path / "missing.sqlite3"))
    with pytest.raises(sqlite3.OperationalError):
        with store.connection():
            pass
    assert not store.path.exists()
