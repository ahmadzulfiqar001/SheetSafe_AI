"""Explicit SQLite lifecycle and transactions for trusted backend code only.

Call initialize() during controlled application startup before serving DB-backed
routes. Each operation owns a connection; connections are never shared between
threads. BEGIN IMMEDIATE serializes writers across processes. No AI/worker logic
or automatic startup side effects are introduced by importing this module.

SQLite is not encrypted by this module. Private uploads still require encrypted
deployment storage and the PRD's privacy, authorization and deletion controls.
"""

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
import json
from pathlib import Path
import re
import sqlite3
import time
from uuid import uuid4

from backend.config import Settings
from backend.storage.schema import APPLICATION_ID, MIGRATIONS, RUN_STATES, SCHEMA_VERSION


class DatabaseVersionError(RuntimeError):
    """The database is foreign, unversioned or newer than this application."""


class DatabaseReadinessError(RuntimeError):
    """Required database controls or consistency checks did not pass."""


_HASH_FIELDS = frozenset({
    "source_sha256", "code_sha256", "schema_sha256", "plan_sha256",
    "artifact_sha256", "error_signature_sha256",
})
_COUNT_FIELDS = frozenset({
    "byte_count", "duration_ms", "cpu_ms", "peak_memory_bytes", "candidate_version",
    "execution_attempts", "retry_count", "input_tokens", "output_tokens",
})
_FLAG_FIELDS = frozenset({"check_passed", "cleanup_confirmed"})
_EVENT_TYPES = frozenset({
    "SESSION_CREATED", "SESSION_REVOKED", "DATASET_CREATED", "DATASET_PROFILED",
    "RUN_CREATED", "RUN_STATE_CHANGED", "ATTEMPT_CREATED", "POLICY_DECISION",
    "INFERENCE_COMPLETED", "VALIDATION_COMPLETED", "CLEANUP_COMPLETED",
    "DELETION_REQUESTED", "DELETION_COMPLETED",
    "SESSION_EXPIRED", "CLEANUP_STARTED", "CLEANUP_RETRY", "CLEANUP_BLOCKED",
    "CLEANUP_DEADLINE_MISSED", "CLEANUP_COMPLETED",
})


class Database:
    """File-backed SQLite metadata store with explicit initialization."""

    def __init__(self, settings: Settings, *, clock: Callable[[], int] | None = None) -> None:
        self.path: Path = settings.database_path
        self.busy_timeout_ms = settings.database_busy_timeout_ms
        self.now = clock if clock is not None else lambda: int(time.time())

    def _open(self, *, create: bool = False) -> sqlite3.Connection:
        # mode=rw prevents typos or missing initialization from silently creating
        # an empty database. as_uri also safely escapes special path characters.
        mode = "rwc" if create else "rw"
        connection = sqlite3.connect(
            f"{self.path.as_uri()}?mode={mode}", uri=True,
            timeout=self.busy_timeout_ms / 1000, isolation_level=None,
        )
        try:
            connection.row_factory = sqlite3.Row
            connection.create_function("retention_now", 0, self.now)
            connection.execute("PRAGMA foreign_keys = ON")
            # REPLACE must also fire delete guards on retained audit records.
            connection.execute("PRAGMA recursive_triggers = ON")
            connection.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms}")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("PRAGMA secure_delete = ON")
            if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
                raise RuntimeError("SQLite foreign-key enforcement is unavailable")
            if connection.execute("PRAGMA secure_delete").fetchone()[0] != 1:
                raise RuntimeError("SQLite secure metadata deletion is unavailable")
            return connection
        except BaseException:
            connection.close()
            raise

    @staticmethod
    def _check_version(connection: sqlite3.Connection) -> None:
        if (
            connection.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID
            or connection.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION
        ):
            raise DatabaseVersionError("Database schema is not initialized or supported")

    def initialize(self) -> None:
        """Apply ordered migrations atomically, then enable WAL on local storage.

        Never use executescript here: its implicit commit can break migration
        atomicity. Initialization refuses to adopt a preexisting unknown schema.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = self._open(create=True)
        try:
            connection.execute("BEGIN IMMEDIATE")
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            application_id = connection.execute("PRAGMA application_id").fetchone()[0]
            if version == 0 and application_id == 0:
                if connection.execute(
                    "SELECT 1 FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' LIMIT 1"
                ).fetchone():
                    raise DatabaseVersionError("Refusing an unversioned nonempty database")
            elif application_id != APPLICATION_ID or not 1 <= version <= SCHEMA_VERSION:
                raise DatabaseVersionError("Database identity or schema version is unsupported")

            for target in range(version + 1, SCHEMA_VERSION + 1):
                for statement in MIGRATIONS[target]:
                    connection.execute(statement)
                connection.execute(f"PRAGMA user_version = {target}")
            connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
            connection.commit()
            if connection.execute("PRAGMA journal_mode = WAL").fetchone()[0] != "wal":
                raise RuntimeError("SQLite WAL mode is unavailable; initialization refused")
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def check_ready(self, *, full_integrity: bool = False) -> None:
        """Probe a fresh connection without writes or automatic database creation.

        Startup checks full integrity; live probes use quick_check plus foreign-key
        checks. SQLite errors propagate to the API's sanitized readiness boundary.
        A successful probe describes this database only, not future runner/AI health.
        """
        with self.connection() as connection:
            if connection.execute("PRAGMA journal_mode").fetchone()[0] != "wal":
                raise DatabaseReadinessError("Required database journal mode is unavailable")
            check = "integrity_check(1)" if full_integrity else "quick_check(1)"
            if connection.execute(f"PRAGMA {check}").fetchall()[0][0] != "ok":
                raise DatabaseReadinessError("Database integrity check failed")
            if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise DatabaseReadinessError("Database relationship check failed")
            # A version number alone cannot prove the required tables still exist.
            for table, columns in (
                ("sessions", "session_id"), ("datasets", "dataset_id"),
                ("dataset_versions", "dataset_id, version"), ("runs", "run_id"),
                ("attempts", "attempt_id"), ("audit_events", "sequence"),
                ("session_creation_limits", "scope, key_hash"),
                ("cleanup_requests", "request_id, state"), ("cleanup_daily_metrics", "day_start"),
            ):
                connection.execute(f"SELECT {columns} FROM {table} LIMIT 0")

    def verify_checkpoint(self) -> None:
        """Remove old WAL frames or refuse to certify cleanup while readers block it.

        secure_delete wipes removed metadata in SQLite pages. Neither operation
        promises physical-media, OS cache, provider or backup erasure.
        """
        connection = self._open()
        try:
            self._check_version(connection)
            result = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            if result[0] != 0:
                raise DatabaseReadinessError("Database checkpoint is blocked")
        finally:
            connection.close()

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        """Yield a read-only snapshot and always close it, including on failure."""
        connection = self._open()
        try:
            self._check_version(connection)
            connection.execute("PRAGMA query_only = ON")
            connection.execute("BEGIN")
            yield connection
        finally:
            connection.rollback()
            connection.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Commit one write unit, or roll it back on any exception.

        Callers use parameterized SQL and must not commit/close the yielded
        connection themselves. Keep work short; do not await external services
        while holding the writer lock. Nested independent writes are not supported.
        """
        connection = self._open()
        try:
            self._check_version(connection)
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def append_audit_event(
        self, connection: sqlite3.Connection, *, session_pseudonym: str,
        event_type: str, build_version: str, run_id: str | None = None,
        attempt_id: str | None = None, state: str | None = None,
        policy_version: str | None = None, image_digest: str | None = None,
        details: Mapping[str, str | int | bool | None] | None = None,
        timestamp: int | None = None,
    ) -> str:
        """Append bounded, content-free evidence in the caller's write transaction.

        No arbitrary text/objects are accepted in details. This is an application
        boundary, not protection from a trusted SQL caller or host administrator.
        Use fresh opaque pseudonyms/IDs, never user filenames or questions.
        """
        if not connection.in_transaction:
            raise RuntimeError("Audit append requires an active transaction")
        if event_type not in _EVENT_TYPES or (state is not None and state not in RUN_STATES):
            raise ValueError("Unsupported audit event type or state")
        for value in (session_pseudonym, build_version, run_id, attempt_id, policy_version):
            if value is not None and not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", value):
                raise ValueError("Audit metadata must be bounded machine identifiers")
        if image_digest is not None and not re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest):
            raise ValueError("Invalid image digest")
        payload = dict(details or {})
        for key, value in payload.items():
            if key in _HASH_FIELDS:
                valid = isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
            elif key in _COUNT_FIELDS:
                valid = value is None or (type(value) is int and 0 <= value <= 2**63 - 1)
            elif key in _FLAG_FIELDS:
                valid = type(value) is bool
            else:
                valid = False
            if not valid:
                raise ValueError("Unsupported audit detail field or value")
        event_id = uuid4().hex
        created_at = self.now() if timestamp is None else timestamp
        if type(created_at) is not int or created_at <= 0:
            raise ValueError("Invalid audit timestamp")
        connection.execute(
            """INSERT INTO audit_events
                (event_id, session_pseudonym, event_type, build_version, run_id,
                 attempt_id, state, policy_version, image_digest, details_json, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (event_id, session_pseudonym, event_type, build_version, run_id,
             attempt_id, state, policy_version, image_digest,
             json.dumps(payload, separators=(",", ":"), allow_nan=False), created_at, created_at + 86400),
        )
        return event_id
