"""Durable session retention with fenced claims and verified cleanup boundaries.

No filesystem or container operations live here. Future reviewed adapters must
remove/verify only their server-owned session namespace, be idempotent, and use
cancellable, deadline-bounded I/O. Missing adapters never constitute verification.
"""

import asyncio
from dataclasses import dataclass
import logging
import sqlite3
import time
from typing import Protocol
from uuid import uuid4

from backend.config import Settings
from backend.storage.database import Database, DatabaseReadinessError


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CleanupContext:
    request_id: str
    session_id: str
    deadline_at: int


@dataclass(frozen=True)
class CleanupVerification:
    session_id: str
    verified: bool


class CleanupAdapter(Protocol):
    async def remove_and_verify(self, context: CleanupContext) -> CleanupVerification: ...


class RetryableCleanupError(Exception):
    """An adapter can retry an explicitly transient failure without exposing text."""


class _LeaseLost(Exception):
    pass


class _CleanupFailure(Exception):
    def __init__(self, code: str, *, retryable: bool = False) -> None:
        self.code, self.retryable = code, retryable


class LifecycleCoordinator:
    def __init__(
        self, database: Database, settings: Settings, *,
        storage: CleanupAdapter | None = None, runner: CleanupAdapter | None = None,
    ) -> None:
        self.database, self.settings = database, settings
        self.storage, self.runner = storage, runner
        self.worker_required = False
        self.running = False
        self.last_sweep_ok = False
        self.last_sweep_at: float | None = None

    def _event(self, connection: sqlite3.Connection, job, event_type: str, now: int, **details) -> str:
        return self.database.append_audit_event(
            connection, session_pseudonym=job["session_pseudonym"], event_type=event_type,
            build_version="0.1.0", timestamp=now, details=details,
        )

    @staticmethod
    def _metric(connection: sqlite3.Connection, metric: str, now: int) -> None:
        day = now - now % 86400
        connection.execute(
            """INSERT INTO cleanup_daily_metrics(day_start, metric, value, expires_at)
                VALUES (?, ?, 1, ?) ON CONFLICT(day_start, metric) DO UPDATE SET value=value+1""",
            (day, metric, day + 2592000),
        )

    def request_cleanup(
        self, connection: sqlite3.Connection, session_id: str, *, reason: str, now: int,
    ) -> str:
        """Revoke and enqueue atomically in a caller-owned writer transaction.

        This is a trusted internal API. HTTP callers must authenticate ownership
        first. Repeated internal requests return the same receipt and deadline.
        """
        if not connection.in_transaction:
            raise RuntimeError("Cleanup request requires a writer transaction")
        if reason not in {"MANUAL", "EXPIRED", "REVOKED"}:
            raise ValueError("Unsupported cleanup reason")
        existing = connection.execute(
            "SELECT request_id FROM cleanup_requests WHERE session_id=?", (session_id,),
        ).fetchone()
        if existing is not None:
            return existing[0]
        session = connection.execute("SELECT * FROM sessions WHERE session_id=?", (session_id,)).fetchone()
        if session is None:
            raise LookupError("Session does not exist")
        starts = [now]
        starts.extend(value for value in (session["revoked_at"], session["deletion_requested_at"]) if value is not None)
        if session["expires_at"] <= now:
            starts.append(session["expires_at"])
        requested = min(starts)
        connection.execute(
            """UPDATE sessions SET revoked_at=coalesce(revoked_at, ?),
                deletion_requested_at=coalesce(deletion_requested_at, ?) WHERE session_id=?""",
            (now, requested, session_id),
        )
        connection.execute(
            """UPDATE runs SET cancel_requested_at=coalesce(cancel_requested_at, ?),
                updated_at=max(updated_at, ?) WHERE session_id=?""", (now, now, session_id),
        )
        context = {"session_pseudonym": session["audit_pseudonym"]}
        if session["revoked_at"] is None:
            self._event(connection, context, "SESSION_EXPIRED" if reason == "EXPIRED" else "SESSION_REVOKED", now)
        receipt = self._event(connection, context, "DELETION_REQUESTED", now)
        connection.execute(
            """INSERT INTO cleanup_requests(request_id, session_id, session_pseudonym, reason,
                requested_at, deadline_at, next_attempt_at) VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (receipt, session_id, session["audit_pseudonym"], reason, requested, requested + 300, now),
        )
        return receipt

    def admissions_paused(self, connection: sqlite3.Connection) -> bool:
        if self.worker_required and (
            not self.running or not self.last_sweep_ok or self.last_sweep_at is None
            or time.monotonic() - self.last_sweep_at > max(60, self.settings.cleanup_interval_seconds * 3)
        ):
            return True
        incomplete = connection.execute(
            """SELECT 1 FROM cleanup_requests WHERE state != 'COMPLETE' AND
                (failure_recorded=1 OR state IN ('BLOCKED', 'RETRY') OR deadline_at <= ? OR
                 (state='RUNNING' AND lease_expires_at <= ?)) LIMIT 1""",
            (self.database.now(), self.database.now()),
        ).fetchone() is not None
        return incomplete or connection.execute(
            """SELECT 1 FROM sessions WHERE expires_at <= ? OR revoked_at <= ?
                OR deletion_requested_at <= ? LIMIT 1""",
            (self.database.now() - 300,) * 3,
        ).fetchone() is not None

    def check_ready(self) -> None:
        with self.database.connection() as connection:
            if self.admissions_paused(connection):
                raise DatabaseReadinessError("Session cleanup needs operator attention or recovery")

    def _discover_and_recover(self) -> None:
        now = self.database.now()
        with self.database.transaction() as connection:
            rows = connection.execute(
                """SELECT * FROM sessions s WHERE
                    (expires_at <= ? OR revoked_at IS NOT NULL OR deletion_requested_at IS NOT NULL)
                    AND NOT EXISTS(SELECT 1 FROM cleanup_requests c WHERE c.session_id=s.session_id)
                    ORDER BY expires_at LIMIT ?""", (now, self.settings.cleanup_batch_size),
            ).fetchall()
            for session in rows:
                self.request_cleanup(connection, session["session_id"], now=now,
                                     reason="EXPIRED" if session["expires_at"] <= now else "REVOKED")
            abandoned = connection.execute(
                """SELECT * FROM cleanup_requests WHERE state='RUNNING' AND lease_expires_at <= ?
                    LIMIT ?""", (now, self.settings.cleanup_batch_size),
            ).fetchall()
            for job in abandoned:
                exhausted = job["attempts"] >= self.settings.cleanup_max_attempts
                connection.execute(
                    """UPDATE cleanup_requests SET state=?, last_error_code=?, next_attempt_at=?, failure_recorded=1,
                        lease_token=NULL, lease_expires_at=NULL WHERE request_id=?""",
                    ("BLOCKED" if exhausted else "RETRY", "RETRY_EXHAUSTED" if exhausted else "LEASE_EXPIRED",
                     now, job["request_id"]),
                )
                self._event(connection, job, "CLEANUP_BLOCKED" if exhausted else "CLEANUP_RETRY", now)
            late = connection.execute(
                """SELECT * FROM cleanup_requests WHERE state != 'COMPLETE' AND deadline_at <= ?
                    AND deadline_missed_at IS NULL LIMIT ?""", (now, self.settings.cleanup_batch_size),
            ).fetchall()
            for job in late:
                connection.execute("UPDATE cleanup_requests SET deadline_missed_at=? WHERE request_id=?",
                                   (now, job["request_id"]))
                self._event(connection, job, "CLEANUP_DEADLINE_MISSED", now, cleanup_confirmed=False)
                self._metric(connection, "DEADLINE_MISSED", now)
                logger.error("Session cleanup deadline missed; cleanup_code=DEADLINE_MISSED")

    def _prune_retention(self) -> None:
        now, batch = self.database.now(), self.settings.cleanup_retention_batch_size
        with self.database.transaction() as connection:
            connection.execute(
                """DELETE FROM audit_events WHERE sequence IN
                    (SELECT sequence FROM audit_events WHERE expires_at <= ? ORDER BY sequence LIMIT ?)""", (now, batch),
            )
            connection.execute(
                """DELETE FROM cleanup_requests WHERE request_id IN
                    (SELECT request_id FROM cleanup_requests WHERE state='COMPLETE' AND retain_until <= ? LIMIT ?)""",
                (now, batch),
            )
            connection.execute("DELETE FROM cleanup_daily_metrics WHERE expires_at <= ?", (now,))
            connection.execute("DELETE FROM session_creation_limits WHERE window_start < ?", (now - now % 60,))

    def _claim(self):
        now = self.database.now()
        with self.database.transaction() as connection:
            job = connection.execute(
                """SELECT * FROM cleanup_requests WHERE state IN ('PENDING', 'RETRY')
                    AND next_attempt_at <= ? AND attempts < ? ORDER BY deadline_at, request_id LIMIT 1""",
                (now, self.settings.cleanup_max_attempts),
            ).fetchone()
            if job is None:
                return None
            token = uuid4().hex
            connection.execute(
                """UPDATE cleanup_requests SET state='RUNNING', attempts=attempts+1,
                    lease_token=?, lease_expires_at=? WHERE request_id=?""", (token, now + 30, job["request_id"]),
            )
            self._event(connection, job, "CLEANUP_STARTED", now, retry_count=job["attempts"])
            return dict(connection.execute("SELECT * FROM cleanup_requests WHERE request_id=?", (job["request_id"],)).fetchone())

    def _leased(self, connection: sqlite3.Connection, job):
        current = connection.execute(
            """SELECT * FROM cleanup_requests WHERE request_id=? AND state='RUNNING'
                AND lease_token=? AND lease_expires_at > ?""",
            (job["request_id"], job["lease_token"], self.database.now()),
        ).fetchone()
        if current is None:
            raise _LeaseLost()
        return current

    def _inventory(self, job) -> tuple[bool, bool]:
        with self.database.connection() as connection:
            self._leased(connection, job)
            if connection.execute("SELECT 1 FROM sessions WHERE session_id=?", (job["session_id"],)).fetchone() is None:
                raise _CleanupFailure("UNVERIFIED")
            storage = connection.execute(
                """SELECT 1 FROM datasets WHERE session_id=? UNION ALL
                    SELECT 1 FROM attempts a JOIN runs r USING(run_id) WHERE r.session_id=? LIMIT 1""",
                (job["session_id"], job["session_id"]),
            ).fetchone() is not None
            runtime = connection.execute(
                """SELECT 1 FROM runs WHERE session_id=? AND
                    (lease_owner IS NOT NULL OR state IN ('EXECUTE', 'VALIDATE')) UNION ALL
                    SELECT 1 FROM attempts a JOIN runs r USING(run_id) WHERE r.session_id=? AND
                    (execution_number IS NOT NULL OR runtime_receipt_json != '{}') LIMIT 1""",
                (job["session_id"], job["session_id"]),
            ).fetchone() is not None
            return storage, runtime

    async def _verify_adapter(self, adapter, needed: bool, kind: str, job) -> str:
        if adapter is None:
            if needed:
                raise _CleanupFailure(f"{kind}_REQUIRED")
            return "NONE_REGISTERED"
        context = CleanupContext(job["request_id"], job["session_id"],
                                 min(job["lease_expires_at"], self.database.now() + 10))
        try:
            result = await asyncio.wait_for(adapter.remove_and_verify(context), self.settings.cleanup_adapter_timeout_seconds)
        except TimeoutError:
            raise _CleanupFailure("ADAPTER_TIMEOUT", retryable=True) from None
        except RetryableCleanupError:
            raise _CleanupFailure("ADAPTER_FAILURE", retryable=True) from None
        except Exception:
            raise _CleanupFailure("ADAPTER_FAILURE") from None
        if not isinstance(result, CleanupVerification) or result.session_id != job["session_id"] or result.verified is not True:
            raise _CleanupFailure("UNVERIFIED")
        return "VERIFIED"

    def _purge_metadata(self, job, storage_status: str, runtime_status: str) -> None:
        with self.database.transaction() as connection:
            self._leased(connection, job)
            session = connection.execute("SELECT * FROM sessions WHERE session_id=?", (job["session_id"],)).fetchone()
            if session is None or session["revoked_at"] is None or session["deletion_requested_at"] is None:
                raise _CleanupFailure("UNVERIFIED")
            connection.execute("DELETE FROM sessions WHERE session_id=?", (job["session_id"],))
            connection.execute(
                """UPDATE cleanup_requests SET phase='CHECKPOINT', storage_status=?, runtime_status=?
                    WHERE request_id=?""", (storage_status, runtime_status, job["request_id"]),
            )

    def _complete(self, job) -> None:
        now = self.database.now()
        with self.database.transaction() as connection:
            current = self._leased(connection, job)
            if current["phase"] != "CHECKPOINT" or connection.execute(
                "SELECT 1 FROM sessions WHERE session_id=?", (job["session_id"],)
            ).fetchone():
                raise _CleanupFailure("UNVERIFIED")
            if current["deadline_missed_at"] is None and now >= current["deadline_at"]:
                connection.execute("UPDATE cleanup_requests SET deadline_missed_at=? WHERE request_id=?",
                                   (now, job["request_id"]))
                self._event(connection, job, "CLEANUP_DEADLINE_MISSED", now, cleanup_confirmed=False)
                self._metric(connection, "DEADLINE_MISSED", now)
            connection.execute(
                """UPDATE cleanup_requests SET state='COMPLETE', completed_at=?, retain_until=?,
                    lease_token=NULL, lease_expires_at=NULL, last_error_code=NULL WHERE request_id=?""",
                (now, now + 86400, job["request_id"]),
            )
            self._event(connection, job, "CLEANUP_COMPLETED", now, cleanup_confirmed=True)
            self._metric(connection, "COMPLETED", now)

    def _fail(self, job, failure: _CleanupFailure) -> None:
        now = self.database.now()
        with self.database.transaction() as connection:
            current = self._leased(connection, job)
            retry = failure.retryable and current["attempts"] < self.settings.cleanup_max_attempts
            code = failure.code if retry or not failure.retryable else "RETRY_EXHAUSTED"
            connection.execute(
                """UPDATE cleanup_requests SET state=?, last_error_code=?, next_attempt_at=?, failure_recorded=1,
                    lease_token=NULL, lease_expires_at=NULL WHERE request_id=?""",
                ("RETRY" if retry else "BLOCKED", code, now + min(30, 2 ** current["attempts"]), job["request_id"]),
            )
            self._event(connection, job, "CLEANUP_RETRY" if retry else "CLEANUP_BLOCKED", now, cleanup_confirmed=False)
            logger.warning("Session cleanup incomplete; cleanup_code=%s", code)

    async def _process(self, job) -> None:
        try:
            if job["phase"] == "RESOURCES":
                storage_needed, runtime_needed = await asyncio.to_thread(self._inventory, job)
                runtime_status = await self._verify_adapter(self.runner, runtime_needed, "RUNNER", job)
                storage_status = await self._verify_adapter(self.storage, storage_needed, "STORAGE", job)
                await asyncio.to_thread(self._purge_metadata, job, storage_status, runtime_status)
            await asyncio.to_thread(self.database.verify_checkpoint)
            await asyncio.to_thread(self._complete, job)
        except _LeaseLost:
            return  # A newer lease owns the decision; stale work cannot certify it.
        except _CleanupFailure as failure:
            await asyncio.to_thread(self._fail, job, failure)
        except DatabaseReadinessError:
            await asyncio.to_thread(self._fail, job, _CleanupFailure("CHECKPOINT_BUSY", retryable=True))
        except (sqlite3.Error, OSError):
            await asyncio.to_thread(self._fail, job, _CleanupFailure("DATABASE_FAILURE", retryable=True))

    async def run_once(self) -> None:
        """One bounded batch; durable state, never an unbounded repair loop."""
        try:
            await self._sweep_once()
        except BaseException:
            self.last_sweep_ok = False
            raise
        self.last_sweep_at = time.monotonic()
        self.last_sweep_ok = True

    async def _sweep_once(self) -> None:
        await asyncio.to_thread(self._discover_and_recover)
        await asyncio.to_thread(self._prune_retention)
        stop_at = time.monotonic() + 5
        for _ in range(self.settings.cleanup_batch_size):
            if time.monotonic() >= stop_at:
                break
            job = await asyncio.to_thread(self._claim)
            if job is None:
                break
            await self._process(job)
        # Also checkpoint pruned audit/receipt pages; retained old WAL copies are
        # not silently treated as meeting the retention requirement.
        await asyncio.to_thread(self.database.verify_checkpoint)

    async def serve(self, stop: asyncio.Event) -> None:
        self.worker_required = self.running = True
        try:
            while not stop.is_set():
                try:
                    await asyncio.wait_for(stop.wait(), self.settings.cleanup_interval_seconds)
                    break
                except TimeoutError:
                    pass
                try:
                    await self.run_once()
                except Exception:
                    self.last_sweep_ok = False
                    logger.error("Session lifecycle sweep failed; cleanup_code=COORDINATOR_FAILURE")
        finally:
            self.running = False

    def resume_blocked(self, request_id: str) -> bool:
        """Operator-only internal recovery after fixing an adapter/control.

        No HTTP runtime-control endpoint is exposed. Retry budget and original
        deadline remain unchanged; exhausted jobs require a reviewed intervention.
        """
        with self.database.transaction() as connection:
            return connection.execute(
                """UPDATE cleanup_requests SET state='PENDING', next_attempt_at=?, last_error_code=NULL
                    WHERE request_id=? AND state='BLOCKED' AND attempts < ?""",
                (self.database.now(), request_id, self.settings.cleanup_max_attempts),
            ).rowcount == 1
