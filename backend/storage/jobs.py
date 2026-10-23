"""Trusted, SQLite-fenced synthetic preparation on existing runs.

No public API, queue loop, payload storage or Docker interface. Transactions
never span transport I/O. An operator process uses its own Database connection;
FastAPI/Streamlit do not gain runner or daemon privileges by importing this code.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import StrEnum
import re
import secrets
import sqlite3

from backend.security.authorization import owned_run
from backend.security.sessions import SessionPrincipal
from backend.storage.database import Database, DatabaseVersionError
from runner.transport_protocol import InputManifest, JobBinding, PayloadEvidence
from runner.transport_state import PreparationState


# Fixed bytes for validation, not Python source or a real dataset. Never executed.
SYNTHETIC_PAYLOAD = b"SheetSafe synthetic smoke fixture v1\n"
LEASE_SECONDS = 10
OWNER_BUDGET_SECONDS = 30
RUN_BUDGET_SECONDS = 180
MAX_CLAIMS = 3
_ACTIVE = frozenset({"CREATED", "RECEIVING", "INPUT_VERIFIED"})
_RUN_STATES = frozenset({"QUEUED", "POLICY_CHECK"})


class JobCode(StrEnum):
    NOT_FOUND = "JOB_NOT_FOUND"
    DUPLICATE = "JOB_ALREADY_REGISTERED"
    BLOCKED = "JOB_BLOCKED"
    OWNED = "JOB_ALREADY_CLAIMED"
    STALE = "JOB_STALE_LEASE"
    STATE = "JOB_STATE_CONFLICT"
    EVIDENCE = "JOB_INVALID_EVIDENCE"
    DEADLINE = "JOB_DEADLINE"
    EXHAUSTED = "JOB_CLAIMS_EXHAUSTED"
    DATABASE_BUSY = "JOB_DATABASE_BUSY"
    DATABASE_FAILURE = "JOB_DATABASE_FAILURE"


class JobError(RuntimeError):
    def __init__(self, code: JobCode) -> None:
        self.code = code
        super().__init__(f"Synthetic preparation failed: {code.value}.")


@dataclass(frozen=True, slots=True)
class JobLease:
    job_id: str
    run_id: str
    session_id: str
    epoch: int
    owner: str = field(repr=False)
    expires_at: int


@dataclass(frozen=True, slots=True)
class JobSnapshot:
    job_id: str
    run_id: str
    state: str
    epoch: int
    execution_enabled: bool = field(default=False, init=False)


class JobStore:
    """Internal trusted worker repository; opaque IDs alone grant no access.

    Registration/read/cancel require an authenticated principal. Workers need
    a server-issued lease token AND the exact current epoch for every mutation.
    SQL callers and the host administrator remain trusted, as elsewhere here.
    """

    def __init__(self, database: Database) -> None:
        self.database = database

    @contextmanager
    def _scope(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        try:
            with (self.database.transaction() if write else self.database.connection()) as connection:
                yield connection
        except sqlite3.Error as error:
            base = getattr(error, "sqlite_errorcode", 0) & 255
            code = JobCode.DATABASE_BUSY if base in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED) else JobCode.DATABASE_FAILURE
            raise JobError(code) from None
        except (OSError, DatabaseVersionError):
            raise JobError(JobCode.DATABASE_FAILURE) from None

    def _now(self) -> int:
        now = self.database.now()
        if type(now) is not int or not 0 < now < 2**63 - RUN_BUDGET_SECONDS:
            raise JobError(JobCode.DEADLINE)
        return now

    @staticmethod
    def _find(connection: sqlite3.Connection, job_id: str) -> sqlite3.Row:
        if type(job_id) is not str:
            raise JobError(JobCode.NOT_FOUND)
        row = connection.execute("SELECT * FROM runs WHERE runner_job_id=?", (job_id,)).fetchone()
        if row is None:
            raise JobError(JobCode.NOT_FOUND)
        return row

    @staticmethod
    def _active(connection: sqlite3.Connection, row: sqlite3.Row, now: int) -> int:
        session = connection.execute(
            """SELECT expires_at FROM sessions WHERE session_id=? AND mode='synthetic'
                AND revoked_at IS NULL AND deletion_requested_at IS NULL AND expires_at>?""",
            (row["session_id"], now),
        ).fetchone()
        if (session is None or row["cancel_requested_at"] is not None
                or row["state"] not in _RUN_STATES or row["cleanup_status"] != "PENDING"
                or connection.execute("SELECT 1 FROM cleanup_requests WHERE session_id=?", (row["session_id"],)).fetchone()):
            raise JobError(JobCode.BLOCKED)
        return session[0]

    def _event(self, connection: sqlite3.Connection, row: sqlite3.Row, event: str, now: int) -> None:
        pseudonym = connection.execute("SELECT audit_pseudonym FROM sessions WHERE session_id=?",
            (row["session_id"],)).fetchone()[0]
        self.database.append_audit_event(connection, session_pseudonym=pseudonym,
            event_type=event, build_version="0.1.0", run_id=row["run_id"],
            timestamp=now, details={"retry_count": row["lease_epoch"]})

    def register(self, principal: SessionPrincipal, run_id: str) -> str:
        """Register exactly one fixed job per existing authorized queued run."""
        with self._scope(write=True) as connection:
            now = self._now()  # Read after obtaining the writer lock.
            row = owned_run(connection, principal, run_id)
            self._active(connection, row, now)
            if row["runner_job_id"] is not None:
                raise JobError(JobCode.DUPLICATE)
            if (row["lease_owner"] is not None or row["admitted_at"] is not None
                    or row["execution_attempts"] or row["candidate_versions"]
                    or connection.execute("SELECT 1 FROM attempts WHERE run_id=?", (run_id,)).fetchone()):
                raise JobError(JobCode.BLOCKED)
            binding = JobBinding(principal.session_id, run_id, 1)
            manifest = InputManifest.for_payload(binding, SYNTHETIC_PAYLOAD)
            connection.execute(
                """UPDATE runs SET runner_job_id=?, prep_protocol_version=1,
                    prep_fixture_id='smoke-v1', prep_payload_length=?, prep_payload_sha256=?,
                    prep_state='CREATED', prep_created_at=?, prep_updated_at=? WHERE run_id=?""",
                (binding.job_id, manifest.payload_length, manifest.sha256, now, now, run_id),
            )
            self._event(connection, self._find(connection, binding.job_id), "JOB_REGISTERED", now)
            return binding.job_id

    def snapshot(self, principal: SessionPrincipal, job_id: str) -> JobSnapshot:
        with self._scope() as connection:
            row = self._find(connection, job_id)
            owned_run(connection, principal, row["run_id"])
            return JobSnapshot(job_id, row["run_id"], row["prep_state"], row["lease_epoch"])

    def claim(self, job_id: str) -> JobLease:
        """Trusted operator entry point; token/epoch are generated, never chosen."""
        with self._scope(write=True) as connection:
            now = self._now()
            row = self._find(connection, job_id)
            session_end = self._active(connection, row, now)
            if row["prep_state"] not in _ACTIVE:
                raise JobError(JobCode.STATE)
            if row["lease_owner"] is not None and row["lease_expires_at"] > now:
                raise JobError(JobCode.OWNED)
            if now < row["prep_updated_at"]:
                raise JobError(JobCode.DEADLINE)
            if row["lease_epoch"] >= MAX_CLAIMS:
                raise JobError(JobCode.EXHAUSTED)
            admitted = row["admitted_at"] if row["admitted_at"] is not None else now
            deadline = row["deadline_at"] if row["deadline_at"] is not None else admitted + RUN_BUDGET_SECONDS
            expires = min(now + LEASE_SECONDS, deadline, session_end)
            if expires <= now:
                raise JobError(JobCode.DEADLINE)
            owner, epoch = secrets.token_hex(32), row["lease_epoch"] + 1
            changed = connection.execute(
                """UPDATE runs SET lease_owner=?, lease_expires_at=?, heartbeat_at=?, lease_epoch=?,
                    prep_claim_started_at=?, prep_state='CREATED', prep_verified_epoch=NULL,
                    prep_updated_at=?, admitted_at=?, deadline_at=?, updated_at=max(updated_at, ?)
                    WHERE run_id=? AND lease_epoch=? AND (lease_owner IS NULL OR lease_expires_at<=?)""",
                (owner, expires, now, epoch, now, now, admitted, deadline, now,
                 row["run_id"], row["lease_epoch"], now),
            ).rowcount
            if changed != 1:
                raise JobError(JobCode.STALE)
            current = self._find(connection, job_id)
            self._event(connection, current, "JOB_RECOVERED" if epoch > 1 else "JOB_CLAIMED", now)
            return JobLease(job_id, row["run_id"], row["session_id"], epoch, owner, expires)

    def _leased(self, connection: sqlite3.Connection, lease: JobLease, now: int) -> sqlite3.Row:
        if (type(lease) is not JobLease or type(lease.epoch) is not int
                or not 1 <= lease.epoch <= MAX_CLAIMS or type(lease.owner) is not str
                or re.fullmatch(r"[0-9a-f]{64}", lease.owner) is None
                or any(type(value) is not str for value in (lease.job_id, lease.run_id, lease.session_id))):
            raise JobError(JobCode.STALE)
        row = self._find(connection, lease.job_id)
        self._active(connection, row, now)
        if row["prep_state"] not in _ACTIVE:
            raise JobError(JobCode.STATE)
        if (row["run_id"] != lease.run_id or row["session_id"] != lease.session_id
                or row["lease_epoch"] != lease.epoch or row["lease_owner"] is None
                or not secrets.compare_digest(row["lease_owner"], lease.owner)
                or row["lease_expires_at"] <= now or row["deadline_at"] <= now
                or now < row["heartbeat_at"] or now < row["prep_updated_at"]):
            raise JobError(JobCode.STALE)
        return row

    def manifest(self, lease: JobLease) -> InputManifest:
        with self._scope() as connection:
            row = self._leased(connection, lease, self._now())
            binding = JobBinding._from_trusted_record(job_id=row["runner_job_id"],
                session_id=row["session_id"], run_id=row["run_id"], lease_epoch=row["lease_epoch"])
            return InputManifest(binding, row["prep_payload_length"], row["prep_payload_sha256"])

    def current(self, lease: JobLease, binding: JobBinding) -> bool:
        # Errors propagate; DB uncertainty never becomes permission.
        manifest = self.manifest(lease)
        return type(binding) is JobBinding and manifest.binding == binding

    def renew(self, lease: JobLease) -> JobLease:
        with self._scope(write=True) as connection:
            now = self._now()
            row = self._leased(connection, lease, now)
            session_end = self._active(connection, row, now)
            expires = min(now + LEASE_SECONDS, row["prep_claim_started_at"] + OWNER_BUDGET_SECONDS,
                row["deadline_at"], session_end)
            if expires <= row["lease_expires_at"] or now <= row["heartbeat_at"]:
                raise JobError(JobCode.DEADLINE)
            connection.execute("UPDATE runs SET lease_expires_at=?, heartbeat_at=? WHERE run_id=? AND lease_epoch=?",
                (expires, now, row["run_id"], lease.epoch))
            self._event(connection, row, "JOB_RENEWED", now)
            return JobLease(lease.job_id, lease.run_id, lease.session_id, lease.epoch, lease.owner, expires)

    def advance(self, lease: JobLease, expected: PreparationState, target: PreparationState,
            evidence: PayloadEvidence | None = None) -> None:
        """Trusted validator callback; input claims alone cannot attest bytes."""
        allowed = {PreparationState.CREATED: PreparationState.RECEIVING,
            PreparationState.RECEIVING: PreparationState.INPUT_VERIFIED,
            PreparationState.INPUT_VERIFIED: PreparationState.READY_FOR_EXECUTION}
        if type(expected) is not PreparationState or type(target) is not PreparationState or allowed.get(expected) != target:
            raise JobError(JobCode.STATE)
        with self._scope(write=True) as connection:
            now = self._now()
            row = self._leased(connection, lease, now)
            if row["prep_state"] != expected.value:
                raise JobError(JobCode.STATE)
            verified_epoch = row["prep_verified_epoch"]
            if target is PreparationState.INPUT_VERIFIED:
                if (type(evidence) is not PayloadEvidence or evidence.job_id != lease.job_id
                        or type(evidence.lease_epoch) is not int or evidence.lease_epoch != lease.epoch
                        or type(evidence.received_bytes) is not int
                        or evidence.received_bytes != row["prep_payload_length"]
                        or type(evidence.sha256) is not str
                        or evidence.sha256 != row["prep_payload_sha256"]
                        or evidence.execution_enabled is not False):
                    raise JobError(JobCode.EVIDENCE)
                verified_epoch = lease.epoch
            elif evidence is not None:
                raise JobError(JobCode.EVIDENCE)
            if target is PreparationState.READY_FOR_EXECUTION and verified_epoch != lease.epoch:
                raise JobError(JobCode.EVIDENCE)
            ready = target is PreparationState.READY_FOR_EXECUTION
            changed = connection.execute(
                """UPDATE runs SET prep_state=?, prep_verified_epoch=?, prep_updated_at=?,
                    lease_owner=CASE WHEN ? THEN NULL ELSE lease_owner END,
                    lease_expires_at=CASE WHEN ? THEN NULL ELSE lease_expires_at END,
                    heartbeat_at=CASE WHEN ? THEN NULL ELSE heartbeat_at END
                    WHERE run_id=? AND lease_epoch=? AND prep_state=? AND lease_owner=? AND lease_expires_at>?""",
                (target.value, verified_epoch, now, ready, ready, ready,
                 row["run_id"], lease.epoch, expected.value, lease.owner, now),
            ).rowcount
            if changed != 1:
                raise JobError(JobCode.STALE)
            self._event(connection, row, "JOB_PREPARATION_CHANGED", now)

    def fail(self, lease: JobLease, state: str) -> None:
        if type(state) is not str or state not in {"FAILED", "INTERRUPTED", "TIMED_OUT", "CANCELLED", "BLOCKED_EXTERNAL"}:
            raise JobError(JobCode.STATE)
        with self._scope(write=True) as connection:
            now = self._now()
            row = self._leased(connection, lease, now)
            connection.execute(
                """UPDATE runs SET prep_state=?, prep_updated_at=?, prep_verified_epoch=NULL,
                    lease_owner=NULL, lease_expires_at=NULL, heartbeat_at=NULL WHERE run_id=? AND lease_epoch=?""",
                (state, now, row["run_id"], lease.epoch),
            )
            self._event(connection, row, "JOB_PREPARATION_CHANGED", now)

    def cancel(self, principal: SessionPrincipal, job_id: str) -> None:
        with self._scope(write=True) as connection:
            now = self._now()
            row = self._find(connection, job_id)
            owned_run(connection, principal, row["run_id"])
            if row["prep_state"] == "CANCELLED":
                return
            self._active(connection, row, now)
            if row["prep_state"] not in _ACTIVE | {"READY_FOR_EXECUTION"}:
                raise JobError(JobCode.STATE)
            connection.execute("UPDATE runs SET cancel_requested_at=coalesce(cancel_requested_at, ?) WHERE run_id=?",
                (now, row["run_id"]))
            self._event(connection, row, "JOB_PREPARATION_CHANGED", now)
