"""Durable simulation-only intent/reconciliation, sharing job transactions/audit.

No external I/O or worker loop. Recovery claims are cleanup/inspection authority
only, even for revoked sessions; they never authorize create or execution.
"""

from dataclasses import dataclass, field
from enum import StrEnum
import hashlib
import re
import secrets
import sqlite3
from uuid import uuid4

from backend.security.authorization import owned_run
from backend.security.sessions import SessionPrincipal
from backend.storage.database import Database
from backend.storage.jobs import JobLease, JobStore
from runner.docker_backend import LOCAL_IMAGE_ID
from runner.engine_metadata import LOCAL_CONFIG_DIGEST
from runner.external_contract import SimulatedObservation, SimulatedResource


RECONCILIATION_SECONDS = 5
MAX_RECONCILIATION_CLAIMS = 3
_RESOLVED = frozenset({"VERIFIED_ABSENT", "VERIFIED_CLEANED"})


class IntentCode(StrEnum):
    NOT_FOUND = "INTENT_NOT_FOUND"
    DUPLICATE = "INTENT_ALREADY_RECORDED"
    STATE = "INTENT_STATE_CONFLICT"
    STALE = "INTENT_STALE_OWNER"
    OWNED = "INTENT_ALREADY_CLAIMED"
    ORIGIN_ACTIVE = "INTENT_ORIGIN_ACTIVE"
    EXHAUSTED = "INTENT_RECONCILIATION_EXHAUSTED"
    SIMULATION_ONLY = "INTENT_SIMULATION_ONLY"


class IntentError(RuntimeError):
    def __init__(self, code: IntentCode) -> None:
        self.code = code
        super().__init__(f"Simulated external intent failed: {code.value}.")


@dataclass(frozen=True, slots=True)
class ReconciliationLease:
    operation_id: str
    epoch: int
    owner: str = field(repr=False)
    expires_at: int


@dataclass(frozen=True, slots=True)
class IntentSnapshot:
    operation_id: str
    state: str
    reconciliation_claims: int
    last_error_code: str | None
    simulation_only: bool = field(default=True, init=False)
    execution_enabled: bool = field(default=False, init=False)
    real_resource_cleanup_verified: bool = field(default=False, init=False)


class ExternalIntentStore:
    def __init__(self, database: Database) -> None:
        self.jobs = JobStore(database)
        self.database = database

    @staticmethod
    def _find(connection: sqlite3.Connection, operation_id: str) -> sqlite3.Row:
        if type(operation_id) is not str or re.fullmatch(r"[0-9a-f]{32}", operation_id) is None:
            raise IntentError(IntentCode.NOT_FOUND)
        row = connection.execute("SELECT * FROM external_intents WHERE operation_id=?", (operation_id,)).fetchone()
        if row is None:
            raise IntentError(IntentCode.NOT_FOUND)
        return row

    def _event(self, connection: sqlite3.Connection, row: sqlite3.Row, event: str, now: int) -> None:
        session = connection.execute("SELECT audit_pseudonym FROM sessions WHERE session_id=?", (row["session_id"],)).fetchone()
        self.database.append_audit_event(connection, session_pseudonym=session[0],
            event_type=event, build_version="0.1.0", run_id=row["run_id"], timestamp=now,
            details={"retry_count": row["reconcile_epoch"]})

    @staticmethod
    def _spec(row: sqlite3.Row) -> SimulatedResource:
        return SimulatedResource(row["operation_id"], row["job_id"], row["run_id"], row["session_id"],
            row["origin_epoch"], row["resource_id"], row["resource_nonce"], row["image_id"], row["config_digest"])

    @staticmethod
    def _snapshot(row: sqlite3.Row) -> IntentSnapshot:
        return IntentSnapshot(row["operation_id"], row["state"], row["reconcile_epoch"], row["last_error_code"])

    def status(self, operation_id: str) -> IntentSnapshot:
        """Trusted operator read, not a public resource-ID authorization API."""
        with self.jobs._scope() as connection:
            return self._snapshot(self._find(connection, operation_id))

    def owned_status(self, principal: SessionPrincipal, operation_id: str) -> IntentSnapshot:
        with self.jobs._scope() as connection:
            row = self._find(connection, operation_id)
            owned_run(connection, principal, row["run_id"])
            return self._snapshot(row)

    def register(self, lease: JobLease) -> str:
        """One fixed simulated create per job; rejects all caller overrides."""
        with self.jobs._scope(write=True) as connection:
            now = self.jobs._now()
            run = self.jobs._leased(connection, lease, now, _permit_intent=True)
            if connection.execute("SELECT 1 FROM external_intents WHERE job_id=?", (lease.job_id,)).fetchone():
                raise IntentError(IntentCode.DUPLICATE)
            if run["prep_state"] != "INPUT_VERIFIED" or run["prep_verified_epoch"] != lease.epoch:
                raise IntentError(IntentCode.STATE)
            operation_id = uuid4().hex
            connection.execute(
                """INSERT INTO external_intents(operation_id,job_id,run_id,session_id,operation_type,mode,
                    origin_epoch,authorized_owner_hash,resource_id,resource_nonce,image_id,config_digest,
                    created_at,updated_at) VALUES (?,?,?,?,'SIMULATED_CREATE_SMOKE','SIMULATED',?,?,?,?,?,?,?,?)""",
                (operation_id, lease.job_id, lease.run_id, lease.session_id, lease.epoch,
                 hashlib.sha256(lease.owner.encode("ascii")).hexdigest(), uuid4().hex, secrets.token_hex(32),
                 LOCAL_IMAGE_ID, LOCAL_CONFIG_DIGEST, now, now))
            self._event(connection, self._find(connection, operation_id), "EXTERNAL_INTENT_RECORDED", now)
            return operation_id

    def begin_dispatch(self, lease: JobLease, operation_id: str) -> SimulatedResource:
        """Commit uncertainty BEFORE returning any single-use fake dispatch spec."""
        with self.jobs._scope(write=True) as connection:
            now = self.jobs._now()
            run = self.jobs._leased(connection, lease, now, _permit_intent=True)
            row = self._find(connection, operation_id)
            if (row["job_id"] != lease.job_id or row["origin_epoch"] != lease.epoch
                    or not secrets.compare_digest(row["authorized_owner_hash"], hashlib.sha256(lease.owner.encode("ascii")).hexdigest())):
                raise IntentError(IntentCode.STALE)
            if row["state"] != "INTENT_RECORDED" or row["reconcile_owner"] is not None or run["prep_state"] != "INPUT_VERIFIED":
                raise IntentError(IntentCode.STATE)
            connection.execute("""UPDATE external_intents SET state='DISPATCH_UNCERTAIN',
                dispatched_at=?,updated_at=? WHERE operation_id=? AND state='INTENT_RECORDED'""", (now, now, operation_id))
            # This run can never be reclaimed as harmless preparation again.
            connection.execute("""UPDATE runs SET prep_state='BLOCKED_EXTERNAL',prep_updated_at=?,
                lease_owner=NULL,lease_expires_at=NULL,heartbeat_at=NULL WHERE run_id=? AND lease_epoch=?""",
                (now, run["run_id"], lease.epoch))
            self._event(connection, row, "EXTERNAL_DISPATCH_UNCERTAIN", now)
            return self._spec(row)

    def claim_reconciliation(self, operation_id: str) -> ReconciliationLease:
        """Cleanup-only recovery is allowed after session expiry/revocation.

        It cannot resume execution or change the run/session/cleanup deadline.
        Exhaustion remains durable and unresolved, requiring operator review.
        """
        exhausted = False
        with self.jobs._scope(write=True) as connection:
            now = self.jobs._now()
            row = self._find(connection, operation_id)
            if row["state"] in _RESOLVED | {"TERMINAL_FAILURE"}:
                raise IntentError(IntentCode.STATE)
            if now < row["updated_at"]:
                raise IntentError(IntentCode.STALE)
            if row["reconcile_owner"] is not None and row["reconcile_expires_at"] > now:
                raise IntentError(IntentCode.OWNED)
            run = connection.execute("SELECT * FROM runs WHERE run_id=?", (row["run_id"],)).fetchone()
            if run["lease_owner"] is not None and run["lease_expires_at"] > now:
                raise IntentError(IntentCode.ORIGIN_ACTIVE)
            if row["reconcile_epoch"] >= MAX_RECONCILIATION_CLAIMS:
                connection.execute("""UPDATE external_intents SET state='TERMINAL_FAILURE',last_error_code='RETRY_EXHAUSTED',
                    updated_at=?,reconcile_owner=NULL,reconcile_expires_at=NULL,inspection_pending=0 WHERE operation_id=?""",
                    (now, operation_id))
                self._event(connection, row, "EXTERNAL_RECONCILE_FAILED", now)
                exhausted = True
            else:
                owner = secrets.token_hex(32)
                epoch = row["reconcile_epoch"] + 1
                connection.execute("""UPDATE external_intents SET reconcile_epoch=?,reconcile_owner=?,
                    reconcile_expires_at=?,inspection_pending=1,updated_at=? WHERE operation_id=? AND reconcile_epoch=?""",
                    (epoch, owner, now + RECONCILIATION_SECONDS, now, operation_id, row["reconcile_epoch"]))
                self._event(connection, self._find(connection, operation_id), "EXTERNAL_RECONCILE_CLAIMED", now)
                result = ReconciliationLease(operation_id, epoch, owner, now + RECONCILIATION_SECONDS)
        if exhausted:
            raise IntentError(IntentCode.EXHAUSTED)
        return result

    def _reconciled(self, connection: sqlite3.Connection, lease: ReconciliationLease, now: int) -> sqlite3.Row:
        if (type(lease) is not ReconciliationLease or type(lease.epoch) is not int
                or not 1 <= lease.epoch <= MAX_RECONCILIATION_CLAIMS or type(lease.owner) is not str
                or re.fullmatch(r"[0-9a-f]{64}", lease.owner) is None):
            raise IntentError(IntentCode.STALE)
        row = self._find(connection, lease.operation_id)
        run = connection.execute("SELECT * FROM runs WHERE run_id=?", (row["run_id"],)).fetchone()
        if (row["state"] in _RESOLVED | {"TERMINAL_FAILURE"} or row["reconcile_owner"] is None
                or not secrets.compare_digest(row["reconcile_owner"], lease.owner)
                or row["reconcile_epoch"] != lease.epoch or row["reconcile_expires_at"] <= now
                or now < row["updated_at"] or run["lease_epoch"] != row["origin_epoch"]):
            raise IntentError(IntentCode.STALE)
        return row

    def inspection_resource(self, lease: ReconciliationLease) -> SimulatedResource:
        with self.jobs._scope() as connection:
            row = self._reconciled(connection, lease, self.jobs._now())
            if row["inspection_pending"] != 1:
                raise IntentError(IntentCode.STATE)
            return self._spec(row)

    @staticmethod
    def _evidence_error(observation: object, expected: SimulatedResource, epoch: int) -> str | None:
        if type(observation) is not SimulatedObservation or observation.simulation_only is not True:
            return "CONTRADICTORY_EVIDENCE"
        resource = observation.resource
        if (type(resource) is not SimulatedResource or resource.simulation_only is not True
                or type(resource.origin_epoch) is not int
                or any(type(getattr(resource, name)) is not str for name in (
                    "operation_id", "job_id", "run_id", "session_id", "resource_id",
                    "ownership_nonce", "image_id", "config_digest")) or resource != expected
                or type(observation.inspection_epoch) is not int or observation.inspection_epoch != epoch):
            return "IDENTITY_MISMATCH"
        if (type(observation.present) is not bool or type(observation.actions_quiesced) is not bool
                or type(observation.lifecycle) is not str
                or (observation.present and observation.lifecycle not in {"CREATED", "STOPPED"})
                or (not observation.present and observation.lifecycle != "ABSENT")):
            return "CONTRADICTORY_EVIDENCE"
        return None

    def _inspection_failure(self, connection: sqlite3.Connection, row: sqlite3.Row,
            reason: str, now: int, *, terminal: bool = False) -> None:
        state = "TERMINAL_FAILURE" if terminal or row["reconcile_epoch"] >= MAX_RECONCILIATION_CLAIMS else "RECONCILIATION_REQUIRED"
        connection.execute("""UPDATE external_intents SET state=?,last_error_code=?,updated_at=?,
            reconcile_owner=NULL,reconcile_expires_at=NULL,inspection_pending=0,actions_quiesced=0 WHERE operation_id=?""",
            (state, reason, now, row["operation_id"]))
        self._event(connection, row, "EXTERNAL_RECONCILE_FAILED", now)

    def inspection_failed(self, lease: ReconciliationLease, *, timed_out: bool = False) -> IntentSnapshot:
        with self.jobs._scope(write=True) as connection:
            now = self.jobs._now()
            row = self._reconciled(connection, lease, now)
            if row["inspection_pending"] != 1:
                raise IntentError(IntentCode.STATE)
            self._inspection_failure(connection, row, "INSPECTION_TIMEOUT" if timed_out else "INSPECTION_FAILED", now)
            return self._snapshot(self._find(connection, lease.operation_id))

    def record_observation(self, lease: ReconciliationLease, observation: SimulatedObservation) -> IntentSnapshot:
        with self.jobs._scope(write=True) as connection:
            now = self.jobs._now()
            row = self._reconciled(connection, lease, now)
            if row["inspection_pending"] != 1:
                raise IntentError(IntentCode.STATE)
            error = self._evidence_error(observation, self._spec(row), lease.epoch)
            if error is None and observation.present and row["dispatched_at"] is None:
                error = "CONTRADICTORY_EVIDENCE"
            if error is not None:
                self._inspection_failure(connection, row, error, now, terminal=True)
            elif not observation.present and not observation.actions_quiesced:
                self._inspection_failure(connection, row, "QUIESCENCE_UNVERIFIED", now)
            else:
                state = "VERIFIED_PRESENT" if observation.present else (
                    "VERIFIED_CLEANED" if row["cleanup_dispatched_at"] is not None else "VERIFIED_ABSENT")
                present = observation.present
                connection.execute("""UPDATE external_intents SET state=?,inspected_at=?,updated_at=?,
                    actions_quiesced=?,inspection_pending=0,last_error_code=NULL,
                    reconcile_owner=CASE WHEN ? THEN reconcile_owner ELSE NULL END,
                    reconcile_expires_at=CASE WHEN ? THEN reconcile_expires_at ELSE NULL END WHERE operation_id=?""",
                    (state, now, now, observation.actions_quiesced, present, present, lease.operation_id))
                self._event(connection, row, "EXTERNAL_INSPECTED", now)
            return self._snapshot(self._find(connection, lease.operation_id))

    def begin_cleanup(self, lease: ReconciliationLease) -> SimulatedResource:
        """Single scoped simulated removal, only after exact/quiesced presence.

        A remove acknowledgement never resolves it; fresh inspection is required.
        """
        with self.jobs._scope(write=True) as connection:
            now = self.jobs._now()
            row = self._reconciled(connection, lease, now)
            if (row["state"] != "VERIFIED_PRESENT" or row["inspection_pending"] != 0
                    or row["actions_quiesced"] != 1 or row["cleanup_dispatched_at"] is not None):
                raise IntentError(IntentCode.STATE)
            connection.execute("""UPDATE external_intents SET state='CLEANUP_REQUIRED',cleanup_dispatched_at=?,
                updated_at=?,actions_quiesced=0,reconcile_owner=NULL,reconcile_expires_at=NULL,
                inspection_pending=0 WHERE operation_id=? AND state='VERIFIED_PRESENT'""", (now, now, lease.operation_id))
            self._event(connection, row, "EXTERNAL_CLEANUP_REQUIRED", now)
            return self._spec(row)
