"""Synthetic external resources only, with real SQLite fencing/recovery."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
import socket
import sqlite3
import subprocess
from threading import Barrier

import pytest

from backend.config import Settings
from backend.security.lifecycle import LifecycleCoordinator
from backend.security.sessions import SessionError
from backend.storage.database import Database
from backend.storage.external_intents import ExternalIntentStore, IntentCode, IntentError
from backend.storage.jobs import JobCode, JobError, JobStore
from backend.storage.schema import MIGRATIONS, SCHEMA_VERSION
from runner.external_contract import SimulatedObservation
from runner.policy import SandboxPolicy, RunnerNotReady, require_execution_ready
from runner.simulated_external import cleanup_simulated, dispatch_simulated, reconcile_simulated
from runner.transport_state import PreparationState as State
from test_jobs import setup, evidence, count_events  # Reuse actual SQLite/session fixture.


@pytest.fixture(autouse=True)
def no_real_external_io(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Real process/network transport is prohibited")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


def prepared_job(setup, run_id="run_0_a"):
    store = setup[1]
    job_id = store.register(setup[3].principal, run_id)
    lease = store.claim(job_id)
    manifest = store.manifest(lease)
    store.advance(lease, State.CREATED, State.RECEIVING)
    store.advance(lease, State.RECEIVING, State.INPUT_VERIFIED, evidence(manifest))
    return lease


@pytest.fixture
def intent(setup):
    lease = prepared_job(setup)
    store = ExternalIntentStore(setup[0])
    operation_id = store.register(lease)
    return setup, store, lease, operation_id, FakeExternal(store)


class FakeExternal:
    simulation_only = True

    def __init__(self, store):
        self.store = store
        self.resources = {}
        self.creates = self.inspections = self.removes = 0
        self.create_hook = self.inspect_hook = self.remove_hook = None
        self.quiesced = True
        self.remove_effect = True

    def simulate_create(self, resource, *, timeout):
        assert timeout == 1.0 and resource.simulation_only is True
        assert self.store.status(resource.operation_id).state == "DISPATCH_UNCERTAIN"
        self.creates += 1
        self.resources[resource.name] = resource
        if self.create_hook:
            self.create_hook()
        return {"success": True}  # Never evidence of verified presence.

    def simulate_inspect(self, resource, *, inspection_epoch, timeout):
        assert timeout == 1.0
        self.inspections += 1
        if self.inspect_hook:
            return self.inspect_hook(resource, inspection_epoch)
        found = self.resources.get(resource.name)
        return SimulatedObservation(found if found is not None else resource, inspection_epoch,
            found is not None, "CREATED" if found is not None else "ABSENT", self.quiesced)

    def simulate_remove(self, resource, *, timeout):
        assert self.store.status(resource.operation_id).state == "CLEANUP_REQUIRED"
        self.removes += 1
        if self.resources.get(resource.name) != resource:
            raise ValueError("Foreign resource must never be removed")
        if self.remove_effect:
            del self.resources[resource.name]
        if self.remove_hook:
            self.remove_hook()
        return {"success": True}  # Never evidence of verified removal.


def record(database, operation_id):
    with database.connection() as connection:
        return dict(connection.execute("SELECT * FROM external_intents WHERE operation_id=?", (operation_id,)).fetchone())


def expect(code, action):
    with pytest.raises(IntentError) as caught:
        action()
    assert caught.value.code is code
    assert str(caught.value) == f"Simulated external intent failed: {code.value}."


def dispatched(intent):
    setup, store, lease, operation_id, fake = intent
    result = dispatch_simulated(store, lease, operation_id, fake)
    assert result.state == "DISPATCH_UNCERTAIN"
    return store.claim_reconciliation(operation_id)


def test_intent_is_durable_owned_immutable_and_recorded_before_dispatch(intent):
    setup, store, lease, operation_id, fake = intent
    row = record(setup[0], operation_id)
    assert row["job_id"] == lease.job_id and row["run_id"] == lease.run_id
    assert row["origin_epoch"] == lease.epoch and row["mode"] == "SIMULATED"
    assert row["state"] == "INTENT_RECORDED" and row["dispatched_at"] is None
    assert lease.owner != row["authorized_owner_hash"]
    assert fake.creates == 0
    restarted = ExternalIntentStore(Database(setup[-1], clock=setup[2]))
    assert restarted.status(operation_id).state == "INTENT_RECORDED"
    assert restarted.owned_status(setup[3].principal, operation_id).execution_enabled is False
    with pytest.raises(SessionError):
        restarted.owned_status(setup[4].principal, operation_id)
    expect(IntentCode.DUPLICATE, lambda: store.register(lease))
    expect(IntentCode.ORIGIN_ACTIVE, lambda: store.claim_reconciliation(operation_id))


def test_input_verification_required_before_intent(setup):
    job_id = setup[1].register(setup[3].principal, "run_0_a")
    lease = setup[1].claim(job_id)
    expect(IntentCode.STATE, lambda: ExternalIntentStore(setup[0]).register(lease))


@pytest.mark.parametrize("iteration", range(5))
def test_competing_registrations_create_one_intent(setup, iteration):
    lease = prepared_job(setup)
    gate = Barrier(2)
    def register():
        local = ExternalIntentStore(Database(setup[-1], clock=setup[2]))
        gate.wait(timeout=5)
        try:
            return local.register(lease)
        except IntentError as error:
            return error.code
    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(lambda _: register(), range(2)))
    assert IntentCode.DUPLICATE in results
    assert sum(type(result) is str for result in results) == 1
    with setup[0].connection() as connection:
        assert connection.execute("SELECT count(*) FROM external_intents").fetchone()[0] == 1


def test_foreign_job_lease_cannot_dispatch_another_intent(intent):
    setup, store, _, operation_id, fake = intent
    other = prepared_job(setup, "run_0_b")
    expect(IntentCode.STALE, lambda: dispatch_simulated(store, other, operation_id, fake))
    assert fake.creates == 0 and store.status(operation_id).state == "INTENT_RECORDED"


def test_composite_foreign_key_rejects_cross_session_binding(intent):
    setup, _, _, operation_id, _ = intent
    other = prepared_job(setup, "run_0_b")
    copied = record(setup[0], operation_id)
    copied.update(operation_id="e" * 32, resource_id="f" * 32,
        job_id=other.job_id, run_id=other.run_id, session_id=setup[4].principal.session_id)
    names = tuple(copied)
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        with setup[0].transaction() as connection:
            connection.execute(f"INSERT INTO external_intents({','.join(names)}) VALUES ({','.join('?' for _ in names)})",
                tuple(copied.values()))


@pytest.mark.parametrize("override", ["command", "mounts", "image_id", "privileged", "operation_type", "operation_id"])
def test_caller_runtime_and_identity_overrides_rejected(setup, override):
    lease = prepared_job(setup)
    with pytest.raises(TypeError):
        ExternalIntentStore(setup[0]).register(lease, **{override: "unapproved"})


@pytest.mark.parametrize("assignment", ["resource_id='" + "e" * 32 + "'", "resource_nonce='" + "e" * 64 + "'",
    "image_id='sha256:" + "e" * 64 + "'", "config_digest='sha256:" + "e" * 64 + "'",
    "origin_epoch=origin_epoch+1", "mode='REAL'", "job_id='foreign'", "operation_type='START'",
    "created_at=created_at+1"])
def test_immutable_identity_cannot_be_replaced(intent, assignment):
    setup, _, _, operation_id, _ = intent
    before = record(setup[0], operation_id)
    with pytest.raises(sqlite3.IntegrityError):
        with setup[0].transaction() as connection:
            connection.execute(f"UPDATE external_intents SET {assignment} WHERE operation_id=?", (operation_id,))
    assert record(setup[0], operation_id) == before


def test_crash_before_dispatch_is_inspected_not_redispatched(intent):
    setup, store, lease, operation_id, fake = intent
    setup[2].value = lease.expires_at
    recovery = ExternalIntentStore(Database(setup[-1], clock=setup[2]))
    claim = recovery.claim_reconciliation(operation_id)
    result = reconcile_simulated(recovery, claim, fake)
    assert result.state == "VERIFIED_ABSENT" and fake.creates == 0
    with pytest.raises(JobError):
        dispatch_simulated(store, lease, operation_id, fake)
    with pytest.raises(JobError) as caught:
        setup[1].claim(lease.job_id)
    assert caught.value.code is JobCode.BLOCKED


def test_crash_after_marker_before_send_remains_unknown(intent):
    setup, store, lease, operation_id, fake = intent
    store.begin_dispatch(lease, operation_id)  # Simulate process disappearing here.
    assert fake.creates == 0 and store.status(operation_id).state == "DISPATCH_UNCERTAIN"
    restarted = ExternalIntentStore(Database(setup[-1], clock=setup[2]))
    claim = restarted.claim_reconciliation(operation_id)
    fake.quiesced = False
    assert reconcile_simulated(restarted, claim, fake).state == "RECONCILIATION_REQUIRED"
    assert fake.creates == 0  # Unknown state never grants another send.


@pytest.mark.parametrize("crash", [False, True])
def test_lost_ack_or_process_crash_after_effect_preserves_unknown(intent, crash):
    setup, store, lease, operation_id, fake = intent
    def lost():
        raise KeyboardInterrupt() if crash else TimeoutError("private transport exception")
    fake.create_hook = lost
    if crash:
        with pytest.raises(KeyboardInterrupt):
            dispatch_simulated(store, lease, operation_id, fake)
    else:
        assert dispatch_simulated(store, lease, operation_id, fake).state == "DISPATCH_UNCERTAIN"
    assert fake.creates == 1 and len(fake.resources) == 1
    restarted = ExternalIntentStore(Database(setup[-1], clock=setup[2]))
    claim = restarted.claim_reconciliation(operation_id)
    result = reconcile_simulated(restarted, claim, fake)
    assert result.state == "VERIFIED_PRESENT" and result.real_resource_cleanup_verified is False
    with pytest.raises(JobError):
        dispatch_simulated(store, lease, operation_id, fake)
    assert fake.creates == 1


@pytest.mark.parametrize("iteration", range(5))
def test_two_dispatchers_cannot_authorize_twice(intent, iteration):
    setup, _, lease, operation_id, fake = intent
    gate = Barrier(2)
    def compete():
        local = ExternalIntentStore(Database(setup[-1], clock=setup[2]))
        gate.wait(timeout=5)
        try:
            return dispatch_simulated(local, lease, operation_id, fake).state
        except (JobError, IntentError):
            return "REJECTED"
    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(lambda _: compete(), range(2)))
    assert results.count("DISPATCH_UNCERTAIN") == 1 and results.count("REJECTED") == 1
    assert fake.creates == 1


@pytest.mark.parametrize("iteration", range(5))
def test_reconciliation_claims_have_one_owner(intent, iteration):
    setup, store, lease, operation_id, fake = intent
    dispatch_simulated(store, lease, operation_id, fake)
    gate = Barrier(2)
    def compete():
        local = ExternalIntentStore(Database(setup[-1], clock=setup[2]))
        gate.wait(timeout=5)
        try:
            return local.claim_reconciliation(operation_id)
        except IntentError as error:
            return error.code
    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(lambda _: compete(), range(2)))
    assert sum(not isinstance(value, IntentCode) for value in results) == 1
    assert IntentCode.OWNED in results


def test_stale_reconciler_at_exact_expiry_cannot_ack(intent):
    setup, store, _, operation_id, fake = intent
    first = dispatched(intent)
    spec = store.inspection_resource(first)
    setup[2].value = first.expires_at - 1
    expect(IntentCode.OWNED, lambda: store.claim_reconciliation(operation_id))
    setup[2].value = first.expires_at
    second = store.claim_reconciliation(operation_id)
    assert second.epoch == first.epoch + 1 and first.owner not in repr(first)
    stale = SimulatedObservation(spec, first.epoch, True, "CREATED", True)
    expect(IntentCode.STALE, lambda: store.record_observation(first, stale))
    assert reconcile_simulated(store, second, fake).state == "VERIFIED_PRESENT"


@pytest.mark.parametrize("change", [{"epoch": True}, {"epoch": 0}, {"epoch": 2}, {"owner": "f" * 64}, {"owner": "\u2603"}])
def test_stale_or_invalid_reconciliation_lease_rejected(intent, change):
    _, store, _, _, _ = intent
    claim = dispatched(intent)
    expect(IntentCode.STALE, lambda: store.inspection_resource(replace(claim, **change)))


@pytest.mark.parametrize("field,value", [("ownership_nonce", "e" * 64), ("resource_id", "e" * 32),
    ("job_id", "foreign"), ("run_id", "foreign"), ("session_id", "foreign"), ("origin_epoch", 2),
    ("image_id", "sha256:" + "e" * 64), ("config_digest", "sha256:" + "e" * 64),
    ("operation_id", "e" * 32)])
def test_foreign_same_name_or_mismatched_resource_is_never_removed(intent, field, value):
    _, store, _, operation_id, fake = intent
    claim = dispatched(intent)
    spec = store.inspection_resource(claim)
    # A forged nonce preserves the same resource name while changing ownership.
    foreign = replace(spec, **{field: value})
    fake.inspect_hook = lambda resource, epoch: SimulatedObservation(foreign, epoch, True, "CREATED", True)
    result = reconcile_simulated(store, claim, fake)
    assert result.state == "TERMINAL_FAILURE" and result.last_error_code == "IDENTITY_MISMATCH"
    assert fake.removes == 0 and len(fake.resources) == 1
    expect(IntentCode.STALE, lambda: cleanup_simulated(store, claim, fake))


@pytest.mark.parametrize("present,lifecycle,quiesced", [(False, "CREATED", True), (True, "ABSENT", True),
    (True, "RUNNING", True), (1, "CREATED", True), (True, "CREATED", 1)])
def test_contradictory_evidence_fails_closed(intent, present, lifecycle, quiesced):
    _, store, _, _, fake = intent
    claim = dispatched(intent)
    fake.inspect_hook = lambda resource, epoch: SimulatedObservation(resource, epoch, present, lifecycle, quiesced)
    assert reconcile_simulated(store, claim, fake).state == "TERMINAL_FAILURE"
    assert fake.removes == 0


def test_absence_without_quiescence_is_not_success(intent):
    _, store, lease, operation_id, fake = intent
    store.begin_dispatch(lease, operation_id)
    fake.quiesced = False
    claim = store.claim_reconciliation(operation_id)
    result = reconcile_simulated(store, claim, fake)
    assert result.state == "RECONCILIATION_REQUIRED" and result.last_error_code == "QUIESCENCE_UNVERIFIED"
    fake.quiesced = True
    claim = store.claim_reconciliation(operation_id)
    assert reconcile_simulated(store, claim, fake).state == "VERIFIED_ABSENT"


def test_scoped_cleanup_needs_separate_absence_proof_and_no_duplicate_completion(intent):
    setup, store, _, operation_id, fake = intent
    claim = dispatched(intent)
    spec = store.inspection_resource(claim)
    assert reconcile_simulated(store, claim, fake).state == "VERIFIED_PRESENT"
    assert cleanup_simulated(store, claim, fake).state == "CLEANUP_REQUIRED"
    assert fake.removes == 1
    next_claim = store.claim_reconciliation(operation_id)
    result = reconcile_simulated(store, next_claim, fake)
    assert result.state == "VERIFIED_CLEANED" and result.real_resource_cleanup_verified is False
    before = count_events(setup[0])
    expect(IntentCode.STALE, lambda: store.record_observation(next_claim,
        SimulatedObservation(spec, next_claim.epoch, False, "ABSENT", True)))
    expect(IntentCode.STATE, lambda: store.claim_reconciliation(operation_id))
    assert count_events(setup[0]) == before and fake.removes == 1


def test_cleanup_ack_without_removal_is_not_verified_clean(intent):
    _, store, _, operation_id, fake = intent
    claim = dispatched(intent)
    reconcile_simulated(store, claim, fake)
    fake.remove_effect = False
    cleanup_simulated(store, claim, fake)
    next_claim = store.claim_reconciliation(operation_id)
    assert reconcile_simulated(store, next_claim, fake).state == "VERIFIED_PRESENT"
    expect(IntentCode.STATE, lambda: cleanup_simulated(store, next_claim, fake))
    assert fake.removes == 1 and len(fake.resources) == 1


def test_unquiesced_present_resource_cannot_be_removed(intent):
    _, store, _, _, fake = intent
    claim = dispatched(intent)
    fake.quiesced = False
    assert reconcile_simulated(store, claim, fake).state == "VERIFIED_PRESENT"
    expect(IntentCode.STATE, lambda: cleanup_simulated(store, claim, fake))
    assert fake.removes == 0


@pytest.mark.parametrize("failure", [TimeoutError, RuntimeError])
def test_inspection_failure_is_sanitized_and_bounded(intent, failure):
    setup, store, lease, operation_id, fake = intent
    dispatch_simulated(store, lease, operation_id, fake)
    def broken(resource, epoch):
        raise failure("private credential path SQL")
    fake.inspect_hook = broken
    for index in range(3):
        claim = store.claim_reconciliation(operation_id)
        result = reconcile_simulated(store, claim, fake)
        assert result.state == ("TERMINAL_FAILURE" if index == 2 else "RECONCILIATION_REQUIRED")
        assert "private" not in repr(result)
    expect(IntentCode.STATE, lambda: store.claim_reconciliation(operation_id))
    assert fake.inspections == 3 and fake.creates == 1 and fake.removes == 0


def test_crashed_reconcilers_exhaust_durably_without_retrying_create(intent):
    setup, store, lease, operation_id, fake = intent
    dispatch_simulated(store, lease, operation_id, fake)
    for _ in range(3):
        claim = store.claim_reconciliation(operation_id)
        setup[2].value = claim.expires_at
    expect(IntentCode.EXHAUSTED, lambda: store.claim_reconciliation(operation_id))
    assert store.status(operation_id).state == "TERMINAL_FAILURE" and fake.creates == 1


def test_database_locked_during_inspection_ack_preserves_unknown(intent):
    setup, store, _, operation_id, fake = intent
    claim = dispatched(intent)
    spec = store.inspection_resource(claim)
    observation = fake.simulate_inspect(spec, inspection_epoch=claim.epoch, timeout=1.0)
    with setup[0].transaction():
        with pytest.raises(JobError) as caught:
            store.record_observation(claim, observation)
        assert caught.value.code is JobCode.DATABASE_BUSY
    assert store.status(operation_id).state == "DISPATCH_UNCERTAIN"
    assert store.record_observation(claim, observation).state == "VERIFIED_PRESENT"


def test_dispatch_audit_failure_rolls_back_and_produces_no_external_effect(intent, monkeypatch):
    setup, store, lease, operation_id, fake = intent
    original = setup[0].append_audit_event
    def broken(*args, **kwargs):
        raise sqlite3.OperationalError("private commit boundary error")
    monkeypatch.setattr(setup[0], "append_audit_event", broken)
    with pytest.raises(JobError):
        dispatch_simulated(store, lease, operation_id, fake)
    assert fake.creates == 0 and store.status(operation_id).state == "INTENT_RECORDED"
    monkeypatch.setattr(setup[0], "append_audit_event", original)
    dispatch_simulated(store, lease, operation_id, fake)
    assert fake.creates == 1


@pytest.mark.parametrize("commit_applied", [False, True])
def test_commit_error_before_or_after_commit_never_dispatches(intent, monkeypatch, commit_applied):
    setup, store, lease, operation_id, fake = intent
    original = setup[0].transaction
    @contextmanager
    def failed_commit():
        with original() as connection:
            yield connection
            if not commit_applied:
                raise sqlite3.OperationalError("commit did not apply")
        if commit_applied:
            raise sqlite3.OperationalError("commit acknowledgement lost")
    with monkeypatch.context() as patch:
        patch.setattr(setup[0], "transaction", failed_commit)
        with pytest.raises(JobError):
            dispatch_simulated(store, lease, operation_id, fake)
    assert fake.creates == 0
    assert store.status(operation_id).state == ("DISPATCH_UNCERTAIN" if commit_applied else "INTENT_RECORDED")
    if commit_applied:
        with pytest.raises(JobError):
            dispatch_simulated(store, lease, operation_id, fake)
        claim = store.claim_reconciliation(operation_id)
        assert reconcile_simulated(store, claim, fake).state == "VERIFIED_ABSENT"


def test_observation_commit_failure_keeps_prior_state_and_audit(intent, monkeypatch):
    setup, store, _, operation_id, fake = intent
    claim = dispatched(intent)
    before = count_events(setup[0])
    original = setup[0].append_audit_event
    def broken(*args, **kwargs):
        raise sqlite3.OperationalError("private rollback")
    monkeypatch.setattr(setup[0], "append_audit_event", broken)
    with pytest.raises(JobError):
        reconcile_simulated(store, claim, fake)
    assert store.status(operation_id).state == "DISPATCH_UNCERTAIN" and count_events(setup[0]) == before
    monkeypatch.setattr(setup[0], "append_audit_event", original)
    assert reconcile_simulated(store, claim, fake).state == "VERIFIED_PRESENT"


def test_revocation_during_create_allows_only_cleanup_recovery(intent):
    setup, store, lease, operation_id, fake = intent
    fake.create_hook = lambda: setup[-2].revoke(setup[3].credential, setup[3].principal.session_id)
    dispatch_simulated(store, lease, operation_id, fake)
    with pytest.raises(JobError):
        dispatch_simulated(store, lease, operation_id, fake)
    claim = store.claim_reconciliation(operation_id)
    assert reconcile_simulated(store, claim, fake).state == "VERIFIED_PRESENT"
    cleanup_simulated(store, claim, fake)
    next_claim = store.claim_reconciliation(operation_id)
    assert reconcile_simulated(store, next_claim, fake).state == "VERIFIED_CLEANED"
    with setup[0].connection() as connection:
        run = connection.execute("SELECT * FROM runs WHERE run_id=?", (lease.run_id,)).fetchone()
        assert run["cancel_requested_at"] is not None and run["state"] != "COMPLETE"


@pytest.mark.parametrize("iteration", range(5))
def test_cancellation_racing_reconciliation_cannot_authorize_execution(intent, iteration):
    setup, store, _, operation_id, fake = intent
    claim = dispatched(intent)
    gate = Barrier(2)
    def cancel():
        gate.wait(timeout=5)
        return setup[-2].revoke(setup[3].credential, setup[3].principal.session_id)
    def reconcile():
        gate.wait(timeout=5)
        return reconcile_simulated(store, claim, fake)
    with ThreadPoolExecutor(max_workers=2) as workers:
        cancellation = workers.submit(cancel)
        reconciliation = workers.submit(reconcile)
        cancellation.result(timeout=5)
        assert reconciliation.result(timeout=5).execution_enabled is False
    assert store.status(operation_id).state == "VERIFIED_PRESENT" and fake.creates == 1


def test_expired_session_cannot_dispatch_but_can_reconcile_without_deadline_extension(intent):
    setup, store, lease, operation_id, fake = intent
    before = record(setup[0], operation_id)
    setup[2].value = setup[3].principal.expires_at
    with pytest.raises(JobError):
        dispatch_simulated(store, lease, operation_id, fake)
    claim = store.claim_reconciliation(operation_id)
    assert reconcile_simulated(store, claim, fake).state == "VERIFIED_ABSENT"
    assert record(setup[0], operation_id)["origin_epoch"] == before["origin_epoch"]
    assert fake.creates == 0
    with setup[0].connection() as connection:
        assert connection.execute("SELECT deadline_at-admitted_at FROM runs WHERE run_id=?", (lease.run_id,)).fetchone()[0] == 180


def test_unresolved_intent_blocks_cleanup_even_if_adapter_claims_success(intent):
    import asyncio
    from backend.security.lifecycle import CleanupVerification
    setup, store, lease, operation_id, fake = intent
    dispatch_simulated(store, lease, operation_id, fake)
    receipt = setup[-2].revoke(setup[3].credential, setup[3].principal.session_id)
    class UntrustedSuccess:
        async def remove_and_verify(self, context):
            return CleanupVerification(context.session_id, True)
    coordinator = LifecycleCoordinator(setup[0], setup[-1], runner=UntrustedSuccess(), storage=UntrustedSuccess())
    asyncio.run(coordinator.run_once())
    with setup[0].connection() as connection:
        cleanup = connection.execute("SELECT * FROM cleanup_requests WHERE request_id=?", (receipt,)).fetchone()
        assert cleanup["state"] != "COMPLETE" and cleanup["failure_recorded"] == 1
        assert cleanup["deadline_at"] == cleanup["requested_at"] + 300
        assert connection.execute("SELECT 1 FROM sessions WHERE session_id=?", (lease.session_id,)).fetchone()
    assert store.status(operation_id).state == "DISPATCH_UNCERTAIN" and fake.removes == 0


def test_resolved_simulation_changes_only_simulated_cleanup_inventory(intent):
    setup, store, lease, operation_id, fake = intent
    claim = dispatched(intent)
    reconcile_simulated(store, claim, fake)
    cleanup_simulated(store, claim, fake)
    next_claim = store.claim_reconciliation(operation_id)
    result = reconcile_simulated(store, next_claim, fake)
    assert result.state == "VERIFIED_CLEANED" and result.real_resource_cleanup_verified is False
    setup[-2].revoke(setup[3].credential, setup[3].principal.session_id)
    coordinator = LifecycleCoordinator(setup[0], setup[-1])
    cleanup_claim = coordinator._claim()
    storage, runtime = coordinator._inventory(cleanup_claim)
    assert storage is True and runtime is False
    with setup[0].connection() as connection:
        assert connection.execute("SELECT count(*) FROM attempts").fetchone()[0] == 0
        assert connection.execute("SELECT state FROM runs WHERE run_id=?", (lease.run_id,)).fetchone()[0] == "QUEUED"


def test_unresolved_metadata_cannot_be_discarded(intent):
    setup, _, _, operation_id, _ = intent
    with pytest.raises(sqlite3.IntegrityError):
        with setup[0].transaction() as connection:
            connection.execute("DELETE FROM external_intents WHERE operation_id=?", (operation_id,))
    with pytest.raises(sqlite3.IntegrityError):
        with setup[0].transaction() as connection:
            connection.execute("DELETE FROM runs WHERE runner_job_id=?", (intent[2].job_id,))


def test_non_simulated_driver_rejected_and_runtime_gates_preserved(intent):
    _, store, lease, operation_id, fake = intent
    fake.simulation_only = False
    expect(IntentCode.SIMULATION_ONLY, lambda: dispatch_simulated(store, lease, operation_id, fake))
    assert store.status(operation_id).state == "INTENT_RECORDED" and fake.creates == 0
    assert SandboxPolicy().execution_enabled is False
    with pytest.raises(RunnerNotReady):
        require_execution_ready()


def old_database(tmp_path, monkeypatch):
    import backend.storage.database as module
    database = Database(Settings(_env_file=None, database_path=tmp_path / "v5.sqlite3"))
    with monkeypatch.context() as patch:
        patch.setattr(module, "SCHEMA_VERSION", 5)
        database.initialize()
        with database.transaction() as connection:
            connection.execute("INSERT INTO sessions(session_id,auth_token_hash,audit_pseudonym) VALUES ('old',?,'old')", ("a" * 64,))
            connection.execute("""INSERT INTO datasets(dataset_id,session_id,source_sha256,storage_ref,file_type,
                byte_count,idempotency_key,request_sha256) VALUES ('old','old',?,'sample','csv',1,'old',?)""", ("a" * 64, "b" * 64))
            connection.execute("INSERT INTO dataset_versions(dataset_id,version,session_id) VALUES ('old',1,'old')")
            connection.execute("""INSERT INTO runs(run_id,session_id,dataset_id,dataset_version,question,
                idempotency_key,request_sha256,runner_job_id,prep_protocol_version,prep_fixture_id,
                prep_payload_length,prep_payload_sha256,prep_state,prep_created_at,prep_updated_at)
                VALUES ('old','old','old',1,'Sample','old',?,?,1,'smoke-v1',1,?,'CREATED',unixepoch(),unixepoch())""",
                ("c" * 64, "d" * 32, "e" * 64))
    return database


def test_migration_v5_preserves_populated_run_and_checks_relationships(tmp_path, monkeypatch):
    database = old_database(tmp_path, monkeypatch)
    database.initialize()
    database.initialize()
    database.check_ready(full_integrity=True)
    with database.connection() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        assert connection.execute("SELECT runner_job_id FROM runs").fetchone()[0] == "d" * 32
        assert connection.execute("SELECT count(*) FROM external_intents").fetchone()[0] == 0
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_migration_v6_failure_rolls_back_table_and_version(tmp_path, monkeypatch):
    database = old_database(tmp_path, monkeypatch)
    with monkeypatch.context() as patch:
        patch.setitem(MIGRATIONS, 6, (*MIGRATIONS[6], "INVALID SQL"))
        with pytest.raises(sqlite3.OperationalError):
            database.initialize()
    with sqlite3.connect(database.path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 5
        assert connection.execute("SELECT name FROM sqlite_schema WHERE name='external_intents'").fetchone() is None
        assert connection.execute("SELECT runner_job_id FROM runs").fetchone()[0] == "d" * 32
    database.initialize()
    database.check_ready(full_integrity=True)
