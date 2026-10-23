"""One bounded fake operation/inspection, never a Docker driver or executor."""

from backend.storage.external_intents import ExternalIntentStore, IntentCode, IntentError, IntentSnapshot, ReconciliationLease
from backend.storage.jobs import JobLease
from runner.external_contract import FakeExternalTransport


FAKE_IO_TIMEOUT_SECONDS = 1.0


def _fake(transport: FakeExternalTransport) -> None:
    if getattr(transport, "simulation_only", None) is not True:
        raise IntentError(IntentCode.SIMULATION_ONLY)


def dispatch_simulated(store: ExternalIntentStore, lease: JobLease, operation_id: str,
        transport: FakeExternalTransport) -> IntentSnapshot:
    _fake(transport)
    resource = store.begin_dispatch(lease, operation_id)  # Commit before I/O.
    try:
        transport.simulate_create(resource, timeout=FAKE_IO_TIMEOUT_SECONDS)
    except Exception:
        pass  # No acknowledgement, including a timeout, proves absence/success.
    # Acks are deliberately not consumed as evidence; uncertainty stays durable.
    return store.status(operation_id)


def reconcile_simulated(store: ExternalIntentStore, lease: ReconciliationLease,
        transport: FakeExternalTransport) -> IntentSnapshot:
    _fake(transport)
    resource = store.inspection_resource(lease)
    try:
        observation = transport.simulate_inspect(resource, inspection_epoch=lease.epoch,
            timeout=FAKE_IO_TIMEOUT_SECONDS)
    except TimeoutError:
        return store.inspection_failed(lease, timed_out=True)
    except Exception:
        return store.inspection_failed(lease)
    return store.record_observation(lease, observation)


def cleanup_simulated(store: ExternalIntentStore, lease: ReconciliationLease,
        transport: FakeExternalTransport) -> IntentSnapshot:
    _fake(transport)
    resource = store.begin_cleanup(lease)  # Commit unknown removal before I/O.
    try:
        transport.simulate_remove(resource, timeout=FAKE_IO_TIMEOUT_SECONDS)
    except Exception:
        pass  # Still CLEANUP_REQUIRED until independent, quiesced absence proof.
    return store.status(lease.operation_id)
