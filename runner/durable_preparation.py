"""Operator-only SQLite integration for the in-memory fake preparation harness.

No concrete transport, execution API or worker loop. READY is persisted logical
validation only. A lease never authorizes Docker or artifact publication.
"""

from dataclasses import dataclass, field
import time
from collections.abc import Callable

from backend.storage.jobs import JobError, JobLease, JobStore
from runner.transport_protocol import PayloadEvidence
from runner.transport_state import (
    FrameTransport, PreparationReceipt, PreparationSimulator, PreparationState,
)


@dataclass(frozen=True, slots=True)
class DurablePreparationResult:
    simulation: PreparationReceipt
    persisted_state: str
    execution_enabled: bool = field(default=False, init=False)


def prepare_synthetic(store: JobStore, lease: JobLease, encoded_manifest: bytes,
        transport: FrameTransport, *, clock: Callable[[], float] = time.monotonic) -> DurablePreparationResult:
    """Trusted operator passes a test fake, never an HTTP-controlled transport.

    A failed DB commit/lease check raises; the harness receipt cannot override it.
    A crash leaves its last committed state for expiry-based bounded recovery.
    No transaction is held around receive/close. No automatic claim or retry.
    """
    manifest = store.manifest(lease)
    previous = PreparationState.CREATED
    persistence_error: JobError | None = None

    def current(binding):
        nonlocal persistence_error
        try:
            return store.current(lease, binding)
        except JobError as error:
            persistence_error = error
            raise

    def stage(target: PreparationState, payload: PayloadEvidence | None) -> None:
        nonlocal previous, persistence_error
        try:
            store.advance(lease, previous, target, payload)
        except JobError as error:
            persistence_error = error
            raise
        previous = target

    receipt = PreparationSimulator(manifest, lease_is_current=current,
        clock=clock, on_stage=stage).prepare(encoded_manifest, transport)
    if persistence_error is not None:
        raise persistence_error
    if receipt.state is not PreparationState.READY_FOR_EXECUTION:
        store.fail(lease, receipt.state.value)
    return DurablePreparationResult(receipt, receipt.state.value)
