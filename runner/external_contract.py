"""Simulation-only external-operation vocabulary, without daemon or I/O code."""

from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True, slots=True)
class SimulatedResource:
    operation_id: str
    job_id: str
    run_id: str
    session_id: str
    origin_epoch: int
    resource_id: str
    ownership_nonce: str = field(repr=False)
    image_id: str
    config_digest: str
    simulation_only: bool = field(default=True, init=False)

    @property
    def name(self) -> str:
        return f"simulated-sheetsafe-{self.resource_id}"


@dataclass(frozen=True, slots=True)
class SimulatedObservation:
    resource: SimulatedResource
    inspection_epoch: int
    present: bool
    lifecycle: str
    actions_quiesced: bool
    simulation_only: bool = field(default=True, init=False)


class FakeExternalTransport(Protocol):
    """Only injected in-memory test fakes implement this milestone's contract.

    Quiescence is synthetic evidence that no old create/remove can arrive later.
    A real driver cannot assert it from a name lookup, timeout or elapsed lease.
    No such driver is implemented or authorized. Timeouts here are cooperative.
    """

    simulation_only: bool

    def simulate_create(self, resource: SimulatedResource, *, timeout: float) -> object: ...
    def simulate_inspect(self, resource: SimulatedResource, *, inspection_epoch: int,
        timeout: float) -> SimulatedObservation: ...
    def simulate_remove(self, resource: SimulatedResource, *, timeout: float) -> object: ...
