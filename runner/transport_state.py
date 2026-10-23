"""One-shot simulated preparation only. No production transport or admission.

Injected receive/close methods are used with in-memory fakes in this milestone.
Their timeout contract is cooperative: this harness cannot preempt a blocking
implementation. No stdin, sockets, files, Docker or generated code are handled.
"""

from asyncio import CancelledError
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
import math
from threading import Lock
import time
from typing import Protocol

from runner.policy import SandboxPolicy
from runner.transport_protocol import (
    FrameValidator, InputManifest, JobBinding, MAX_FRAME_BYTES, PayloadEvidence,
    TransportCode, TransportError, validate_manifest,
)


PREPARATION_SECONDS = 10.0
IDLE_SECONDS = 1.0
MAX_TRANSPORT_READS = 4096


class FrameTransport(Protocol):
    def receive(self, *, max_bytes: int, timeout: float) -> bytes | None: ...
    def close(self) -> None: ...


class PreparationState(StrEnum):
    CREATED = "CREATED"
    RECEIVING = "RECEIVING"
    INPUT_VERIFIED = "INPUT_VERIFIED"
    READY_FOR_EXECUTION = "READY_FOR_EXECUTION"  # Logical test label only.
    FAILED = "FAILED"
    INTERRUPTED = "INTERRUPTED"
    TIMED_OUT = "TIMED_OUT"
    CANCELLED = "CANCELLED"


@dataclass(frozen=True, slots=True)
class PreparationReceipt:
    job_id: str
    state: PreparationState
    history: tuple[PreparationState, ...]
    failure: TransportCode | None
    payload: PayloadEvidence | None
    stream_close_returned: bool
    execution_enabled: bool = field(default=False, init=False)
    persistent_authorization_verified: bool = field(default=False, init=False)
    input_immutability_verified: bool = field(default=False, init=False)
    cleanup_verified: bool = field(default=False, init=False)
    unverified_controls: tuple[str, ...] = field(default=SandboxPolicy().unverified_controls, init=False)


class PreparationSimulator:
    def __init__(self, manifest: InputManifest, *, lease_is_current: Callable[[JobBinding], bool],
            cancelled: Callable[[], bool] = lambda: False, clock: Callable[[], float] = time.monotonic,
            on_stage: Callable[[PreparationState, PayloadEvidence | None], None] | None = None) -> None:
        if type(manifest) is not InputManifest:
            raise TransportError(TransportCode.MALFORMED_MANIFEST)
        self._manifest, self._lease, self._cancelled, self._clock = manifest, lease_is_current, cancelled, clock
        self._on_stage = on_stage
        self._state = PreparationState.CREATED
        self._history = [self._state]
        self._lock = Lock()

    def _move(self, state: PreparationState, payload: PayloadEvidence | None = None) -> None:
        # An optional trusted persistence hook commits before a successful stage.
        # Terminal simulation changes never invoke it or hide a failed commit.
        if self._on_stage is not None and state in (
                PreparationState.RECEIVING, PreparationState.INPUT_VERIFIED,
                PreparationState.READY_FOR_EXECUTION):
            self._on_stage(state, payload)
        self._state = state
        self._history.append(state)

    def _now(self) -> float:
        value = self._clock()
        if type(value) not in (int, float) or not math.isfinite(value):
            raise TransportError(TransportCode.TIMED_OUT)
        return value

    def prepare(self, encoded_manifest: bytes, transport: FrameTransport) -> PreparationReceipt:
        if not self._lock.acquire(blocking=False):
            raise TransportError(TransportCode.DUPLICATE_DELIVERY)
        try:
            if self._state is not PreparationState.CREATED:
                raise TransportError(TransportCode.DUPLICATE_DELIVERY)
            return self._prepare(encoded_manifest, transport)
        finally:
            self._lock.release()

    def _prepare(self, encoded: bytes, transport: FrameTransport) -> PreparationReceipt:
        failure, payload, closed, close_attempted = None, None, False, False
        try:
            previous = start = self._now()
            def guard():
                nonlocal previous
                now = self._now()
                if now < previous or now - start >= PREPARATION_SECONDS:
                    raise TransportError(TransportCode.TIMED_OUT)
                previous = now
                cancel = self._cancelled()
                if type(cancel) is not bool:
                    raise TransportError(TransportCode.UNEXPECTED_TRANSPORT)
                if cancel:
                    raise TransportError(TransportCode.CANCELLED)
                if self._lease(self._manifest.binding) is not True:
                    raise TransportError(TransportCode.STALE_LEASE)
                return now
            guard()
            validate_manifest(encoded, self._manifest)
            validator = FrameValidator(self._manifest)
            self._move(PreparationState.RECEIVING)
            for _ in range(MAX_TRANSPORT_READS):
                before = guard()
                timeout = min(IDLE_SECONDS, PREPARATION_SECONDS - (before - start))
                chunk = transport.receive(max_bytes=MAX_FRAME_BYTES, timeout=timeout)
                after = guard()
                if after - before >= timeout:
                    raise TransportError(TransportCode.TIMED_OUT)
                if chunk is None:  # Explicit complete-stream EOF, not an empty fragment.
                    payload = validator.finish()
                    self._move(PreparationState.INPUT_VERIFIED, payload)
                    break
                validator.feed(chunk)
            else:
                raise TransportError(TransportCode.READ_LIMIT)
            close_attempted = True
            transport.close()
            closed = True
            guard()  # Late revocation/cancellation/timeout still prevents logical readiness.
            self._move(PreparationState.READY_FOR_EXECUTION)
        except TransportError as error:
            failure = error.code
        except TimeoutError:
            failure = TransportCode.TIMED_OUT
        except CancelledError:
            failure = TransportCode.CANCELLED
        except (InterruptedError, EOFError):
            failure = TransportCode.INTERRUPTED
        except Exception:
            failure = TransportCode.UNEXPECTED_TRANSPORT
        except BaseException:
            self._move(PreparationState.INTERRUPTED)
            raise
        finally:
            if not close_attempted:
                try:
                    transport.close()
                    closed = True
                except CancelledError:
                    failure = failure or TransportCode.CANCELLED
                except Exception:
                    failure = failure or TransportCode.UNEXPECTED_TRANSPORT
                except BaseException:
                    if self._state is not PreparationState.INTERRUPTED:
                        self._move(PreparationState.INTERRUPTED)
                    raise
        if failure is not None:
            state = {TransportCode.TIMED_OUT: PreparationState.TIMED_OUT,
                TransportCode.CANCELLED: PreparationState.CANCELLED,
                TransportCode.INTERRUPTED: PreparationState.INTERRUPTED}.get(failure, PreparationState.FAILED)
            self._move(state)
        return PreparationReceipt(self._manifest.binding.job_id, self._state, tuple(self._history), failure, payload, closed)
