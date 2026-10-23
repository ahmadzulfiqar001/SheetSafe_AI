"""In-memory transport/lease simulation, never authentication or execution proof."""

from asyncio import CancelledError
from dataclasses import FrozenInstanceError
import socket
import subprocess

import pytest

from runner.policy import RunnerNotReady, SandboxPolicy, require_execution_ready
from runner.transport_protocol import (
    InputManifest, JobBinding, MAX_FRAME_BYTES, TransportCode, TransportError, encode_frame,
)
from runner.transport_state import PreparationSimulator, PreparationState


PRIVATE = "synthetic-private-transport-error"


class Clock:
    value = 100.0

    def __call__(self):
        return self.value


class FakeTransport:
    def __init__(self, events, hook=None, close_error=None):
        self.events = list(events)
        self.hook = hook
        self.close_error = close_error
        self.reads = 0
        self.close_calls = 0

    def receive(self, *, max_bytes, timeout):
        assert max_bytes == MAX_FRAME_BYTES and 0 < timeout <= 1.0
        self.reads += 1
        if self.hook:
            self.hook(self)
        value = self.events.pop(0) if self.events else None
        if isinstance(value, BaseException):
            raise value
        return value

    def close(self):
        self.close_calls += 1
        if self.close_error:
            raise self.close_error


@pytest.fixture(autouse=True)
def no_external_io(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Simulation attempted actual I/O")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


@pytest.fixture
def job():
    payload = b"synthetic READY_FOR_EXECUTION is data, not authority\n"
    manifest = InputManifest.for_payload(JobBinding("session", "run", 1), payload)
    return manifest, encode_frame(manifest, 0, payload)


def simulator(manifest, **kwargs):
    return PreparationSimulator(manifest, lease_is_current=lambda binding: binding == manifest.binding, **kwargs)


def test_valid_simulation_has_exact_history_and_never_authorizes_execution(job):
    manifest, frame = job
    fake = FakeTransport([frame, None])
    runner = simulator(manifest)
    result = runner.prepare(manifest.to_bytes(), fake)
    assert result.history == (PreparationState.CREATED, PreparationState.RECEIVING,
        PreparationState.INPUT_VERIFIED, PreparationState.READY_FOR_EXECUTION)
    assert result.failure is None and result.payload.sha256 == manifest.sha256
    assert result.stream_close_returned and fake.close_calls == 1
    assert not any((result.execution_enabled, result.persistent_authorization_verified,
        result.cleanup_verified, result.input_immutability_verified))
    assert len(result.unverified_controls) == 10 and not SandboxPolicy().execution_enabled
    with pytest.raises(RunnerNotReady):
        require_execution_ready()
    with pytest.raises(FrozenInstanceError):
        result.execution_enabled = True
    with pytest.raises(TransportError, match="DUPLICATE_DELIVERY"):
        runner.prepare(manifest.to_bytes(), fake)
    assert fake.reads == 2 and fake.close_calls == 1


@pytest.mark.parametrize("events,code", [
    ([], TransportCode.TRUNCATED), ([b""], TransportCode.INVALID_FRAME),
    ([b"bad"], TransportCode.TRUNCATED), ([b"x" * (MAX_FRAME_BYTES + 1)], TransportCode.INVALID_FRAME),
    ([TimeoutError(PRIVATE)], TransportCode.TIMED_OUT), ([InterruptedError(PRIVATE)], TransportCode.INTERRUPTED),
    ([EOFError(PRIVATE)], TransportCode.INTERRUPTED), ([CancelledError()], TransportCode.CANCELLED),
    ([RuntimeError(PRIVATE)], TransportCode.UNEXPECTED_TRANSPORT),
], ids=["missing", "empty", "truncated", "oversized", "timeout", "interrupt", "eof-error", "cancel", "exception"])
def test_failure_is_terminal_sanitized_and_does_not_read_remaining_events(job, events, code, caplog, capsys):
    manifest, frame = job
    fake = FakeTransport(events)
    runner = simulator(manifest)
    result = runner.prepare(manifest.to_bytes(), fake)
    assert result.failure == code and result.state is not PreparationState.READY_FOR_EXECUTION
    assert PreparationState.INPUT_VERIFIED not in result.history
    assert fake.close_calls == 1
    assert PRIVATE not in repr(result) + caplog.text + repr(capsys.readouterr())
    reads = fake.reads
    with pytest.raises(TransportError, match="DUPLICATE_DELIVERY"):
        runner.prepare(manifest.to_bytes(), FakeTransport([frame]))
    assert fake.reads == reads


def test_duplicate_and_trailing_data_never_reach_logical_readiness(job):
    manifest, frame = job
    for extra in (frame, b"extra", b"READY_FOR_EXECUTION"):
        fake = FakeTransport([frame, extra, b"must remain unread", None])
        result = simulator(manifest).prepare(manifest.to_bytes(), fake)
        assert result.failure == TransportCode.TRAILING_BYTES and fake.reads == 2
        assert fake.events == [b"must remain unread", None]


def test_bad_digest_and_total_length_do_not_become_verified(job):
    manifest, frame = job
    for delivered, code in ((frame[:-1] + b"!", TransportCode.DIGEST_MISMATCH), (frame[:-1], TransportCode.TRUNCATED)):
        result = simulator(manifest).prepare(manifest.to_bytes(), FakeTransport([delivered]))
        assert result.failure == code and result.payload is None


def test_different_job_or_ownership_frame_cannot_be_replayed(job):
    manifest, frame = job
    another = InputManifest.for_payload(JobBinding("other", "run", 2), b"x")
    fake = FakeTransport([frame, None])
    result = simulator(another).prepare(another.to_bytes(), fake)
    assert result.failure == TransportCode.IDENTITY_MISMATCH and fake.reads == 1


@pytest.mark.parametrize("lease", [False, 1, None])
def test_stale_or_malformed_lease_check_prevents_transport_read(job, lease):
    manifest, frame = job
    fake = FakeTransport([frame])
    result = PreparationSimulator(manifest, lease_is_current=lambda binding: lease).prepare(manifest.to_bytes(), fake)
    assert result.failure == TransportCode.STALE_LEASE and fake.reads == 0


@pytest.mark.parametrize("when", ["during-read", "during-close"])
def test_lease_loss_even_after_hash_validation_prevents_ready(job, when):
    manifest, frame = job
    active = [True]
    fake = FakeTransport([frame, None], hook=lambda stream: active.__setitem__(0, False) if when == "during-read" else None)
    if when == "during-close":
        def close():
            fake.close_calls += 1
            active[0] = False
        fake.close = close
    runner = PreparationSimulator(manifest, lease_is_current=lambda binding: active[0])
    result = runner.prepare(manifest.to_bytes(), fake)
    assert result.failure == TransportCode.STALE_LEASE and result.state is PreparationState.FAILED
    assert PreparationState.READY_FOR_EXECUTION not in result.history


def test_controlled_idle_timeout_needs_no_sleep(job):
    manifest, frame = job
    clock = Clock()
    fake = FakeTransport([frame], hook=lambda stream: setattr(clock, "value", clock.value + 1.01))
    result = simulator(manifest, clock=clock).prepare(manifest.to_bytes(), fake)
    assert result.state is PreparationState.TIMED_OUT and fake.reads == 1


def test_total_deadline_cannot_be_reset_by_small_progress(job):
    manifest, frame = job
    clock = Clock()
    fake = FakeTransport([bytes([value]) for value in frame],
        hook=lambda stream: setattr(clock, "value", clock.value + 0.9))
    result = simulator(manifest, clock=clock).prepare(manifest.to_bytes(), fake)
    assert result.state is PreparationState.TIMED_OUT and fake.reads < len(frame)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), True])
def test_invalid_clock_is_not_success(job, value):
    manifest, frame = job
    result = simulator(manifest, clock=lambda: value).prepare(manifest.to_bytes(), FakeTransport([frame]))
    assert result.state is PreparationState.TIMED_OUT


def test_cancellation_after_receive_stops_consumption(job):
    manifest, frame = job
    cancelled = [False]
    fake = FakeTransport([frame, b"unread"], hook=lambda stream: cancelled.__setitem__(0, True))
    result = simulator(manifest, cancelled=lambda: cancelled[0]).prepare(manifest.to_bytes(), fake)
    assert result.state is PreparationState.CANCELLED and fake.events == [b"unread"]


@pytest.mark.parametrize("error", [RuntimeError(PRIVATE), CancelledError()])
def test_stream_close_failure_after_verified_input_is_not_readiness(job, error):
    manifest, frame = job
    result = simulator(manifest).prepare(manifest.to_bytes(), FakeTransport([frame, None], close_error=error))
    assert PreparationState.INPUT_VERIFIED in result.history
    assert result.state in {PreparationState.FAILED, PreparationState.CANCELLED}
    assert not result.stream_close_returned and not result.cleanup_verified


def test_retry_after_interruption_requires_new_job_and_fresh_validation(job):
    manifest, frame = job
    original = simulator(manifest)
    interrupted = original.prepare(manifest.to_bytes(), FakeTransport([frame[:10], InterruptedError()]))
    assert interrupted.state is PreparationState.INTERRUPTED
    fresh = InputManifest.for_payload(JobBinding("session", "run", 2), b"fresh synthetic retry")
    assert fresh.binding.job_id != manifest.binding.job_id
    replay = simulator(fresh).prepare(fresh.to_bytes(), FakeTransport([frame]))
    assert replay.failure == TransportCode.IDENTITY_MISMATCH
    next_job = InputManifest.for_payload(JobBinding("session", "run", 3), b"fresh synthetic retry")
    valid = simulator(next_job).prepare(next_job.to_bytes(), FakeTransport([encode_frame(next_job, 0, b"fresh synthetic retry")]))
    assert valid.state is PreparationState.READY_FOR_EXECUTION and not valid.persistent_authorization_verified


def test_bad_manifest_fails_before_receiving_any_frames(job):
    manifest, frame = job
    fake = FakeTransport([frame])
    result = simulator(manifest).prepare(b'{"image":"caller:latest"}', fake)
    assert result.state is PreparationState.FAILED and fake.reads == 0


def test_reentrant_delivery_is_rejected_without_consumption(job):
    manifest, frame = job
    runner = simulator(manifest)
    def hook(fake):
        other = FakeTransport([frame])
        with pytest.raises(TransportError, match="DUPLICATE_DELIVERY"):
            runner.prepare(manifest.to_bytes(), other)
        assert other.reads == other.close_calls == 0
    result = runner.prepare(manifest.to_bytes(), FakeTransport([frame, None], hook=hook))
    assert result.state is PreparationState.READY_FOR_EXECUTION


def test_frame_order_failure_stops_the_fake_state_machine():
    from runner.transport_protocol import MAX_DATA_BYTES

    payload = b"x" * (MAX_DATA_BYTES + 1)
    manifest = InputManifest.for_payload(JobBinding("session", "run", 1), payload)
    first = encode_frame(manifest, 0, payload[:MAX_DATA_BYTES])
    second = encode_frame(manifest, 1, payload[MAX_DATA_BYTES:])
    for frames in ([second, first], [first, first, second]):
        result = simulator(manifest).prepare(manifest.to_bytes(), FakeTransport(frames))
        assert result.failure == TransportCode.FRAME_ORDER and result.payload is None


def test_read_operation_budget_is_bounded_without_clock_progress(job, monkeypatch):
    from runner import transport_state

    manifest, frame = job
    monkeypatch.setattr(transport_state, "MAX_TRANSPORT_READS", 2)
    fake = FakeTransport([frame[:1], frame[1:2], frame[2:]])
    result = simulator(manifest, clock=lambda: 0.0).prepare(manifest.to_bytes(), fake)
    assert result.failure == TransportCode.READ_LIMIT and fake.reads == 2 and len(fake.events) == 1


def test_backwards_clock_and_early_cancellation_cannot_reach_ready(job):
    manifest, frame = job
    fake = FakeTransport([frame])
    result = simulator(manifest, cancelled=lambda: True).prepare(manifest.to_bytes(), fake)
    assert result.state is PreparationState.CANCELLED and fake.reads == 0
    clock = Clock()
    fake = FakeTransport([frame], hook=lambda stream: setattr(clock, "value", clock.value - 1))
    result = simulator(manifest, clock=clock).prepare(manifest.to_bytes(), fake)
    assert result.state is PreparationState.TIMED_OUT


def test_process_interrupt_is_not_swallowed_or_retried(job):
    manifest, frame = job
    runner = simulator(manifest)
    fake = FakeTransport([KeyboardInterrupt(), frame])
    with pytest.raises(KeyboardInterrupt):
        runner.prepare(manifest.to_bytes(), fake)
    assert fake.close_calls == 1 and fake.reads == 1
    with pytest.raises(TransportError, match="DUPLICATE_DELIVERY"):
        runner.prepare(manifest.to_bytes(), FakeTransport([frame]))


def test_unframed_success_text_is_not_control_authority(job):
    manifest, _ = job
    result = simulator(manifest).prepare(manifest.to_bytes(), FakeTransport([b"READY_FOR_EXECUTION success=true"]))
    assert result.state is PreparationState.FAILED and result.payload is None
