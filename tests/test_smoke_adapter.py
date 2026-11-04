"""Unit tests for the operator-only native Linux Docker smoke adapter.

Uses in-memory fake Docker transports and synthetic clock harnesses;
never contacts a real daemon, creates processes, or opens network sockets.
"""

from copy import deepcopy
import json
import os
import socket
import subprocess
from threading import Event
import time

import pytest

from runner.docker_backend import (
    API_TIMEOUT_SECONDS,
    LOCAL_IMAGE_ID,
    ContainerJobSpec,
    ContainerNotFound,
    CreateRejected,
)
from runner.policy import FixtureRequest, SandboxPolicy
from runner.smoke_adapter import (
    DEFAULT_WALL_DEADLINE_SECONDS,
    FIXED_SMOKE_FIXTURE_ID,
    MAX_LOG_BYTES_PER_STREAM,
    DockerSmokeTransport,
    DryRunSmokeTransport,
    SmokeAdapter,
    SmokeAdmissionError,
    SmokeFailureCode,
    SmokeLifecycleState,
    SmokeOutcome,
    main,
)


@pytest.fixture(autouse=True)
def no_external_io(monkeypatch):
    attempts = []

    def forbidden(*args, **kwargs):
        attempts.append(True)
        raise AssertionError("Smoke adapter test attempted external execution or networking")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    yield
    assert not attempts, "External I/O was attempted, even if its exception was caught"


class FakeSmokeDocker:
    """Strict in-memory transport simulator for smoke execution testing."""

    def __init__(self) -> None:
        self.records: dict[str, dict] = {}
        self.calls: list[tuple[str, str]] = []
        self.counter = 0
        self.create_hook = None
        self.inspect_hook = None
        self.start_hook = None
        self.wait_hook = None
        self.kill_hook = None
        self.logs_hook = None
        self.remove_hook = None
        self.container_running = False
        self.exit_code = 0
        self.oom_killed = False
        self.cpu_usage_ns = 0
        self.stdout_bytes = b'{"fixture_id":"smoke-v1","marker_created":true,"protected_write_denied":true}\n'
        self.stderr_bytes = b""

    def create(self, spec: ContainerJobSpec, *, timeout: float) -> str:
        self.calls.append(("create", spec.name))
        if self.create_hook:
            return self.create_hook(self, spec)
        self.counter += 1
        cid = f"{self.counter:064x}"
        config = spec.create_body()
        host = config.pop("HostConfig")
        self.records[cid] = {
            "Id": cid,
            "Name": "/" + spec.name,
            "Image": LOCAL_IMAGE_ID,
            "Config": config,
            "HostConfig": host,
            "State": {
                "Status": "created",
                "Running": False,
                "Paused": False,
                "Restarting": False,
                "Dead": False,
                "Pid": 0,
                "ExitCode": 0,
                "OOMKilled": False,
            },
            "Mounts": [],
            "NetworkSettings": {"Ports": {}, "Networks": {"none": {}}},
            "AppArmorProfile": "docker-default",
            "CPUStats": {"cpu_usage": {"total_usage": self.cpu_usage_ns}},
        }
        return cid

    def inspect(self, reference: str, *, timeout: float) -> dict:
        self.calls.append(("inspect", reference))
        if self.inspect_hook:
            self.inspect_hook(self, reference)
        if reference in self.records:
            rec = deepcopy(self.records[reference])
            rec["State"]["Running"] = self.container_running
            rec["State"]["ExitCode"] = self.exit_code
            rec["State"]["OOMKilled"] = self.oom_killed
            rec["CPUStats"]["cpu_usage"]["total_usage"] = self.cpu_usage_ns
            return rec
        for metadata in self.records.values():
            if metadata["Name"] == "/" + reference:
                rec = deepcopy(metadata)
                rec["State"]["Running"] = self.container_running
                rec["State"]["ExitCode"] = self.exit_code
                rec["State"]["OOMKilled"] = self.oom_killed
                rec["CPUStats"]["cpu_usage"]["total_usage"] = self.cpu_usage_ns
                return rec
        raise ContainerNotFound(f"Container not found: {reference}")

    def start(self, container_id: str, *, timeout: float) -> None:
        self.calls.append(("start", container_id))
        if self.start_hook:
            self.start_hook(self, container_id)
        if container_id not in self.records:
            raise ContainerNotFound(container_id)
        self.container_running = True
        self.records[container_id]["State"]["Status"] = "running"
        self.records[container_id]["State"]["Running"] = True
        self.records[container_id]["State"]["Pid"] = 12345

    def wait(self, container_id: str, *, timeout: float) -> int:
        self.calls.append(("wait", container_id))
        if self.wait_hook:
            return self.wait_hook(self, container_id)
        self.container_running = False
        return self.exit_code

    def kill(self, container_id: str, *, signal: str, timeout: float) -> None:
        self.calls.append(("kill", f"{container_id}:{signal}"))
        if self.kill_hook:
            self.kill_hook(self, container_id, signal)
        self.container_running = False
        if container_id in self.records:
            self.records[container_id]["State"]["Status"] = "exited"
            self.records[container_id]["State"]["Running"] = False
            self.records[container_id]["State"]["ExitCode"] = 137

    def logs(
        self,
        container_id: str,
        *,
        stdout: bool,
        stderr: bool,
        max_bytes: int,
        timeout: float,
    ) -> bytes:
        self.calls.append(("logs", container_id))
        if self.logs_hook:
            return self.logs_hook(self, container_id, stdout=stdout, stderr=stderr)
        if stdout:
            return self.stdout_bytes[:max_bytes]
        if stderr:
            return self.stderr_bytes[:max_bytes]
        return b""

    def remove(self, container_id: str, *, force: bool, timeout: float) -> None:
        self.calls.append(("remove", container_id))
        if self.remove_hook:
            self.remove_hook(self, container_id)
        if container_id in self.records:
            del self.records[container_id]


class FakeEngineReader:
    def __init__(self, issues: tuple[str, ...] = ()) -> None:
        self._issues = issues

    def channel(self) -> dict:
        return {"Host": "unix:///var/run/docker.sock", "SkipTLSVerify": False}

    def version(self) -> dict:
        return {"ApiVersion": "1.47", "MinAPIVersion": "1.24"}

    def info(self) -> dict:
        return {
            "Driver": "overlay2",
            "OperatingSystem": "Ubuntu 24.04 LTS",
            "OSType": "linux",
            "Architecture": "x86_64",
            "SecurityOptions": ["name=seccomp,profile=builtin", "name=apparmor", "name=cgroupns"],
            "CgroupVersion": "2",
            "CgroupDriver": "systemd",
        }

    def image(self) -> list[dict]:
        from runner.engine_metadata import LOCAL_CONFIG_DIGEST

        return [
            {
                "Id": LOCAL_IMAGE_ID,
                "RepoTags": ["sheetsafe-runner:environment-review"],
                "RepoDigests": [],
                "Comment": "",
                "Created": "2026-10-22T04:14:00Z",
                "DockerVersion": "27.3.1",
                "Author": "",
                "Architecture": "amd64",
                "Os": "linux",
                "Size": 100000000,
                "GraphDriver": {"Name": "overlay2", "Data": {}},
                "RootFS": {"Type": "layers", "Layers": []},
                "Metadata": {"LastTagTime": "2026-10-22T04:14:00Z"},
                "Descriptor": {"mediaType": "application/vnd.docker.distribution.manifest.v2+json", "digest": LOCAL_IMAGE_ID, "size": 1234},
                "Config": {
                    "User": "10001:10001",
                    "Entrypoint": ["/usr/local/bin/python", "-I", "-S", "-B", "-u", "/opt/sheetsafe/bootstrap.py"],
                    "Cmd": ["smoke-v1"],
                    "WorkingDir": "/work",
                    "StopSignal": "SIGTERM",
                    "Env": ["LANG=C.UTF-8", "HOME=/nonexistent", "PATH=/usr/local/bin:/usr/bin:/bin"],
                    "ArgsEscaped": False,
                    "Labels": {
                        "org.opencontainers.image.title": "SheetSafe fixed smoke fixture",
                        "org.opencontainers.image.version": "smoke-v1",
                        "io.sheetsafe.policy": "sheetsafe-smoke-policy-v1",
                    },
                    "Healthcheck": {"Test": ["NONE"]},
                    "ExposedPorts": {},
                    "Volumes": {},
                },
            }
        ]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_smoke_adapter_dry_run_default():
    """Dry-run mode performs admission checks without creating containers."""
    fake_docker = FakeSmokeDocker()
    adapter = SmokeAdapter(fake_docker)

    receipt = adapter.run_smoke("smoke-v1", dry_run=True)

    assert receipt.dry_run is True
    assert receipt.state is SmokeLifecycleState.DRY_RUN
    assert receipt.outcome is SmokeOutcome.DRY_RUN_PASSED
    assert receipt.configuration_verified is True
    assert receipt.started is False
    assert receipt.container_id is None
    assert receipt.cleanup_confirmed is True
    assert receipt.failure is None
    assert receipt.execution_enabled is False
    assert receipt.production_authorized is False
    # Verifies zero container create/start calls were made
    assert len(fake_docker.calls) == 0


def test_smoke_adapter_rejects_unsupported_fixture():
    """Only smoke-v1 is accepted; any other input fails closed before transport."""
    fake_docker = FakeSmokeDocker()
    adapter = SmokeAdapter(fake_docker)

    with pytest.raises(SmokeAdmissionError) as exc_info:
        adapter.run_smoke("malicious_arbitrary_python_fixture")
    assert exc_info.value.code is SmokeFailureCode.UNSUPPORTED_FIXTURE

    with pytest.raises(SmokeAdmissionError) as exc_info:
        adapter.run_smoke("")
    assert exc_info.value.code is SmokeFailureCode.UNSUPPORTED_FIXTURE

    assert len(fake_docker.calls) == 0


def test_smoke_adapter_success_lifecycle():
    """Full successful execution lifecycle with verified container removal."""
    fake_docker = FakeSmokeDocker()
    # Container exits immediately upon inspection loop
    fake_docker.container_running = False
    fake_docker.exit_code = 0

    adapter = SmokeAdapter(fake_docker)
    receipt = adapter.run_smoke("smoke-v1", dry_run=False)

    assert receipt.dry_run is False
    assert receipt.state is SmokeLifecycleState.ABSENT
    assert receipt.outcome is SmokeOutcome.COMPLETED
    assert receipt.configuration_verified is True
    assert receipt.started is True
    assert receipt.exit_code == 0
    assert receipt.oom_killed is False
    assert receipt.timed_out is False
    assert receipt.cancelled is False
    assert receipt.cleanup_confirmed is True
    assert receipt.failure is None
    assert receipt.cleanup_failure is None
    assert receipt.stdout_snippet is not None
    assert "smoke-marker" in receipt.stdout_snippet or "protected_write_denied" in receipt.stdout_snippet

    # Verify lifecycle call sequence
    op_names = [call[0] for call in fake_docker.calls]
    assert "create" in op_names
    assert "inspect" in op_names
    assert "start" in op_names
    assert "logs" in op_names
    assert "remove" in op_names


def test_smoke_adapter_preflight_failure_fails_closed():
    """Preflight check failure halts admission before container create."""
    fake_docker = FakeSmokeDocker()
    bad_reader = FakeEngineReader()
    # Monkeypatch bad reader channel to simulate broken preflight
    bad_reader.channel = lambda: {"Host": "tcp://malicious:2375", "SkipTLSVerify": True}

    adapter = SmokeAdapter(fake_docker, preflight_reader=bad_reader)

    with pytest.raises(SmokeAdmissionError) as exc_info:
        adapter.run_smoke("smoke-v1", dry_run=False)
    assert exc_info.value.code is SmokeFailureCode.PREFLIGHT_FAILED

    assert len(fake_docker.calls) == 0


def test_smoke_adapter_failed_create_fails_closed():
    """If create raises CreateRejected, adapter handles cleanup and fails closed."""
    fake_docker = FakeSmokeDocker()

    def bad_create(self, spec):
        raise CreateRejected("Docker create rejected spec")

    fake_docker.create_hook = bad_create

    adapter = SmokeAdapter(fake_docker)
    receipt = adapter.run_smoke("smoke-v1", dry_run=False)

    assert receipt.outcome is SmokeOutcome.FAILED
    assert receipt.failure is SmokeFailureCode.CREATE_FAILED
    assert receipt.started is False
    assert receipt.cleanup_confirmed is True


def test_smoke_adapter_invalid_container_id_fails_closed():
    """Create returning non-64-hex container ID fails admission and cleans up."""
    fake_docker = FakeSmokeDocker()
    fake_docker.create_hook = lambda self, spec: "invalid-short-id"

    adapter = SmokeAdapter(fake_docker)
    receipt = adapter.run_smoke("smoke-v1", dry_run=False)

    assert receipt.outcome is SmokeOutcome.FAILED
    assert receipt.failure is SmokeFailureCode.INVALID_IDENTITY
    assert receipt.started is False


def test_smoke_adapter_policy_mismatch_aborts_and_cleans_up():
    """Tampered inspect metadata (e.g. root user) triggers POLICY_MISMATCH before start."""
    fake_docker = FakeSmokeDocker()

    def tampered_inspect(self, ref):
        # Allow initial inspect check to return bad user
        if ref in self.records:
            self.records[ref]["Config"]["User"] = "0:0"

    fake_docker.inspect_hook = tampered_inspect

    adapter = SmokeAdapter(fake_docker)
    receipt = adapter.run_smoke("smoke-v1", dry_run=False)

    assert receipt.outcome is SmokeOutcome.FAILED
    assert receipt.failure is SmokeFailureCode.POLICY_MISMATCH
    assert receipt.started is False
    assert receipt.cleanup_confirmed is True
    # Ensure start was never called
    assert not any(call[0] == "start" for call in fake_docker.calls)


def test_smoke_adapter_start_failure_aborts_and_cleans_up():
    """Engine error on start aborts and initiates verified cleanup."""
    fake_docker = FakeSmokeDocker()

    def bad_start(self, cid):
        raise RuntimeError("Failed to start container")

    fake_docker.start_hook = bad_start

    adapter = SmokeAdapter(fake_docker)
    receipt = adapter.run_smoke("smoke-v1", dry_run=False)

    assert receipt.outcome is SmokeOutcome.FAILED
    assert receipt.failure is SmokeFailureCode.START_FAILED
    assert receipt.started is False
    assert receipt.cleanup_confirmed is True


def test_smoke_adapter_watchdog_wall_timeout():
    """Container running past deadline is killed by monotonic watchdog."""
    fake_docker = FakeSmokeDocker()
    fake_docker.container_running = True

    simulated_time = 100.0

    def fake_clock():
        return simulated_time

    def fake_sleep(duration):
        nonlocal simulated_time
        simulated_time += 25.0  # Advance past 20.0s deadline in one step

    adapter = SmokeAdapter(fake_docker, clock=fake_clock, sleep_fn=fake_sleep)
    receipt = adapter.run_smoke("smoke-v1", dry_run=False, wall_deadline_seconds=20.0)

    assert receipt.outcome is SmokeOutcome.TIMED_OUT
    assert receipt.timed_out is True
    assert receipt.failure is SmokeFailureCode.TIMED_OUT
    assert receipt.cleanup_confirmed is True
    # Ensure kill was called
    assert any(call[0] == "kill" for call in fake_docker.calls)


def test_smoke_adapter_watchdog_cancellation():
    """External cancel event triggers watchdog kill and records cancelled."""
    fake_docker = FakeSmokeDocker()
    fake_docker.container_running = True
    cancel_evt = Event()

    simulated_time = 100.0

    def fake_clock():
        return simulated_time

    def fake_sleep(duration):
        cancel_evt.set()  # Simulate cancel event firing during wait

    adapter = SmokeAdapter(fake_docker, clock=fake_clock, sleep_fn=fake_sleep)
    receipt = adapter.run_smoke("smoke-v1", dry_run=False, cancel_event=cancel_evt)

    assert receipt.outcome is SmokeOutcome.CANCELLED
    assert receipt.cancelled is True
    assert receipt.failure is SmokeFailureCode.CANCELLED
    assert receipt.cleanup_confirmed is True
    assert any(call[0] == "kill" for call in fake_docker.calls)


def test_smoke_adapter_watchdog_cpu_limit_exceeded():
    """Cumulative CPU exceeding budget triggers watchdog kill."""
    fake_docker = FakeSmokeDocker()
    fake_docker.container_running = True
    # Set CPU usage to 11 seconds (exceeding 10s budget)
    fake_docker.cpu_usage_ns = int(11.5 * 1e9)

    adapter = SmokeAdapter(fake_docker)
    receipt = adapter.run_smoke("smoke-v1", dry_run=False, cpu_limit_seconds=10.0)

    assert receipt.outcome is SmokeOutcome.FAILED
    assert receipt.cpu_limit_exceeded is True
    assert receipt.failure is SmokeFailureCode.CPU_LIMIT_EXCEEDED
    assert receipt.cleanup_confirmed is True
    assert any(call[0] == "kill" for call in fake_docker.calls)


def test_smoke_adapter_container_exit_nonzero():
    """Container exiting with code 1 records failure."""
    fake_docker = FakeSmokeDocker()
    fake_docker.container_running = False
    fake_docker.exit_code = 1
    fake_docker.stderr_bytes = b"fixture_failed\n"

    adapter = SmokeAdapter(fake_docker)
    receipt = adapter.run_smoke("smoke-v1", dry_run=False)

    assert receipt.outcome is SmokeOutcome.FAILED
    assert receipt.exit_code == 1
    assert receipt.failure is SmokeFailureCode.EXECUTION_FAILED
    assert receipt.cleanup_confirmed is True


def test_smoke_adapter_oom_killed_detected():
    """OOMKilled flag on container state is recorded as OOM_KILLED."""
    fake_docker = FakeSmokeDocker()
    fake_docker.container_running = False
    fake_docker.exit_code = 137
    fake_docker.oom_killed = True

    adapter = SmokeAdapter(fake_docker)
    receipt = adapter.run_smoke("smoke-v1", dry_run=False)

    assert receipt.outcome is SmokeOutcome.FAILED
    assert receipt.oom_killed is True
    assert receipt.failure is SmokeFailureCode.OOM_KILLED
    assert receipt.cleanup_confirmed is True


def test_smoke_adapter_log_truncation_at_budget():
    """Stdout exceeding 64 KiB is truncated to MAX_LOG_BYTES_PER_STREAM."""
    fake_docker = FakeSmokeDocker()
    fake_docker.container_running = False
    fake_docker.stdout_bytes = b"A" * (MAX_LOG_BYTES_PER_STREAM + 5000)

    adapter = SmokeAdapter(fake_docker)
    receipt = adapter.run_smoke("smoke-v1", dry_run=False)

    assert receipt.logs_truncated is True
    assert receipt.stdout_snippet is not None
    assert len(receipt.stdout_snippet) <= MAX_LOG_BYTES_PER_STREAM


def test_smoke_adapter_cleanup_failure_blocks_admissions():
    """Remove failure causes adapter to enter UNRESOLVED and permanently block admissions."""
    fake_docker = FakeSmokeDocker()
    fake_docker.container_running = False

    def bad_remove(self, cid):
        raise RuntimeError("Failed to remove container: device or resource busy")

    fake_docker.remove_hook = bad_remove

    adapter = SmokeAdapter(fake_docker)
    receipt = adapter.run_smoke("smoke-v1", dry_run=False)

    assert receipt.cleanup_confirmed is False
    assert receipt.state is SmokeLifecycleState.UNRESOLVED
    assert receipt.cleanup_failure in (SmokeFailureCode.REMOVE_FAILED, SmokeFailureCode.CLEANUP_UNRESOLVED)
    assert adapter.admissions_blocked is True

    # Subsequent request is immediately rejected with ADMISSIONS_BLOCKED
    with pytest.raises(SmokeAdmissionError) as exc_info:
        adapter.run_smoke("smoke-v1", dry_run=True)
    assert exc_info.value.code is SmokeFailureCode.ADMISSIONS_BLOCKED


def test_smoke_adapter_receipt_security_invariants():
    """SmokeReceipt strictly preserves execution_enabled=False and SEC01-10 unverified controls."""
    fake_docker = FakeSmokeDocker()
    adapter = SmokeAdapter(fake_docker)

    receipt = adapter.run_smoke("smoke-v1", dry_run=True)
    assert receipt.execution_enabled is False
    assert receipt.production_authorized is False
    assert len(receipt.unverified_controls) == 10
    assert "SEC01" in receipt.unverified_controls
    assert "SEC10" in receipt.unverified_controls

    as_dict = receipt.to_dict()
    assert as_dict["execution_enabled"] is False
    assert as_dict["production_authorized"] is False
    assert "unverified_controls" in as_dict


def test_smoke_adapter_cli_dry_run_success(capsys):
    """CLI defaults to dry-run and prints valid JSON receipt."""
    ret = main(["--dry-run"])
    assert ret == 0
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert parsed["dry_run"] is True
    assert parsed["outcome"] == "DRY_RUN_PASSED"
    assert parsed["execution_enabled"] is False


def test_smoke_adapter_cli_rejects_native_execution_on_windows(monkeypatch, capsys):
    """Running with --execute-approved-native-smoke on Windows fails closed with explanation."""
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: None)
    monkeypatch.setattr("sys.platform", "win32")

    ret = main(["--execute-approved-native-smoke"])
    assert ret == 2
    captured = capsys.readouterr()
    assert "native Linux host" in captured.err
    assert "LSM_NOT_ADVERTISED" in captured.err

