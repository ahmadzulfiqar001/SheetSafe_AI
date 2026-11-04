"""Unit tests for the operator-only native Linux Docker smoke adapter.

Uses in-memory fake Docker transports, mocked subprocess pipes, and synthetic
clock harnesses; never contacts a real daemon, creates real containers, or opens
network sockets.
"""

from __future__ import annotations

from copy import deepcopy
import io
import json
import os
from pathlib import Path
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
    FailureCode,
    RunnerLifecycleError,
)
from runner.engine_metadata import (
    HOST_DEFAULTS,
    LOCAL_CONFIG_DIGEST,
    MASKED_PATHS,
    READONLY_PATHS,
)
from runner.policy import FixtureRequest, SandboxPolicy
from runner.preflight import ImageTagMismatch
from runner.smoke_adapter import (
    DEFAULT_WALL_DEADLINE_SECONDS,
    FIXED_SMOKE_FIXTURE_ID,
    MAX_LOG_BYTES_PER_STREAM,
    DryRunSmokeTransport,
    NativeCliSmokeTransport,
    SmokeAdapter,
    SmokeAdmissionError,
    SmokeFailureCode,
    SmokeLifecycleState,
    SmokeOutcome,
    main,
    normalize_created_inspect,
    validate_runtime_inspect,
)


@pytest.fixture(autouse=True)
def no_external_io(monkeypatch):
    attempts = []

    def forbidden(*args, **kwargs):
        attempts.append(True)
        raise AssertionError(
            "Smoke adapter test attempted external execution or networking"
        )

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    yield
    assert not attempts, (
        "External I/O was attempted, even if its exception was caught"
    )


def build_native_inspect_response(
    spec: ContainerJobSpec,
    container_id: str,
) -> dict:
    """Construct a realistic native Docker Engine 1.56 container inspect payload."""
    expected_config = spec.create_body()
    expected_host = expected_config.pop("HostConfig")
    policy = SandboxPolicy()
    return {
        "Id": container_id,
        "Created": "2026-10-22T05:00:00.000000000Z",
        "Path": policy.entrypoint[0],
        "Args": [*policy.entrypoint[1:], "smoke-v1"],
        "State": {
            "Status": "created",
            "Running": False,
            "Paused": False,
            "Restarting": False,
            "OOMKilled": False,
            "Dead": False,
            "Pid": 0,
            "ExitCode": 0,
            "Error": "",
            "StartedAt": "0001-01-01T00:00:00Z",
            "FinishedAt": "0001-01-01T00:00:00Z",
        },
        "Image": LOCAL_IMAGE_ID,
        "ResolvConfPath": "/var/lib/docker/containers/resolv.conf",
        "HostnamePath": "/var/lib/docker/containers/hostname",
        "HostsPath": "/var/lib/docker/containers/hosts",
        "LogPath": "",
        "Name": "/" + spec.name,
        "RestartCount": 0,
        "Driver": "overlay2",
        "Platform": "linux",
        "MountLabel": "",
        "ProcessLabel": "",
        "AppArmorProfile": "docker-default",
        "ExecIDs": None,
        "GraphDriver": {"Name": "overlay2", "Data": None},
        "Mounts": [],
        "Config": {
            **expected_config,
            "Hostname": container_id[:12],
            "Domainname": "",
            "AttachStdin": False,
            "AttachStdout": False,
            "AttachStderr": False,
            "OnBuild": None,
            "ArgsEscaped": True,
        },
        "HostConfig": {
            **HOST_DEFAULTS,
            **expected_host,
            "MaskedPaths": [*MASKED_PATHS, "/sys/devices/system/cpu/cpu0/thermal_throttle"],
            "ReadonlyPaths": list(READONLY_PATHS),
        },
        "NetworkSettings": {
            "Bridge": "",
            "SandboxID": "",
            "SandboxKey": "",
            "Ports": {},
            "HairpinMode": False,
            "LinkLocalIPv6Address": "",
            "LinkLocalIPv6PrefixLen": 0,
            "Networks": {
                "none": {
                    "IPAMConfig": None,
                    "Links": None,
                    "Aliases": None,
                    "NetworkID": "a" * 64,
                    "EndpointID": "",
                    "Gateway": "",
                    "IPAddress": "",
                    "IPPrefixLen": 0,
                    "IPv6Gateway": "",
                    "GlobalIPv6Address": "",
                    "GlobalIPv6PrefixLen": 0,
                    "MacAddress": "",
                    "DriverOpts": None,
                    "DNSNames": None,
                    "GwPriority": 0,
                }
            },
        },
    }


class FakeSmokeDocker:
    """Strict in-memory transport simulator for smoke execution testing."""

    def __init__(self, *, use_native_inspect_format: bool = False) -> None:
        self.records: dict[str, dict] = {}
        self.calls: list[tuple[str, str]] = []
        self.counter = 0
        self.use_native_inspect_format = use_native_inspect_format
        self.create_hook = None
        self.inspect_hook = None
        self.start_hook = None
        self.kill_hook = None
        self.logs_hook = None
        self.remove_hook = None
        self.started = False
        self.container_running = False
        self.exit_code = 0
        self.oom_killed = False
        self.cpu_usage_ns = 0
        self.stdout_bytes = (
            b'{"fixture_id":"smoke-v1","marker_created":true,'
            b'"protected_write_denied":true,"runtime_verification":"UNVERIFIED"}\n'
        )
        self.stderr_bytes = b""

    def create(self, spec: ContainerJobSpec, *, timeout: float) -> str:
        self.calls.append(("create", spec.name))
        if self.create_hook:
            return self.create_hook(self, spec)
        self.counter += 1
        cid = f"{self.counter:064x}"
        if self.use_native_inspect_format:
            self.records[cid] = build_native_inspect_response(spec, cid)
        else:
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
                },
                "Mounts": [],
                "NetworkSettings": {"Ports": {}, "Networks": {"none": {}}},
                "AppArmorProfile": "docker-default",
            }
        return cid

    def inspect(self, reference: str, *, timeout: float) -> dict:
        self.calls.append(("inspect", reference))
        if self.inspect_hook:
            res = self.inspect_hook(self, reference)
            if res is not None:
                return res
        cid = None
        if reference in self.records:
            cid = reference
        else:
            for candidate_id, metadata in self.records.items():
                if metadata["Name"] == "/" + reference:
                    cid = candidate_id
                    break
        if cid is None:
            raise ContainerNotFound(f"Container not found: {reference}")

        rec = deepcopy(self.records[cid])
        if self.started:
            rec["State"]["Running"] = self.container_running
            rec["State"]["ExitCode"] = self.exit_code
            rec["State"]["OOMKilled"] = self.oom_killed
            rec["State"]["Status"] = (
                "running" if self.container_running else "exited"
            )
            rec["CPUStats"] = {"cpu_usage": {"total_usage": self.cpu_usage_ns}}
        return rec

    def start(self, container_id: str, *, timeout: float) -> None:
        self.calls.append(("start", container_id))
        if self.start_hook:
            self.start_hook(self, container_id)
        if container_id not in self.records:
            raise ContainerNotFound(container_id)
        self.started = True
        if self.container_running:
            self.records[container_id]["State"]["Status"] = "running"
            self.records[container_id]["State"]["Running"] = True
            self.records[container_id]["State"]["Pid"] = 12345
        else:
            self.records[container_id]["State"]["Status"] = "exited"
            self.records[container_id]["State"]["Running"] = False
            self.records[container_id]["State"]["Pid"] = 0

    def kill(self, container_id: str, *, signal: str, timeout: float) -> None:
        self.calls.append(("kill", f"{container_id}:{signal}"))
        if self.kill_hook:
            self.kill_hook(self, container_id, signal)
            return
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
            return self.logs_hook(
                self, container_id, stdout=stdout, stderr=stderr
            )
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
    """Valid compliant EngineReader for preflight testing."""

    def __init__(self) -> None:
        self.security_options = [
            "name=seccomp,profile=builtin",
            "name=apparmor",
            "name=cgroupns",
        ]

    def channel(self) -> dict:
        return {"Host": "unix:///var/run/docker.sock", "SkipTLSVerify": False}

    def version(self) -> dict:
        return {
            "Client": {"ApiVersion": "1.56"},
            "Server": {
                "Version": "27.3.1",
                "ApiVersion": "1.56",
                "MinAPIVersion": "1.24",
                "Os": "linux",
                "Arch": "amd64",
            },
        }

    def info(self) -> dict:
        return {
            "OSType": "linux",
            "Architecture": "x86_64",
            "CgroupVersion": "2",
            "CgroupDriver": "systemd",
            "MemoryLimit": True,
            "SwapLimit": True,
            "CpuCfsPeriod": True,
            "CpuCfsQuota": True,
            "PidsLimit": True,
            "SecurityOptions": list(self.security_options),
            "Runtimes": {"runc": {"path": "runc"}},
            "DefaultRuntime": "runc",
            "Warnings": None,
        }

    def image(self) -> dict:
        policy = SandboxPolicy()
        return {
            "Id": LOCAL_IMAGE_ID,
            "Os": "linux",
            "Architecture": "amd64",
            "Descriptor": {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": LOCAL_IMAGE_ID,
                "annotations": {"config.digest": LOCAL_CONFIG_DIGEST},
            },
            "RepoDigests": [],
            "Config": {
                "User": "10001:10001",
                "Entrypoint": list(policy.entrypoint),
                "Cmd": ["smoke-v1"],
                "WorkingDir": "/work",
                "StopSignal": "SIGTERM",
                "Env": [
                    "LANG=C.UTF-8",
                    "HOME=/nonexistent",
                    "PATH=/usr/local/bin:/usr/bin:/bin",
                ],
                "ArgsEscaped": True,
                "Labels": {
                    "org.opencontainers.image.title": "SheetSafe fixed smoke fixture",
                    "org.opencontainers.image.version": "smoke-v1",
                    "io.sheetsafe.policy": policy.version,
                },
            },
        }


# ---------------------------------------------------------------------------
# Core Lifecycle & Admission Tests
# ---------------------------------------------------------------------------


def test_smoke_adapter_dry_run_default():
    """Dry-run mode performs admission checks with zero Docker transport calls."""
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
    assert len(fake_docker.calls) == 0


def test_smoke_adapter_dry_run_transport_blocks_non_dry_run():
    """DryRunSmokeTransport fails closed if invoked with dry_run=False."""
    adapter = SmokeAdapter(DryRunSmokeTransport())
    with pytest.raises(SmokeAdmissionError) as exc_info:
        adapter.run_smoke("smoke-v1", dry_run=False)
    assert exc_info.value.code is SmokeFailureCode.ADMISSIONS_BLOCKED


def test_smoke_adapter_rejects_unsupported_fixture():
    """Only smoke-v1 is accepted; any other input fails closed before transport."""
    fake_docker = FakeSmokeDocker()
    adapter = SmokeAdapter(fake_docker)

    for bad_input in ("malicious_arbitrary_python_fixture", "", None, 123, {"fixture_id": "smoke-v1"}):
        with pytest.raises(SmokeAdmissionError) as exc_info:
            adapter.run_smoke(bad_input)  # type: ignore[arg-type]
        assert exc_info.value.code is SmokeFailureCode.UNSUPPORTED_FIXTURE

    assert len(fake_docker.calls) == 0


def test_smoke_adapter_rejects_out_of_bounds_budgets():
    """Deadlines or CPU limits exceeding policy maximums are rejected before transport."""
    fake_docker = FakeSmokeDocker()
    adapter = SmokeAdapter(fake_docker)

    for bad_wall in (0.0, -1.0, 20.1, float("inf"), float("nan")):
        with pytest.raises(SmokeAdmissionError) as exc_info:
            adapter.run_smoke("smoke-v1", dry_run=False, wall_deadline_seconds=bad_wall)
        assert exc_info.value.code is SmokeFailureCode.POLICY_MISMATCH

    for bad_cpu in (0.0, -5.0, 10.1, float("inf")):
        with pytest.raises(SmokeAdmissionError) as exc_info:
            adapter.run_smoke("smoke-v1", dry_run=False, cpu_limit_seconds=bad_cpu)
        assert exc_info.value.code is SmokeFailureCode.POLICY_MISMATCH

    assert len(fake_docker.calls) == 0


def test_smoke_adapter_success_lifecycle():
    """Full successful execution lifecycle with verified container removal."""
    fake_docker = FakeSmokeDocker()
    fake_docker.container_running = False
    fake_docker.exit_code = 0

    adapter = SmokeAdapter(fake_docker, preflight_reader=FakeEngineReader())
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
    assert "protected_write_denied" in receipt.stdout_snippet

    op_names = [call[0] for call in fake_docker.calls]
    assert "create" in op_names
    assert "inspect" in op_names
    assert "start" in op_names
    assert "logs" in op_names
    assert "remove" in op_names


def test_smoke_adapter_native_inspect_normalization_boundary():
    """Native Docker Engine inspect JSON is validated strictly before verify_configuration."""
    # 1. Valid native Docker Engine inspect response succeeds
    fake_docker = FakeSmokeDocker(use_native_inspect_format=True)
    fake_docker.container_running = False
    fake_docker.exit_code = 0
    adapter = SmokeAdapter(fake_docker)
    receipt = adapter.run_smoke("smoke-v1", dry_run=False)
    assert receipt.outcome is SmokeOutcome.COMPLETED
    assert receipt.configuration_verified is True
    assert receipt.cleanup_confirmed is True

    # 2. Unsafe or unreviewed mutations in native inspect JSON fail closed with POLICY_MISMATCH
    spec = ContainerJobSpec.for_fixture(FixtureRequest("smoke-v1"))
    cid = "a" * 64
    base_native = build_native_inspect_response(spec, cid)
    assert normalize_created_inspect(deepcopy(base_native), spec, cid)["Id"] == cid

    unsafe_mutations = [
        lambda d: d.__setitem__("UnknownTopField", True),
        lambda d: d["HostConfig"].__setitem__("Privileged", True),
        lambda d: d["HostConfig"].__setitem__("GroupAdd", ["docker"]),
        lambda d: d["HostConfig"].__setitem__("MaskedPaths", ["/proc/kcore"]),  # Missing required masks
        lambda d: d["HostConfig"].__setitem__("ReadonlyPaths", []),  # Weakened readonly paths
        lambda d: d["HostConfig"].__setitem__("LogConfig", {"Type": "json-file", "Config": {}}),
        lambda d: d["Config"].__setitem__("User", "0:0"),
        lambda d: d["Config"].__setitem__("AttachStdin", True),
        lambda d: d["Mounts"].append({"Source": "/etc", "Destination": "/host"}),
        lambda d: d["NetworkSettings"]["Networks"]["none"].__setitem__("IPAddress", "172.17.0.2"),
        lambda d: d["State"].__setitem__("Running", True),
        lambda d: d.__setitem__("AppArmorProfile", "unconfined"),
    ]
    for mutate in unsafe_mutations:
        tampered = deepcopy(base_native)
        mutate(tampered)
        with pytest.raises(RunnerLifecycleError) as exc_info:
            normalize_created_inspect(tampered, spec, cid)
        assert exc_info.value.code is FailureCode.POLICY_MISMATCH


def test_smoke_adapter_preflight_failure_fails_closed():
    """Preflight check failure halts admission before container create with zero transport calls."""
    fake_docker = FakeSmokeDocker()
    bad_reader = FakeEngineReader()
    bad_reader.channel = lambda: {  # type: ignore[method-assign]
        "Host": "tcp://malicious:2375",
        "SkipTLSVerify": True,
    }

    adapter = SmokeAdapter(fake_docker, preflight_reader=bad_reader)

    with pytest.raises(SmokeAdmissionError) as exc_info:
        adapter.run_smoke("smoke-v1", dry_run=False)
    assert exc_info.value.code is SmokeFailureCode.PREFLIGHT_FAILED
    assert len(fake_docker.calls) == 0

    # Also test ImageTagMismatch / LSM_NOT_ADVERTISED preflight failure
    no_lsm_reader = FakeEngineReader()
    no_lsm_reader.security_options = ["name=seccomp,profile=builtin", "name=cgroupns"]
    adapter2 = SmokeAdapter(fake_docker, preflight_reader=no_lsm_reader)
    with pytest.raises(SmokeAdmissionError) as exc_info2:
        adapter2.run_smoke("smoke-v1", dry_run=True)
    assert exc_info2.value.code is SmokeFailureCode.PREFLIGHT_FAILED
    assert len(fake_docker.calls) == 0


def test_smoke_adapter_failed_create_fails_closed():
    """If create raises CreateRejected, adapter verifies absence by name and fails closed."""
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
    assert adapter.admissions_blocked is False


def test_smoke_adapter_ambiguous_create_error_marks_cleanup_unresolved_and_blocks():
    """An ambiguous create error (e.g. timeout) cannot assume cleanup success by name absence alone."""
    fake_docker = FakeSmokeDocker()

    def timeout_create(self, spec):
        raise TimeoutError("Docker create timed out; container may materialize late")

    fake_docker.create_hook = timeout_create

    adapter = SmokeAdapter(fake_docker)
    receipt = adapter.run_smoke("smoke-v1", dry_run=False)

    assert receipt.outcome is SmokeOutcome.FAILED
    assert receipt.failure is SmokeFailureCode.CREATE_FAILED
    assert receipt.cleanup_confirmed is False
    assert receipt.cleanup_failure is SmokeFailureCode.CLEANUP_UNRESOLVED
    assert receipt.state is SmokeLifecycleState.UNRESOLVED
    assert adapter.admissions_blocked is True


def test_smoke_adapter_invalid_container_id_fails_closed():
    """Invalid non-hex container ID returned by create is rejected and blocks adapter."""
    fake_docker = FakeSmokeDocker()
    fake_docker.create_hook = lambda self, spec: "invalid-id-not-64-hex"

    adapter = SmokeAdapter(fake_docker)
    receipt = adapter.run_smoke("smoke-v1", dry_run=False)

    assert receipt.outcome is SmokeOutcome.FAILED
    assert receipt.failure is SmokeFailureCode.INVALID_IDENTITY
    assert receipt.started is False
    assert receipt.cleanup_confirmed is False
    assert adapter.admissions_blocked is True


def test_smoke_adapter_duplicate_container_id_rejected():
    """Reused container ID across runs is rejected with DUPLICATE_IDENTITY."""
    fake_docker = FakeSmokeDocker()
    fake_docker.container_running = False
    adapter = SmokeAdapter(fake_docker)

    r1 = adapter.run_smoke("smoke-v1", dry_run=False)
    assert r1.outcome is SmokeOutcome.COMPLETED

    # Force counter back to 0 so the second run receives the same 64-hex container ID
    fake_docker.counter = 0
    r2 = adapter.run_smoke("smoke-v1", dry_run=False)
    assert r2.outcome is SmokeOutcome.FAILED
    assert r2.failure is SmokeFailureCode.DUPLICATE_IDENTITY
    assert r2.started is False
    assert r2.cleanup_confirmed is True


def test_smoke_adapter_policy_mismatch_aborts_and_cleans_up():
    """If inspect reveals weakened policy (e.g. Privileged=True), adapter aborts before start."""
    fake_docker = FakeSmokeDocker()

    def tamper_inspect(self, ref):
        for rec in self.records.values():
            rec["HostConfig"]["Privileged"] = True

    fake_docker.inspect_hook = tamper_inspect

    adapter = SmokeAdapter(fake_docker)
    receipt = adapter.run_smoke("smoke-v1", dry_run=False)

    assert receipt.outcome is SmokeOutcome.FAILED
    assert receipt.failure is SmokeFailureCode.POLICY_MISMATCH
    assert receipt.started is False
    assert receipt.cleanup_confirmed is True
    assert not any(call[0] == "start" for call in fake_docker.calls)


def test_smoke_adapter_malformed_inspect_data_fails_closed():
    """Malformed inspect data during pre-start, runtime, or cleanup fails closed and is never ContainerNotFound."""
    spec = ContainerJobSpec.for_fixture(FixtureRequest("smoke-v1"))
    cid = "1" * 64
    valid_rec = {
        "Id": cid,
        "Name": "/" + spec.name,
        "Image": LOCAL_IMAGE_ID,
        "Config": spec.create_body(),
        "State": {"Status": "exited", "Running": False, "ExitCode": 0, "OOMKilled": False},
    }
    valid_rec["HostConfig"] = valid_rec["Config"].pop("HostConfig")

    # 1. Runtime inspect rejects boolean ExitCode or non-dict State
    bad_exit = deepcopy(valid_rec)
    bad_exit["State"]["ExitCode"] = True  # bool is not int!
    with pytest.raises(SmokeAdmissionError) as exc_info:
        validate_runtime_inspect(bad_exit, spec, cid)
    assert exc_info.value.code is SmokeFailureCode.INSPECT_FAILED

    # 2. Runtime inspect failure kills running container and marks INSPECT_FAILED
    fake_docker = FakeSmokeDocker()
    fake_docker.container_running = True

    def corrupt_runtime_inspect(self, ref):
        if self.started and ref in self.records:
            return {
                "Id": ref,
                "Name": self.records[ref]["Name"],
                "Config": self.records[ref]["Config"],
                "State": {"Status": "running", "Running": "not-a-bool"},
            }
        return None

    fake_docker.inspect_hook = corrupt_runtime_inspect
    adapter = SmokeAdapter(fake_docker)
    receipt = adapter.run_smoke("smoke-v1", dry_run=False)
    assert receipt.outcome is SmokeOutcome.FAILED
    assert receipt.failure is SmokeFailureCode.INSPECT_FAILED
    assert any(call[0] == "kill" for call in fake_docker.calls)

    # 3. Malformed inspect error during cleanup _absent check never counts as ContainerNotFound
    fake_docker2 = FakeSmokeDocker()
    fake_docker2.container_running = False

    def fail_post_remove_inspect(self, ref):
        if any(c[0] == "remove" for c in self.calls):
            raise RuntimeError("Malformed JSON returned by docker inspect")
        return None

    fake_docker2.inspect_hook = fail_post_remove_inspect
    adapter2 = SmokeAdapter(fake_docker2)
    receipt2 = adapter2.run_smoke("smoke-v1", dry_run=False)
    assert receipt2.cleanup_confirmed is False
    assert receipt2.state is SmokeLifecycleState.UNRESOLVED
    assert receipt2.outcome is SmokeOutcome.FAILED
    assert adapter2.admissions_blocked is True


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
        simulated_time += 25.0

    adapter = SmokeAdapter(fake_docker, clock=fake_clock, sleep_fn=fake_sleep)
    receipt = adapter.run_smoke(
        "smoke-v1", dry_run=False, wall_deadline_seconds=20.0
    )

    assert receipt.outcome is SmokeOutcome.TIMED_OUT
    assert receipt.timed_out is True
    assert receipt.failure is SmokeFailureCode.TIMED_OUT
    assert receipt.cleanup_confirmed is True
    assert any(call[0] == "kill" for call in fake_docker.calls)


def test_smoke_adapter_watchdog_cancellation():
    """Setting cancel_event triggers immediate SIGKILL and CANCELLED outcome."""
    fake_docker = FakeSmokeDocker()
    fake_docker.container_running = True

    cancel_ev = Event()
    cancel_ev.set()

    adapter = SmokeAdapter(fake_docker)
    receipt = adapter.run_smoke(
        "smoke-v1", dry_run=False, cancel_event=cancel_ev
    )

    assert receipt.outcome is SmokeOutcome.CANCELLED
    assert receipt.cancelled is True
    assert receipt.failure is SmokeFailureCode.CANCELLED
    assert receipt.cleanup_confirmed is True
    assert any(call[0] == "kill" for call in fake_docker.calls)


def test_smoke_adapter_watchdog_cpu_limit_exceeded():
    """Container exceeding 10s cumulative CPU usage is killed by watchdog."""
    fake_docker = FakeSmokeDocker()
    fake_docker.container_running = True
    fake_docker.cpu_usage_ns = int(12.5 * 1e9)

    adapter = SmokeAdapter(fake_docker)
    receipt = adapter.run_smoke(
        "smoke-v1", dry_run=False, cpu_limit_seconds=10.0
    )

    assert receipt.outcome is SmokeOutcome.FAILED
    assert receipt.cpu_limit_exceeded is True
    assert receipt.failure is SmokeFailureCode.CPU_LIMIT_EXCEEDED
    assert receipt.cleanup_confirmed is True
    assert any(call[0] == "kill" for call in fake_docker.calls)


def test_smoke_adapter_watchdog_failure_when_kill_fails_or_container_survives():
    """If SIGKILL fails or container stays Running past kill grace window, watchdog records WATCHDOG_FAILED."""
    fake_docker = FakeSmokeDocker()
    fake_docker.container_running = True

    simulated_time = 50.0

    def fake_clock():
        return simulated_time

    def fake_sleep(duration):
        nonlocal simulated_time
        simulated_time += 5.0

    # Simulate a container that refuses to stop when kill() is called
    def stubborn_kill(self, cid, signal):
        raise RuntimeError("runc kill failed: container stuck")

    fake_docker.kill_hook = stubborn_kill

    adapter = SmokeAdapter(fake_docker, clock=fake_clock, sleep_fn=fake_sleep)
    receipt = adapter.run_smoke(
        "smoke-v1", dry_run=False, wall_deadline_seconds=20.0
    )

    assert receipt.outcome is SmokeOutcome.FAILED
    assert receipt.timed_out is True
    assert receipt.failure is SmokeFailureCode.WATCHDOG_FAILED


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


def test_smoke_adapter_log_failure_marks_run_failed():
    """Log retrieval failure sets LOG_RETRIEVAL_FAILED and downgrades outcome to FAILED."""
    fake_docker = FakeSmokeDocker()
    fake_docker.container_running = False
    fake_docker.exit_code = 0

    def failing_logs(self, cid, *, stdout, stderr):
        raise RuntimeError("Diagnostic stream read failed")

    fake_docker.logs_hook = failing_logs

    adapter = SmokeAdapter(fake_docker)
    receipt = adapter.run_smoke("smoke-v1", dry_run=False)

    assert receipt.outcome is SmokeOutcome.FAILED
    assert receipt.failure is SmokeFailureCode.LOG_RETRIEVAL_FAILED
    assert receipt.cleanup_confirmed is True


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
    assert receipt.outcome is SmokeOutcome.FAILED
    assert receipt.cleanup_failure in (
        SmokeFailureCode.REMOVE_FAILED,
        SmokeFailureCode.CLEANUP_UNRESOLVED,
    )
    assert adapter.admissions_blocked is True

    with pytest.raises(SmokeAdmissionError) as exc_info:
        adapter.run_smoke("smoke-v1", dry_run=True)
    assert exc_info.value.code is SmokeFailureCode.ADMISSIONS_BLOCKED


def test_smoke_adapter_uncertain_cleanup_identity_mismatch_never_removes_foreign_container():
    """If name lookup during cleanup resolves to a foreign/tampered container, remove is NOT called."""
    fake_docker = FakeSmokeDocker()
    fake_docker.container_running = False

    def swap_identity_on_cleanup(self, ref):
        # During cleanup, looking up by container name returns a different ownership nonce
        if ref.startswith("sheetsafe-smoke-"):
            for rec in self.records.values():
                tampered = deepcopy(rec)
                tampered["Config"]["Labels"]["io.sheetsafe.owner"] = "f" * 32
                return tampered
        return None

    fake_docker.inspect_hook = swap_identity_on_cleanup

    adapter = SmokeAdapter(fake_docker)
    receipt = adapter.run_smoke("smoke-v1", dry_run=False)

    assert receipt.cleanup_confirmed is False
    assert receipt.cleanup_failure is SmokeFailureCode.INVALID_IDENTITY
    assert receipt.state is SmokeLifecycleState.UNRESOLVED
    assert adapter.admissions_blocked is True
    assert not any(call[0] == "remove" for call in fake_docker.calls)


def test_smoke_adapter_process_restart_persists_blocked_state_and_in_flight_crash(
    tmp_path: Path,
):
    """Durable state file preserves admissions_blocked and seen IDs across process restarts."""
    state_file = tmp_path / "smoke_state.json"

    # 1. Clean run persists seen_container_ids and IDLE status across restart
    docker1 = FakeSmokeDocker()
    docker1.container_running = False
    adapter1 = SmokeAdapter(docker1, state_path=state_file)
    r1 = adapter1.run_smoke("smoke-v1", dry_run=False)
    assert r1.outcome is SmokeOutcome.COMPLETED
    assert adapter1.admissions_blocked is False

    # Restarted adapter rejects duplicate container ID from prior process
    docker2 = FakeSmokeDocker()
    docker2.container_running = False
    docker2.counter = 0  # Reuses 000...001 from adapter1
    adapter2 = SmokeAdapter(docker2, state_path=state_file)
    assert adapter2.admissions_blocked is False
    r2 = adapter2.run_smoke("smoke-v1", dry_run=False)
    assert r2.outcome is SmokeOutcome.FAILED
    assert r2.failure is SmokeFailureCode.DUPLICATE_IDENTITY
    assert r2.cleanup_confirmed is True

    # 2. Failed cleanup in adapter2 permanently blocks adapter3 after process restart
    docker2.remove_hook = lambda self, cid: (_ for _ in ()).throw(
        RuntimeError("daemon lost during rm")
    )
    r3 = adapter2.run_smoke("smoke-v1", dry_run=False)
    assert r3.cleanup_confirmed is False
    assert adapter2.admissions_blocked is True

    docker3 = FakeSmokeDocker()
    adapter3 = SmokeAdapter(docker3, state_path=state_file)
    assert adapter3.admissions_blocked is True
    with pytest.raises(SmokeAdmissionError) as exc_info:
        adapter3.run_smoke("smoke-v1", dry_run=True)
    assert exc_info.value.code is SmokeFailureCode.ADMISSIONS_BLOCKED
    assert len(docker3.calls) == 0

    # 3. Simulated mid-run process crash (IN_FLIGHT left on disk) blocks next restart
    crash_state_file = tmp_path / "crash_state.json"
    crash_state_file.write_text(
        json.dumps(
            {
                "version": 1,
                "status": "IN_FLIGHT",
                "blocked": True,
                "active_job_id": "a" * 32,
                "active_container_name": "sheetsafe-smoke-" + ("a" * 32),
                "active_container_id": None,
                "failure_reason": None,
                "seen_container_ids": [],
            }
        ),
        encoding="utf-8",
    )
    adapter_after_crash = SmokeAdapter(docker3, state_path=crash_state_file)
    assert adapter_after_crash.admissions_blocked is True
    with pytest.raises(SmokeAdmissionError) as exc_info2:
        adapter_after_crash.run_smoke("smoke-v1", dry_run=False)
    assert exc_info2.value.code is SmokeFailureCode.ADMISSIONS_BLOCKED

    # 4. Corrupt state file on disk fails closed
    corrupt_state_file = tmp_path / "corrupt_state.json"
    corrupt_state_file.write_text("{corrupt-json", encoding="utf-8")
    adapter_corrupt = SmokeAdapter(docker3, state_path=corrupt_state_file)
    assert adapter_corrupt.admissions_blocked is True


def test_native_cli_smoke_transport_mappings_and_error_handling(monkeypatch):
    """NativeCliSmokeTransport maps CLI flags accurately, streams attached start output, and never masks errors."""
    monkeypatch.setattr("sys.platform", "linux")
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/docker")

    spec = ContainerJobSpec.for_fixture(FixtureRequest("smoke-v1"))
    create_args = NativeCliSmokeTransport.build_create_args(spec)

    # Verify exact security flags and absence of broken entrypoint override
    assert create_args[:4] == ["create", "--name", spec.name, "--platform"]
    assert "linux/amd64" in create_args
    assert "--entrypoint" not in create_args
    assert "--user" in create_args and "10001:10001" in create_args
    assert "--network" in create_args and "none" in create_args
    assert "--read-only" in create_args
    assert "--cap-drop" in create_args and "ALL" in create_args
    assert "--security-opt" in create_args and "no-new-privileges=true" in create_args
    assert "--cpu-period" in create_args and "100000" in create_args
    assert "--cpu-quota" in create_args and "100000" in create_args
    assert "--memory" in create_args and f"{1024**3}b" in create_args
    assert "--memory-swap" in create_args and f"{1024**3}b" in create_args
    assert "--pids-limit" in create_args and "32" in create_args
    assert "--log-driver" in create_args and "none" in create_args
    assert "--no-healthcheck" in create_args
    assert "--stop-signal" in create_args and "SIGTERM" in create_args
    assert any(
        arg.startswith("/work:rw,nodev,nosuid,noexec,size=") for arg in create_args
    )
    assert any(
        arg.startswith("/tmp:rw,nodev,nosuid,noexec,size=") for arg in create_args
    )
    assert create_args[-2:] == [LOCAL_IMAGE_ID, "smoke-v1"]

    # Fake Popen for testing NativeCliSmokeTransport without external processes
    cid = "b" * 64
    popen_calls: list[list[str]] = []
    next_response: list[tuple[int, bytes, bytes]] = []

    class FakePopen:
        def __init__(self, cmd, **kwargs):
            popen_calls.append(list(cmd))
            rc, out, err = next_response.pop(0)
            self.returncode = rc
            self.stdout = io.BytesIO(out)
            self.stderr = io.BytesIO(err)

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            self.returncode = -9

    monkeypatch.setattr(subprocess, "Popen", FakePopen)
    transport = NativeCliSmokeTransport(context="default")

    # 1. create returns validated 64-hex container ID
    next_response.append((0, (cid + "\n").encode("ascii"), b""))
    assert transport.create(spec, timeout=1.0) == cid
    assert popen_calls[-1][:4] == ["/usr/bin/docker", "--context", "default", "create"]

    # 2. inspect parses valid JSON array and raises RuntimeError (NOT ContainerNotFound) on malformed JSON
    native_meta = build_native_inspect_response(spec, cid)
    next_response.append((0, json.dumps([native_meta]).encode("utf-8"), b""))
    inspected = transport.inspect(cid, timeout=1.0)
    assert inspected["Id"] == cid

    for bad_payload in (b"{not-json", b"[]", b"[123]", b"[{}, {}]"):
        next_response.append((0, bad_payload, b""))
        with pytest.raises(RuntimeError):
            transport.inspect(cid, timeout=1.0)

    # Explicit "No such container" raises ContainerNotFound
    next_response.append(
        (1, b"", b"Error: No such container: " + cid.encode("ascii"))
    )
    with pytest.raises(ContainerNotFound):
        transport.inspect(cid, timeout=1.0)

    # 3. start uses `docker start --attach` and streams stdout/stderr to logs()
    expected_out = b'{"fixture_id":"smoke-v1","marker_created":true}\n'
    expected_err = b""
    next_response.append((0, expected_out, expected_err))
    transport.start(cid, timeout=1.0)
    assert popen_calls[-1] == [
        "/usr/bin/docker",
        "--context",
        "default",
        "start",
        "--attach",
        cid,
    ]
    assert (
        transport.logs(
            cid, stdout=True, stderr=False, max_bytes=65536, timeout=1.0
        )
        == expected_out
    )
    assert (
        transport.logs(
            cid, stdout=False, stderr=True, max_bytes=65536, timeout=1.0
        )
        == expected_err
    )

    # 4. Calling logs() for an unknown container raises RuntimeError (never returns b"")
    with pytest.raises(RuntimeError):
        transport.logs(
            "c" * 64, stdout=True, stderr=False, max_bytes=65536, timeout=1.0
        )

    # 5. remove cleans up session and invokes `docker rm -f`
    next_response.append((0, (cid + "\n").encode("ascii"), b""))
    transport.remove(cid, force=True, timeout=1.0)
    assert popen_calls[-1] == [
        "/usr/bin/docker",
        "--context",
        "default",
        "rm",
        "-f",
        cid,
    ]


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


def test_smoke_adapter_cli_dry_run_success(capsys, tmp_path: Path):
    """CLI defaults to dry-run and prints valid JSON receipt."""
    state_file = tmp_path / "cli_state.json"
    ret = main(["--dry-run", "--state-file", str(state_file)])
    assert ret == 0
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert parsed["dry_run"] is True
    assert parsed["outcome"] == "DRY_RUN_PASSED"
    assert parsed["execution_enabled"] is False
    assert not state_file.exists()


def test_smoke_adapter_cli_rejects_native_execution_on_windows(
    monkeypatch, capsys
):
    """Running with --execute-approved-native-smoke on Windows fails closed with explanation."""
    monkeypatch.setattr("sys.platform", "win32")

    ret = main(["--execute-approved-native-smoke"])
    assert ret == 2
    captured = capsys.readouterr()
    assert "native Linux host" in captured.err
    assert "LSM_NOT_ADVERTISED" in captured.err
