"""Unit tests for the operator-only native Linux Docker smoke adapter.

Uses in-memory fake Docker transports, mocked subprocess pipes, and synthetic
clock harnesses; never contacts a real daemon, creates real containers, or opens
network sockets.
"""

from __future__ import annotations

from collections.abc import Callable
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
    ALL_SERVICE_ACCOUNTS,
    CONTAINER_GUEST_GID,
    CONTAINER_GUEST_UID,
    DEFAULT_LOCK_FILE_NAME,
    DEFAULT_STATE_FILE_PATH,
    DEFAULT_WALL_DEADLINE_SECONDS,
    FIXED_SMOKE_FIXTURE_ID,
    FORBIDDEN_SERVICE_ACCOUNTS,
    MAX_LOG_BYTES_PER_STREAM,
    OPERATOR_SERVICE_ACCOUNT,
    PROTECTED_STATE_DIR,
    DryRunSmokeTransport,
    LocalOperatorEnvironmentReader,
    NativeCliSmokeTransport,
    PolicyMismatchError,
    SmokeAdapter,
    SmokeAdmissionError,
    SmokeFailureCode,
    SmokeLifecycleState,
    SmokeOutcome,
    StatFacts,
    _DurableSmokeLedger,
    main,
    normalize_created_inspect,
    validate_runtime_inspect,
    verify_operator_identity,
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


@pytest.fixture
def tmp_path(tmp_path: Path, monkeypatch) -> Path:
    """Ensure pytest temp directory hierarchy has strict 0o700 permissions for ledger tests."""
    if os.name != "nt":
        euid = os.geteuid()
        for candidate in (tmp_path.parent.parent, tmp_path.parent, tmp_path):
            try:
                if (
                    candidate.exists()
                    and not candidate.is_symlink()
                    and candidate.stat().st_uid == euid
                ):
                    candidate.chmod(0o700)
            except OSError:
                pass
        # If pytest was invoked with --basetemp inside the git repo, scope default
        # trusted_ancestor_root to tmp_path unless explicitly overridden by the test.
        if any((p / ".git").exists() for p in tmp_path.parents):
            orig_init = _DurableSmokeLedger.__init__

            def _patched_init(self, path, **kwargs):
                if (
                    kwargs.get("trusted_ancestor_root") is None
                    and path is not None
                    and tmp_path in Path(os.path.abspath(path)).parents
                ):
                    kwargs["trusted_ancestor_root"] = tmp_path
                orig_init(self, path, **kwargs)

            monkeypatch.setattr(_DurableSmokeLedger, "__init__", _patched_init)
    else:
        import stat as stat_mod

        recorded_modes: dict[Path, int] = {}
        recorded_symlinks: set[Path] = set()
        recorded_hardlinks: set[Path] = set()
        orig_os_chmod = os.chmod
        orig_path_chmod = Path.chmod

        def _win_os_chmod(p, mode, *args, **kwargs):
            if not isinstance(p, int):
                recorded_modes[Path(os.path.abspath(p))] = mode & 0o7777
            return orig_os_chmod(p, mode, *args, **kwargs)

        def _win_path_chmod(self_path: Path, mode: int, **kwargs):
            recorded_modes[Path(os.path.abspath(self_path))] = mode & 0o7777
            return orig_path_chmod(self_path, mode, **kwargs)

        monkeypatch.setattr(os, "chmod", _win_os_chmod)
        monkeypatch.setattr(Path, "chmod", _win_path_chmod)

        orig_path_unlink = Path.unlink

        def _win_path_unlink(self_path: Path, *args, **kwargs):
            abs_p = Path(os.path.abspath(self_path))
            recorded_symlinks.discard(abs_p)
            recorded_hardlinks.discard(abs_p)
            return orig_path_unlink(self_path, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", _win_path_unlink)

        abs_tmp = Path(os.path.abspath(tmp_path))

        def _win_transform_stat(
            self_reader, path: Path, raw: StatFacts
        ) -> StatFacts:
            abs_p = Path(os.path.abspath(path))
            nlink = 2 if abs_p in recorded_hardlinks else raw.st_nlink
            if abs_p in recorded_symlinks or stat_mod.S_ISLNK(raw.st_mode):
                return StatFacts(
                    st_mode=stat_mod.S_IFLNK | 0o777,
                    st_uid=1000,
                    st_gid=1000,
                    st_nlink=nlink,
                    st_dev=raw.st_dev,
                    st_ino=raw.st_ino,
                    st_file_attributes=raw.st_file_attributes | 0x400,
                )
            if abs_p in recorded_modes:
                fmt = stat_mod.S_IFMT(raw.st_mode)
                return StatFacts(
                    st_mode=fmt | recorded_modes[abs_p],
                    st_uid=1000,
                    st_gid=1000,
                    st_nlink=nlink,
                    st_dev=raw.st_dev,
                    st_ino=raw.st_ino,
                    st_file_attributes=raw.st_file_attributes,
                )
            fmt = stat_mod.S_IFMT(raw.st_mode)
            if stat_mod.S_ISDIR(raw.st_mode):
                default_mode = (
                    0o755 if abs_p in abs_tmp.parents else 0o700
                )
                return StatFacts(
                    st_mode=fmt | default_mode,
                    st_uid=1000,
                    st_gid=1000,
                    st_nlink=nlink,
                    st_dev=raw.st_dev,
                    st_ino=raw.st_ino,
                    st_file_attributes=raw.st_file_attributes,
                )
            return StatFacts(
                st_mode=fmt | 0o600,
                st_uid=1000,
                st_gid=1000,
                st_nlink=nlink,
                st_dev=raw.st_dev,
                st_ino=raw.st_ino,
                st_file_attributes=raw.st_file_attributes,
            )

        monkeypatch.setattr(
            LocalOperatorEnvironmentReader,
            "transform_stat",
            _win_transform_stat,
        )
        monkeypatch.setattr(
            LocalOperatorEnvironmentReader,
            "_win_recorded_symlinks",
            recorded_symlinks,
            raising=False,
        )
        monkeypatch.setattr(
            LocalOperatorEnvironmentReader,
            "_win_recorded_hardlinks",
            recorded_hardlinks,
            raising=False,
        )

        orig_init = _DurableSmokeLedger.__init__

        def _patched_win_init(self, path, **kwargs):
            if (
                kwargs.get("trusted_ancestor_root") is None
                and path is not None
                and abs_tmp in Path(os.path.abspath(path)).parents
            ):
                kwargs["trusted_ancestor_root"] = abs_tmp
            orig_init(self, path, **kwargs)

        monkeypatch.setattr(_DurableSmokeLedger, "__init__", _patched_win_init)

    return tmp_path


def _create_symlink_for_test(
    target: Path, link_path: Path, *, target_is_directory: bool = False
) -> None:
    """Create a real OS symlink on Linux (and Windows when permitted), or record symlink on Windows."""
    if os.name != "nt":
        os.symlink(target, link_path, target_is_directory=target_is_directory)
        return
    try:
        os.symlink(target, link_path, target_is_directory=target_is_directory)
    except OSError:
        if target_is_directory:
            link_path.mkdir(exist_ok=True)
        else:
            link_path.write_bytes(b"symlink-placeholder")
        symlinks = getattr(
            LocalOperatorEnvironmentReader, "_win_recorded_symlinks", None
        )
        if symlinks is not None:
            symlinks.add(Path(os.path.abspath(link_path)))


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
        assert isinstance(exc_info.value, PolicyMismatchError)
        assert exc_info.value.detail


def build_docker29_cli_created_inspect_response(
    spec: ContainerJobSpec,
    container_id: str,
) -> dict:
    """Construct a realistic Docker 29.9.3 (Ubuntu 24.04, cgroups v2) pre-start `docker inspect` payload.

    Reflects actual differences produced by `docker create` CLI + `docker inspect` before `docker start`:
    - Empty pre-start networking file paths (`ResolvConfPath: ""`, `HostnamePath: ""`, `HostsPath: ""`)
    - Top-level `ImageManifestDescriptor` (containerd image store), `SizeRw: None`, `SizeRootFs: None`
    - `GraphDriver` with populated `Data` layer directory map (`LowerDir`, `MergedDir`, `UpperDir`, `WorkDir`)
    - `Config` with `AttachStdout: True`, `AttachStderr: True`, omitted `ExposedPorts` and `Volumes` (`omitempty`),
      omitted `NetworkDisabled` (since `--network none` sets `HostConfig.NetworkMode="none"`), `StopTimeout: None`
    - `HostConfig` with `IOMaximumIOps: 0`, `IOMaximumBandwidth: 0`, `OomKillDisable: None` (cgroups v2 default),
      `DnsOptions: []`, `DnsSearch: []`, omitted `Mounts` and `Sysctls` (`omitempty`),
      `SecurityOpt: ["no-new-privileges:true"]`, and core Moby `MaskedPaths`
    - `State` with `Health: None`
    - `NetworkSettings` with `SecondaryIPAddresses: None`, `SecondaryIPv6Addresses: None`, empty legacy
      `DefaultNetworkSettings` fields, and `Networks.none.IPAMOperational: False`
    """
    raw = build_native_inspect_response(spec, container_id)
    # 1. Top-level Docker 29 pre-start fields
    raw["ResolvConfPath"] = ""
    raw["HostnamePath"] = ""
    raw["HostsPath"] = ""
    raw["SizeRw"] = None
    raw["SizeRootFs"] = None
    raw["ImageManifestDescriptor"] = {
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": LOCAL_IMAGE_ID,
        "size": 1842,
        "annotations": {"config.digest": LOCAL_CONFIG_DIGEST},
        "platform": {"architecture": "amd64", "os": "linux"},
    }
    # 2. GraphDriver and Docker 29 containerd Storage metadata
    raw["GraphDriver"] = {
        "Name": "overlay2",
        "Data": {
            "LowerDir": "/var/lib/docker/overlay2/layer1/diff:/var/lib/docker/overlay2/layer0/diff",
            "MergedDir": "/var/lib/docker/overlay2/layer1/merged",
            "UpperDir": "/var/lib/docker/overlay2/layer1/diff",
            "WorkDir": "/var/lib/docker/overlay2/layer1/work",
        },
    }
    raw["Storage"] = {"RootFS": {"Snapshot": {"Name": "overlayfs"}}}
    # 3. Config fields from `docker create` CLI
    raw["Config"]["AttachStdout"] = True
    raw["Config"]["AttachStderr"] = True
    raw["Config"].pop("ExposedPorts", None)
    raw["Config"].pop("Volumes", None)
    raw["Config"].pop("NetworkDisabled", None)
    raw["Config"]["StopTimeout"] = None
    raw["Config"]["Shell"] = None
    # 4. HostConfig fields from Docker 29 on Ubuntu 24.04 (cgroups v2)
    raw["HostConfig"]["IOMaximumIOps"] = 0
    raw["HostConfig"]["IOMaximumBandwidth"] = 0
    raw["HostConfig"]["OomKillDisable"] = None
    raw["HostConfig"]["DnsOptions"] = []
    raw["HostConfig"]["DnsSearch"] = []
    raw["HostConfig"].pop("Mounts", None)
    raw["HostConfig"].pop("Sysctls", None)
    raw["HostConfig"]["SecurityOpt"] = ["no-new-privileges:true"]
    raw["HostConfig"]["MaskedPaths"] = [
        "/proc/asound",
        "/proc/acpi",
        "/proc/kcore",
        "/proc/keys",
        "/proc/latency_stats",
        "/proc/timer_list",
        "/proc/timer_stats",
        "/proc/sched_debug",
        "/proc/scsi",
        "/sys/firmware",
    ]
    # 5. State with Health: None
    raw["State"]["Health"] = None
    # 6. NetworkSettings with SecondaryIPAddresses, SecondaryIPv6Addresses, legacy empty fields, and IPAMOperational
    raw["NetworkSettings"]["SecondaryIPAddresses"] = None
    raw["NetworkSettings"]["SecondaryIPv6Addresses"] = None
    raw["NetworkSettings"]["EndpointID"] = ""
    raw["NetworkSettings"]["Gateway"] = ""
    raw["NetworkSettings"]["GlobalIPv6Address"] = ""
    raw["NetworkSettings"]["GlobalIPv6PrefixLen"] = 0
    raw["NetworkSettings"]["IPAddress"] = ""
    raw["NetworkSettings"]["IPPrefixLen"] = 0
    raw["NetworkSettings"]["IPv6Gateway"] = ""
    raw["NetworkSettings"]["MacAddress"] = ""
    raw["NetworkSettings"]["Networks"]["none"]["IPAMOperational"] = False
    return raw


def test_smoke_adapter_docker29_cli_created_inspect_compatibility_and_diagnostics():
    """Docker 29.9.3 native `docker create` + `docker inspect` output passes verification and reports bounded field diagnostics on mismatch."""
    spec = ContainerJobSpec.for_fixture(FixtureRequest("smoke-v1"))
    cid = "d" * 64
    docker29_payload = build_docker29_cli_created_inspect_response(spec, cid)

    # 1. Realistic Docker 29.9.3 pre-start inspect payload normalizes cleanly and passes verify_configuration
    projection = normalize_created_inspect(
        deepcopy(docker29_payload), spec, cid
    )
    assert projection["Id"] == cid
    assert projection["Config"]["User"] == "10001:10001"
    assert projection["HostConfig"]["NetworkMode"] == "none"
    assert projection["HostConfig"]["ReadonlyRootfs"] is True
    assert projection["HostConfig"]["OomKillDisable"] is False

    # Also verify containerd snapshotter variants and documented null/omitted Storage forms
    for valid_storage in (
        {"RootFS": {"Snapshot": {"Name": "overlayfs"}}},
        {"RootFS": {"Snapshot": {"Name": "overlay2"}}},
        {"RootFS": {"Snapshot": {"Name": None}}},
        {"RootFS": {"Snapshot": {}}},
        {"RootFS": {"Snapshot": None}},
        {"RootFS": {}},
        {"RootFS": None},
        {},
        None,
    ):
        storage_variant = deepcopy(docker29_payload)
        storage_variant["Driver"] = "overlayfs"
        storage_variant["GraphDriver"] = None
        storage_variant["Storage"] = valid_storage
        assert (
            normalize_created_inspect(storage_variant, spec, cid)["Id"] == cid
        )

    # 2. Full SmokeAdapter lifecycle with Docker 29.9.3 pre-start inspect payload succeeds
    fake_docker = FakeSmokeDocker(use_native_inspect_format=True)
    fake_docker.container_running = False
    fake_docker.exit_code = 0
    created_specs: dict[str, ContainerJobSpec] = {}
    orig_create = fake_docker.create

    def create_with_d29(job_spec: ContainerJobSpec, *, timeout: float) -> str:
        created_cid = orig_create(job_spec, timeout=timeout)
        created_specs[created_cid] = job_spec
        fake_docker.records[created_cid] = (
            build_docker29_cli_created_inspect_response(job_spec, created_cid)
        )
        return created_cid

    fake_docker.create = create_with_d29  # type: ignore[method-assign]
    adapter = SmokeAdapter(fake_docker, preflight_reader=FakeEngineReader())
    receipt = adapter.run_smoke("smoke-v1", dry_run=False)
    assert receipt.outcome is SmokeOutcome.COMPLETED
    assert receipt.configuration_verified is True
    assert receipt.started is True
    assert receipt.cleanup_confirmed is True
    assert receipt.failure is None
    assert receipt.failure_detail is None
    assert receipt.to_dict()["failure_detail"] is None

    # 3. Field-level mismatch diagnostics identify the exact section.field without leaking sensitive values
    diagnostic_cases: list[tuple[Callable[[dict], None], str]] = [
        (
            lambda d: d.__setitem__("UnexpectedTopKey", "secret_val"),
            "TopLevel.UnexpectedTopKey:unexpected_field",
        ),
        (
            lambda d: d.__setitem__("AppArmorProfile", "unconfined"),
            "TopLevel.AppArmorProfile:value_mismatch",
        ),
        (
            lambda d: d["GraphDriver"].__setitem__("Name", "vfs"),
            "GraphDriver:value_mismatch",
        ),
        (
            lambda d: d.__setitem__("Storage", "not-a-dict"),
            "TopLevel.Storage:invalid_type",
        ),
        (
            lambda d: d["Storage"].__setitem__("ExtraStorageField", True),
            "TopLevel.Storage.ExtraStorageField:unexpected_field",
        ),
        (
            lambda d: d["Storage"]["RootFS"].__setitem__("ExtraRootField", True),
            "TopLevel.Storage.RootFS.ExtraRootField:unexpected_field",
        ),
        (
            lambda d: d["Storage"]["RootFS"]["Snapshot"].__setitem__(
                "ExtraSnapField", "/host/path"
            ),
            "TopLevel.Storage.RootFS.Snapshot.ExtraSnapField:unexpected_field",
        ),
        (
            lambda d: d["Storage"]["RootFS"]["Snapshot"].__setitem__(
                "Name", "vfs"
            ),
            "TopLevel.Storage.RootFS.Snapshot.Name:value_mismatch",
        ),
        (
            lambda d: d["Storage"]["RootFS"]["Snapshot"].__setitem__(
                "Name", ""
            ),
            "TopLevel.Storage.RootFS.Snapshot.Name:value_mismatch",
        ),
        (
            lambda d: d["Config"].__setitem__("User", "0:0"),
            "Config.User:value_mismatch",
        ),
        (
            lambda d: d["Config"].__setitem__("AttachStdin", True),
            "Config.AttachStdin:value_mismatch",
        ),
        (
            lambda d: d["Config"].__setitem__(
                "Env", ["SECRET_API_KEY=super_secret_token_99999"]
            ),
            "Config.Env:value_mismatch",
        ),
        (
            lambda d: d["HostConfig"].__setitem__("Privileged", True),
            "HostConfig.Privileged:value_mismatch",
        ),
        (
            lambda d: d["HostConfig"].__setitem__("OomKillDisable", True),
            "HostConfig.OomKillDisable:value_mismatch",
        ),
        (
            lambda d: d["HostConfig"].__setitem__("GroupAdd", ["docker"]),
            "HostConfig.GroupAdd:value_mismatch",
        ),
        (
            lambda d: d["HostConfig"].__setitem__(
                "Binds", ["/var/run/docker.sock:/var/run/docker.sock"]
            ),
            "HostConfig.Binds:value_mismatch",
        ),
        (
            lambda d: d["State"].__setitem__("Running", True),
            "State.Running:value_mismatch",
        ),
        (
            lambda d: d["NetworkSettings"]["Networks"]["none"].__setitem__(
                "IPAddress", "10.0.0.5"
            ),
            "NetworkSettings.Networks.none.IPAddress:value_mismatch",
        ),
        (
            lambda d: d["Mounts"].append({"Source": "/etc/shadow"}),
            "Mounts:value_mismatch",
        ),
    ]
    for mutate_fn, expected_detail in diagnostic_cases:
        bad = deepcopy(docker29_payload)
        mutate_fn(bad)
        with pytest.raises(PolicyMismatchError) as exc_info:
            normalize_created_inspect(bad, spec, cid)
        assert exc_info.value.code is FailureCode.POLICY_MISMATCH
        assert exc_info.value.detail == expected_detail
        assert "super_secret_token_99999" not in str(exc_info.value)
        assert "/etc/shadow" not in str(exc_info.value)

    # 4. SmokeReceipt surfaces bounded `failure_detail` on POLICY_MISMATCH and still cleans up container
    tampered_docker = FakeSmokeDocker()
    tampered_docker.inspect_hook = lambda self, ref: (
        self.records[ref]["HostConfig"].__setitem__("Privileged", True)
        if not self.started and ref in self.records
        else None
    )
    tampered_adapter = SmokeAdapter(tampered_docker)
    mismatch_receipt = tampered_adapter.run_smoke("smoke-v1", dry_run=False)
    assert mismatch_receipt.outcome is SmokeOutcome.FAILED
    assert mismatch_receipt.failure is SmokeFailureCode.POLICY_MISMATCH
    assert (
        mismatch_receipt.failure_detail
        == "HostConfig.Privileged:value_mismatch"
    )
    assert (
        mismatch_receipt.to_dict()["failure_detail"]
        == "HostConfig.Privileged:value_mismatch"
    )
    assert mismatch_receipt.started is False
    assert mismatch_receipt.cleanup_confirmed is True


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
    crash_state_file.chmod(0o600)
    adapter_after_crash = SmokeAdapter(docker3, state_path=crash_state_file)
    assert adapter_after_crash.admissions_blocked is True
    with pytest.raises(SmokeAdmissionError) as exc_info2:
        adapter_after_crash.run_smoke("smoke-v1", dry_run=False)
    assert exc_info2.value.code is SmokeFailureCode.ADMISSIONS_BLOCKED

    # 4. Corrupt state file on disk fails closed
    corrupt_state_file = tmp_path / "corrupt_state.json"
    corrupt_state_file.write_text("{corrupt-json", encoding="utf-8")
    corrupt_state_file.chmod(0o600)
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


# ---------------------------------------------------------------------------
# Operator-Deployment Security Boundary Tests (Identity, Protected Ledger,
# Permissions, Symlinks/Hardlinks, Process Locking, Atomic Writes & Recovery)
# ---------------------------------------------------------------------------


class FakeOperatorEnvReader:
    """Configurable environment and filesystem metadata reader for operator deployment tests."""

    def __init__(self) -> None:
        self._uid = 993
        self._euid = 993
        self._gid = 993
        self._egid = 993
        self._supp_gids = {993, 998}  # 998 = docker
        self.passwd_lines = [
            "root:x:0:0:root:/root:/bin/bash",
            "sheetsafe-api:x:991:991:SheetSafe API:/nonexistent:/usr/sbin/nologin",
            "sheetsafe-ui:x:992:992:SheetSafe UI:/nonexistent:/usr/sbin/nologin",
            "sheetsafe-runner:x:993:993:SheetSafe Runner:/nonexistent:/usr/sbin/nologin",
            "sheetsafe-validator:x:994:994:SheetSafe Validator:/nonexistent:/usr/sbin/nologin",
        ]
        self.group_lines = [
            "root:x:0:",
            "sudo:x:27:linuxuser",
            "wheel:x:28:",
            "docker:x:998:sheetsafe-runner",
            "sheetsafe-api:x:991:",
            "sheetsafe-ui:x:992:",
            "sheetsafe-runner:x:993:",
            "sheetsafe-validator:x:994:",
        ]
        # S_IFSOCK (0o140000) | 0o660 owned by root:docker (0:998)
        self.socket_facts = StatFacts(
            st_mode=0o140660,
            st_uid=0,
            st_gid=998,
            st_nlink=1,
            st_dev=1,
            st_ino=100,
        )
        self.path_overrides: dict[Path, Callable[[StatFacts], StatFacts]] = {}

    def uid(self) -> int:
        return self._uid

    def euid(self) -> int:
        return self._euid

    def gid(self) -> int:
        return self._gid

    def egid(self) -> int:
        return self._egid

    def supplementary_gids(self) -> set[int]:
        return set(self._supp_gids)

    def passwd_text(self) -> str:
        return "\n".join(self.passwd_lines) + "\n"

    def group_text(self) -> str:
        return "\n".join(self.group_lines) + "\n"

    def socket_stat(self) -> StatFacts:
        return self.socket_facts

    def transform_stat(self, path: Path, raw: StatFacts) -> StatFacts:
        base_reader = LocalOperatorEnvironmentReader()
        transformed = base_reader.transform_stat(path, raw)
        abs_p = Path(os.path.abspath(path))
        if abs_p in self.path_overrides:
            return self.path_overrides[abs_p](transformed)
        return transformed


def test_operator_identity_verification_and_service_isolation():
    """Dedicated operator identity (`sheetsafe-runner`) and Docker socket DAC are strictly enforced."""
    # 1. Valid dedicated operator setup succeeds
    env = FakeOperatorEnvReader()
    verify_operator_identity(env)

    # 2. Rejects running as root (UID 0 or GID 0 or supplementary GID 0)
    root_env = deepcopy(env)
    root_env._uid = root_env._euid = 0
    with pytest.raises(SmokeAdmissionError) as exc_info:
        verify_operator_identity(root_env)
    assert exc_info.value.code is SmokeFailureCode.OPERATOR_IDENTITY_INVALID

    # 3. Rejects running as container guest identity (10001:10001)
    guest_env = deepcopy(env)
    guest_env._uid = guest_env._euid = CONTAINER_GUEST_UID
    with pytest.raises(SmokeAdmissionError) as exc_info:
        verify_operator_identity(guest_env)
    assert exc_info.value.code is SmokeFailureCode.OPERATOR_IDENTITY_INVALID

    # 4. Rejects real vs effective UID/GID mismatch
    setuid_env = deepcopy(env)
    setuid_env._uid = 1000
    with pytest.raises(SmokeAdmissionError) as exc_info:
        verify_operator_identity(setuid_env)
    assert exc_info.value.code is SmokeFailureCode.OPERATOR_IDENTITY_INVALID

    # 5. Rejects missing dedicated service accounts (e.g. validator missing)
    missing_acct_env = deepcopy(env)
    missing_acct_env.passwd_lines = [
        line
        for line in env.passwd_lines
        if not line.startswith("sheetsafe-validator:")
    ]
    with pytest.raises(SmokeAdmissionError) as exc_info:
        verify_operator_identity(missing_acct_env)
    assert exc_info.value.code is SmokeFailureCode.OPERATOR_IDENTITY_INVALID

    # 6. Rejects colliding UIDs among the 4 services or any service using UID 10001
    colliding_env = deepcopy(env)
    colliding_env.passwd_lines[1] = (
        "sheetsafe-api:x:993:991:SheetSafe API:/nonexistent:/usr/sbin/nologin"
    )
    with pytest.raises(SmokeAdmissionError) as exc_info:
        verify_operator_identity(colliding_env)
    assert exc_info.value.code is SmokeFailureCode.OPERATOR_IDENTITY_INVALID

    # 7. Rejects running as sheetsafe-api / sheetsafe-ui / sheetsafe-validator instead of sheetsafe-runner
    api_env = deepcopy(env)
    api_env._uid = api_env._euid = 991
    api_env._gid = api_env._egid = 991
    with pytest.raises(SmokeAdmissionError) as exc_info:
        verify_operator_identity(api_env)
    assert exc_info.value.code is SmokeFailureCode.OPERATOR_IDENTITY_INVALID

    # 8. Rejects sheetsafe-api / sheetsafe-ui / sheetsafe-validator in docker or sudo group
    for forbidden_svc in FORBIDDEN_SERVICE_ACCOUNTS:
        leaked_docker_env = deepcopy(env)
        leaked_docker_env.group_lines = [
            f"docker:x:998:sheetsafe-runner,{forbidden_svc}"
            if line.startswith("docker:")
            else line
            for line in env.group_lines
        ]
        with pytest.raises(SmokeAdmissionError) as exc_info:
            verify_operator_identity(leaked_docker_env)
        assert exc_info.value.code is SmokeFailureCode.OPERATOR_IDENTITY_INVALID

    # 9. Rejects sheetsafe-runner in sudo/root/wheel group
    sudo_runner_env = deepcopy(env)
    sudo_runner_env.group_lines = [
        "sudo:x:27:linuxuser,sheetsafe-runner"
        if line.startswith("sudo:")
        else line
        for line in env.group_lines
    ]
    with pytest.raises(SmokeAdmissionError) as exc_info:
        verify_operator_identity(sudo_runner_env)
    assert exc_info.value.code is SmokeFailureCode.OPERATOR_IDENTITY_INVALID

    # 10. Rejects world-accessible, non-root, symlinked, or non-writable Docker socket
    for bad_sock in (
        StatFacts(0o140666, 0, 998, 1, 1, 100),  # world read/write
        StatFacts(0o140660, 993, 998, 1, 1, 100),  # not owned by root
        StatFacts(0o120777, 0, 998, 1, 1, 100),  # symlink
        StatFacts(0o100660, 0, 998, 1, 1, 100),  # regular file, not socket
        StatFacts(0o140600, 0, 998, 1, 1, 100),  # runner cannot write socket
    ):
        bad_sock_env = deepcopy(env)
        bad_sock_env.socket_facts = bad_sock
        with pytest.raises(SmokeAdmissionError) as exc_info:
            verify_operator_identity(bad_sock_env)
        assert exc_info.value.code is SmokeFailureCode.OPERATOR_IDENTITY_INVALID


def test_smoke_adapter_default_state_path_and_git_checkout_rejection(
    tmp_path: Path,
):
    """Default state ledger is /var/lib/sheetsafe/runner/smoke_state.json and Git checkouts are rejected."""
    assert PROTECTED_STATE_DIR == Path("/var/lib/sheetsafe/runner")
    assert DEFAULT_STATE_FILE_PATH == Path(
        "/var/lib/sheetsafe/runner/smoke_state.json"
    )
    assert DEFAULT_LOCK_FILE_NAME == "smoke_state.lock"

    # 1. State path inside a simulated Git checkout (ancestor contains .git) is rejected fail-closed
    fake_repo = tmp_path / "user_checkout"
    fake_repo.mkdir(mode=0o700)
    fake_repo.chmod(0o700)
    (fake_repo / ".git").mkdir(mode=0o700)
    checkout_state_dir = fake_repo / "runner_state"
    checkout_state_dir.mkdir(mode=0o700)
    checkout_state_dir.chmod(0o700)

    fake_docker = FakeSmokeDocker()
    adapter = SmokeAdapter(
        fake_docker,
        state_path=checkout_state_dir / "smoke_state.json",
        trusted_ancestor_root=fake_repo,
    )
    assert adapter.admissions_blocked is True
    with pytest.raises(SmokeAdmissionError) as exc_info:
        adapter.run_smoke("smoke-v1", dry_run=False)
    assert exc_info.value.code is SmokeFailureCode.STATE_STORAGE_UNSAFE
    assert "Git checkout" in str(exc_info.value)
    assert len(fake_docker.calls) == 0

    # 2. Requiring protected root rejects any directory other than /var/lib/sheetsafe/runner
    valid_test_dir = tmp_path / "valid_runner"
    valid_test_dir.mkdir(mode=0o700)
    valid_test_dir.chmod(0o700)
    adapter_protected = SmokeAdapter(
        fake_docker,
        state_path=valid_test_dir / "smoke_state.json",
        require_protected_root=True,
    )
    assert adapter_protected.admissions_blocked is True
    with pytest.raises(SmokeAdmissionError) as exc_info2:
        adapter_protected.run_smoke("smoke-v1", dry_run=False)
    assert exc_info2.value.code is SmokeFailureCode.STATE_STORAGE_UNSAFE


def test_smoke_adapter_rejects_weak_permissions_and_wrong_ownership(
    tmp_path: Path,
):
    """Directory and file permissions and ownership are strictly validated before any admission."""
    fake_docker = FakeSmokeDocker()

    # 1. Missing state directory fails closed (never auto-created with mkdir(parents=True))
    missing_dir = tmp_path / "does_not_exist"
    adapter_missing = SmokeAdapter(
        fake_docker, state_path=missing_dir / "smoke_state.json"
    )
    assert adapter_missing.admissions_blocked is True
    with pytest.raises(SmokeAdmissionError) as exc_info:
        adapter_missing.run_smoke("smoke-v1", dry_run=False)
    assert exc_info.value.code is SmokeFailureCode.STATE_STORAGE_UNSAFE

    # 2. State directory with weak permissions (0o755, 0o770, 0o777) fails closed
    for weak_dir_mode in (0o755, 0o770, 0o777):
        weak_dir = tmp_path / f"dir_{oct(weak_dir_mode)}"
        weak_dir.mkdir(mode=0o700)
        weak_dir.chmod(weak_dir_mode)
        adapter_weak_dir = SmokeAdapter(
            fake_docker, state_path=weak_dir / "smoke_state.json"
        )
        assert adapter_weak_dir.admissions_blocked is True
        with pytest.raises(SmokeAdmissionError) as exc_info:
            adapter_weak_dir.run_smoke("smoke-v1", dry_run=False)
        assert exc_info.value.code is SmokeFailureCode.STATE_STORAGE_UNSAFE
        weak_dir.chmod(0o700)

    # 3. State file or lock file with weak permissions (0o644, 0o660, 0o666) fails closed
    state_dir = tmp_path / "strict_dir"
    state_dir.mkdir(mode=0o700)
    state_dir.chmod(0o700)
    state_file = state_dir / "smoke_state.json"
    adapter_init = SmokeAdapter(fake_docker, state_path=state_file)
    adapter_init.initialize_ledger()
    assert state_file.exists()

    for weak_file_mode in (0o644, 0o660, 0o666):
        state_file.chmod(weak_file_mode)
        adapter_weak_file = SmokeAdapter(fake_docker, state_path=state_file)
        assert adapter_weak_file.admissions_blocked is True
        with pytest.raises(SmokeAdmissionError) as exc_info:
            adapter_weak_file.run_smoke("smoke-v1", dry_run=False)
        assert exc_info.value.code is SmokeFailureCode.STATE_STORAGE_UNSAFE
    state_file.chmod(0o600)

    lock_file = state_dir / DEFAULT_LOCK_FILE_NAME
    assert lock_file.exists()
    lock_file.chmod(0o644)
    adapter_weak_lock = SmokeAdapter(fake_docker, state_path=state_file)
    assert adapter_weak_lock.admissions_blocked is True
    with pytest.raises(SmokeAdmissionError) as exc_info:
        adapter_weak_lock.run_smoke("smoke-v1", dry_run=False)
    assert exc_info.value.code is SmokeFailureCode.STATE_STORAGE_UNSAFE
    lock_file.chmod(0o600)

    # 4. Group-writable or world-writable ancestor directory fails closed
    bad_ancestor = tmp_path / "writable_ancestor"
    bad_ancestor.mkdir(mode=0o700)
    nested_runner = bad_ancestor / "runner"
    nested_runner.mkdir(mode=0o700)
    nested_runner.chmod(0o700)
    for bad_anc_mode in (0o775, 0o777, 0o1777):
        bad_ancestor.chmod(bad_anc_mode)
        adapter_bad_anc = SmokeAdapter(
            fake_docker,
            state_path=nested_runner / "smoke_state.json",
            trusted_ancestor_root=tmp_path,
        )
        assert adapter_bad_anc.admissions_blocked is True
        with pytest.raises(SmokeAdmissionError) as exc_info:
            adapter_bad_anc.run_smoke("smoke-v1", dry_run=False)
        assert exc_info.value.code is SmokeFailureCode.STATE_STORAGE_UNSAFE
    bad_ancestor.chmod(0o700)

    # 5. Wrong owner UID/GID on state_dir or state_file or guest UID 10001 fails closed
    env_wrong_owner = FakeOperatorEnvReader()
    current_euid = LocalOperatorEnvironmentReader().euid()
    current_egid = LocalOperatorEnvironmentReader().egid()
    env_wrong_owner._uid = env_wrong_owner._euid = current_euid
    env_wrong_owner._gid = env_wrong_owner._egid = current_egid
    env_wrong_owner.path_overrides[Path(os.path.abspath(state_dir))] = (
        lambda f: StatFacts(
            f.st_mode, 99999, f.st_gid, f.st_nlink, f.st_dev, f.st_ino
        )
    )
    adapter_wrong_owner = SmokeAdapter(
        fake_docker, state_path=state_file, env_reader=env_wrong_owner
    )
    assert adapter_wrong_owner.admissions_blocked is True
    with pytest.raises(SmokeAdmissionError) as exc_info:
        adapter_wrong_owner.run_smoke("smoke-v1", dry_run=False)
    assert exc_info.value.code is SmokeFailureCode.STATE_STORAGE_UNSAFE

    env_guest = FakeOperatorEnvReader()
    env_guest._uid = env_guest._euid = CONTAINER_GUEST_UID
    env_guest._gid = env_guest._egid = CONTAINER_GUEST_GID
    adapter_guest = SmokeAdapter(
        fake_docker, state_path=state_file, env_reader=env_guest
    )
    assert adapter_guest.admissions_blocked is True
    with pytest.raises(SmokeAdmissionError) as exc_info:
        adapter_guest.run_smoke("smoke-v1", dry_run=False)
    assert exc_info.value.code is SmokeFailureCode.OPERATOR_IDENTITY_INVALID
    assert len(fake_docker.calls) == 0


def test_smoke_adapter_rejects_symlinks_and_hardlinks(tmp_path: Path):
    """Symlinked state file, lock file, state directory, ancestor directory, and hardlinks fail closed."""
    fake_docker = FakeSmokeDocker()

    outside_target = tmp_path / "outside_target.json"
    outside_target.write_text("{}", encoding="utf-8")
    outside_target.chmod(0o600)

    # 1. Symlinked state file is rejected without creating smoke_state.lock (isolated directory)
    case1_dir = tmp_path / "case1_sym_state"
    case1_dir.mkdir(mode=0o700)
    case1_dir.chmod(0o700)
    sym_state = case1_dir / "smoke_state.json"
    _create_symlink_for_test(outside_target, sym_state)
    adapter1 = SmokeAdapter(fake_docker, state_path=sym_state)
    assert adapter1.admissions_blocked is True
    with pytest.raises(SmokeAdmissionError) as exc_info:
        adapter1.run_smoke("smoke-v1", dry_run=False)
    assert exc_info.value.code is SmokeFailureCode.STATE_STORAGE_UNSAFE
    assert not (case1_dir / DEFAULT_LOCK_FILE_NAME).exists()

    # 2. Symlinked lock file is rejected (isolated directory)
    case2_dir = tmp_path / "case2_sym_lock"
    case2_dir.mkdir(mode=0o700)
    case2_dir.chmod(0o700)
    sym_lock = case2_dir / DEFAULT_LOCK_FILE_NAME
    _create_symlink_for_test(outside_target, sym_lock)
    adapter2 = SmokeAdapter(
        fake_docker, state_path=case2_dir / "smoke_state.json"
    )
    assert adapter2.admissions_blocked is True
    with pytest.raises(SmokeAdmissionError) as exc_info:
        adapter2.run_smoke("smoke-v1", dry_run=False)
    assert exc_info.value.code is SmokeFailureCode.STATE_STORAGE_UNSAFE

    # 3. Symlinked state directory is rejected (isolated directory)
    case3_base = tmp_path / "case3_sym_dir"
    case3_base.mkdir(mode=0o700)
    case3_base.chmod(0o700)
    case3_real = case3_base / "real_runner"
    case3_real.mkdir(mode=0o700)
    case3_real.chmod(0o700)
    sym_dir = case3_base / "symlinked_runner_dir"
    _create_symlink_for_test(case3_real, sym_dir, target_is_directory=True)
    adapter3 = SmokeAdapter(
        fake_docker, state_path=sym_dir / "smoke_state.json"
    )
    assert adapter3.admissions_blocked is True
    with pytest.raises(SmokeAdmissionError) as exc_info:
        adapter3.run_smoke("smoke-v1", dry_run=False)
    assert exc_info.value.code is SmokeFailureCode.STATE_STORAGE_UNSAFE

    # 4. Symlinked ancestor directory is rejected (isolated directory)
    case4_base = tmp_path / "case4_sym_ancestor"
    case4_base.mkdir(mode=0o700)
    case4_base.chmod(0o700)
    real_parent = case4_base / "real_parent"
    real_parent.mkdir(mode=0o700)
    real_parent.chmod(0o700)
    nested_dir = real_parent / "runner"
    nested_dir.mkdir(mode=0o700)
    nested_dir.chmod(0o700)
    sym_parent = case4_base / "sym_parent"
    _create_symlink_for_test(real_parent, sym_parent, target_is_directory=True)
    adapter4 = SmokeAdapter(
        fake_docker,
        state_path=sym_parent / "runner" / "smoke_state.json",
        trusted_ancestor_root=case4_base,
    )
    assert adapter4.admissions_blocked is True
    with pytest.raises(SmokeAdmissionError) as exc_info:
        adapter4.run_smoke("smoke-v1", dry_run=False)
    assert exc_info.value.code is SmokeFailureCode.STATE_STORAGE_UNSAFE

    # 5. Hardlinked state file (st_nlink > 1) is rejected (isolated directory)
    case5_dir = tmp_path / "case5_hardlink_state"
    case5_dir.mkdir(mode=0o700)
    case5_dir.chmod(0o700)
    valid_state = case5_dir / "smoke_state.json"
    adapter_ok = SmokeAdapter(fake_docker, state_path=valid_state)
    adapter_ok.initialize_ledger()
    hardlink_path = tmp_path / "hardlinked_state.json"
    win_hardlinks = getattr(
        LocalOperatorEnvironmentReader, "_win_recorded_hardlinks", None
    )
    if os.name != "nt":
        os.link(valid_state, hardlink_path)
    else:
        try:
            os.link(valid_state, hardlink_path)
        except OSError:
            hardlink_path.write_bytes(valid_state.read_bytes())
            if win_hardlinks is not None:
                win_hardlinks.add(Path(os.path.abspath(valid_state)))
    try:
        adapter5 = SmokeAdapter(fake_docker, state_path=valid_state)
        assert adapter5.admissions_blocked is True
        with pytest.raises(SmokeAdmissionError) as exc_info:
            adapter5.run_smoke("smoke-v1", dry_run=False)
        assert exc_info.value.code is SmokeFailureCode.STATE_STORAGE_UNSAFE
    finally:
        if win_hardlinks is not None:
            win_hardlinks.discard(Path(os.path.abspath(valid_state)))
        hardlink_path.unlink()

    # 6. Hardlinked lock file (st_nlink > 1) is rejected (isolated directory)
    case6_dir = tmp_path / "case6_hardlink_lock"
    case6_dir.mkdir(mode=0o700)
    case6_dir.chmod(0o700)
    case6_state = case6_dir / "smoke_state.json"
    adapter6_init = SmokeAdapter(fake_docker, state_path=case6_state)
    adapter6_init.initialize_ledger()
    case6_lock = case6_dir / DEFAULT_LOCK_FILE_NAME
    assert case6_lock.exists()
    hardlink_lock_path = tmp_path / "hardlinked_lock.lock"
    if os.name != "nt":
        os.link(case6_lock, hardlink_lock_path)
    else:
        try:
            os.link(case6_lock, hardlink_lock_path)
        except OSError:
            hardlink_lock_path.write_bytes(b"")
            if win_hardlinks is not None:
                win_hardlinks.add(Path(os.path.abspath(case6_lock)))
    try:
        adapter6 = SmokeAdapter(fake_docker, state_path=case6_state)
        assert adapter6.admissions_blocked is True
        with pytest.raises(SmokeAdmissionError) as exc_info:
            adapter6.run_smoke("smoke-v1", dry_run=False)
        assert exc_info.value.code is SmokeFailureCode.STATE_STORAGE_UNSAFE
    finally:
        if win_hardlinks is not None:
            win_hardlinks.discard(Path(os.path.abspath(case6_lock)))
        hardlink_lock_path.unlink()

    assert len(fake_docker.calls) == 0


def test_smoke_adapter_process_lock_prevents_concurrent_admissions(
    tmp_path: Path,
):
    """Process-level lock on smoke_state.lock prevents two operator instances from admitting simultaneous jobs."""
    state_dir = tmp_path / "lock_runner"
    state_dir.mkdir(mode=0o700)
    state_dir.chmod(0o700)
    state_file = state_dir / "smoke_state.json"

    docker1 = FakeSmokeDocker()
    docker1.container_running = False
    docker2 = FakeSmokeDocker()
    docker2.container_running = False

    adapter1 = SmokeAdapter(docker1, state_path=state_file)
    adapter1.initialize_ledger()
    adapter2 = SmokeAdapter(docker2, state_path=state_file)

    competing_outcomes: list[SmokeFailureCode] = []

    def try_concurrent_admission_during_start(self, cid):
        # While adapter1 is mid-execution holding smoke_state.lock, adapter2 attempts admission
        with pytest.raises(SmokeAdmissionError) as exc_info:
            adapter2.run_smoke("smoke-v1", dry_run=False)
        competing_outcomes.append(exc_info.value.code)

    docker1.start_hook = try_concurrent_admission_during_start

    r1 = adapter1.run_smoke("smoke-v1", dry_run=False)
    assert r1.outcome is SmokeOutcome.COMPLETED
    assert competing_outcomes == [SmokeFailureCode.JOB_ACTIVE]
    assert len(docker2.calls) == 0

    # Once adapter1 completes and releases smoke_state.lock, adapter2 can acquire it cleanly
    docker2.counter = 10  # distinct container ID
    r2 = adapter2.run_smoke("smoke-v1", dry_run=False)
    assert r2.outcome is SmokeOutcome.COMPLETED


def test_smoke_adapter_atomic_write_dir_fsync_init_and_missing_expected_state(
    tmp_path: Path, monkeypatch
):
    """Atomic ledger write fsyncs file and parent directory, and missing expected state fails closed."""
    state_dir = tmp_path / "atomic_runner"
    state_dir.mkdir(mode=0o700)
    state_dir.chmod(0o700)
    state_file = state_dir / "smoke_state.json"

    fsynced_fds: list[int] = []
    orig_fsync = os.fsync

    def tracking_fsync(fd: int) -> None:
        fsynced_fds.append(fd)
        orig_fsync(fd)

    monkeypatch.setattr(os, "fsync", tracking_fsync)

    # 1. require_initialized_ledger=True fails closed when smoke_state.json does not exist yet
    docker = FakeSmokeDocker()
    docker.container_running = False
    uninit_adapter = SmokeAdapter(
        docker, state_path=state_file, require_initialized_ledger=True
    )
    assert uninit_adapter.admissions_blocked is True
    with pytest.raises(SmokeAdmissionError) as exc_info:
        uninit_adapter.run_smoke("smoke-v1", dry_run=False)
    assert exc_info.value.code is SmokeFailureCode.ADMISSIONS_BLOCKED
    assert len(docker.calls) == 0

    # 2. initialize_ledger() atomically writes IDLE state and fsyncs (file + dir on POSIX)
    init_receipt = uninit_adapter.initialize_ledger()
    assert init_receipt["initialized"] is True
    assert init_receipt["status"] == "IDLE"
    assert state_file.exists()
    assert len(fsynced_fds) >= (2 if os.name != "nt" else 1)

    # Second call to initialize_ledger() is idempotent
    init_receipt2 = uninit_adapter.initialize_ledger()
    assert init_receipt2["initialized"] is False
    assert init_receipt2["status"] == "IDLE"

    # Now run_smoke succeeds with require_initialized_ledger=True
    r1 = uninit_adapter.run_smoke("smoke-v1", dry_run=False)
    assert r1.outcome is SmokeOutcome.COMPLETED

    # 3. Deleting an expected state file mid-deployment causes immediate fail-closed ADMISSIONS_BLOCKED
    state_file.unlink()
    assert uninit_adapter.admissions_blocked is True
    with pytest.raises(SmokeAdmissionError) as exc_info2:
        uninit_adapter.run_smoke("smoke-v1", dry_run=False)
    assert exc_info2.value.code is SmokeFailureCode.ADMISSIONS_BLOCKED

    # 4. initialize_ledger() refuses to overwrite a blocked/unresolved or corrupted ledger
    state_file.write_text(
        json.dumps(
            {
                "version": 1,
                "status": "UNRESOLVED",
                "blocked": True,
                "active_job_id": "a" * 32,
                "active_container_name": "sheetsafe-smoke-" + ("a" * 32),
                "active_container_id": "1" * 64,
                "failure_reason": "CLEANUP_UNRESOLVED",
                "seen_container_ids": ["1" * 64],
            }
        ),
        encoding="utf-8",
    )
    state_file.chmod(0o600)
    blocked_adapter = SmokeAdapter(docker, state_path=state_file)
    with pytest.raises(SmokeAdmissionError) as exc_info3:
        blocked_adapter.initialize_ledger()
    assert exc_info3.value.code is SmokeFailureCode.ADMISSIONS_BLOCKED


def test_operator_launcher_script_and_cli_deployment_modes(
    tmp_path: Path, monkeypatch, capsys
):
    """Verify the reviewed operator launcher script and CLI --init-state-ledger / --verify-operator-deployment flags."""
    launcher = (
        Path(__file__).resolve().parent.parent
        / "scripts"
        / "run_operator_smoke.sh"
    )
    assert launcher.exists()
    raw_script = launcher.read_bytes()
    assert b"\r\n" not in raw_script, "Launcher script must use LF line endings"
    script_text = raw_script.decode("utf-8")
    assert "set -euo pipefail" in script_text
    assert "umask 0077" in script_text
    assert 'EXPECTED_ACCOUNT="sheetsafe-runner"' in script_text
    assert 'PROTECTED_DIR="/var/lib/sheetsafe/runner"' in script_text
    assert (
        'STATE_FILE="/var/lib/sheetsafe/runner/smoke_state.json"'
        in script_text
    )
    assert "--verify-operator-deployment" in script_text
    assert "--init-state-ledger" in script_text

    # Test CLI --init-state-ledger on Linux with custom state file
    monkeypatch.setattr("sys.platform", "linux")
    state_dir = tmp_path / "cli_init_runner"
    state_dir.mkdir(mode=0o700)
    state_dir.chmod(0o700)
    state_file = state_dir / "smoke_state.json"

    rc = main(["--init-state-ledger", "--state-file", str(state_file)])
    assert rc == 0
    out_data = json.loads(capsys.readouterr().out)
    assert out_data["initialized"] is True
    assert out_data["status"] == "IDLE"
    assert state_file.exists()

    # Second CLI --init-state-ledger is idempotent
    rc2 = main(["--init-state-ledger", "--state-file", str(state_file)])
    assert rc2 == 0
    out_data2 = json.loads(capsys.readouterr().out)
    assert out_data2["initialized"] is False
    assert out_data2["status"] == "IDLE"
