"""Portable synthetic Linux evidence; no Docker or container execution."""

from copy import deepcopy
from dataclasses import FrozenInstanceError, asdict
import json
from types import SimpleNamespace
import stat
import subprocess

import pytest

from runner import host_readiness as host
from runner.docker_backend import LOCAL_IMAGE_ID
from runner.engine_metadata import LOCAL_CONFIG_DIGEST
from runner.policy import SandboxPolicy, RunnerNotReady, require_execution_ready


PRIVATE = "synthetic-sensitive-host-error-do-not-publish"


class FakeEngine:
    def __init__(self):
        self.calls = []
        self.failure = None
        self.details = {
            "OSType": "linux", "Architecture": "x86_64", "KernelVersion": "6.8.0-generic",
            "CgroupVersion": "2", "CgroupDriver": "systemd", "MemoryLimit": True,
            "SwapLimit": True, "CpuCfsPeriod": True, "CpuCfsQuota": True, "PidsLimit": True,
            "SecurityOptions": ["name=seccomp,profile=builtin", "name=apparmor", "name=cgroupns"],
            "DefaultRuntime": "runc", "Runtimes": {"runc": {"path": "runc"}}, "Warnings": None,
        }

    def read(self, name, value):
        self.calls.append(name)
        if self.failure == name:
            raise PermissionError(PRIVATE)
        return deepcopy(value)

    def channel(self):
        return self.read("channel", {"Host": "unix:///var/run/docker.sock", "SkipTLSVerify": False})

    def version(self):
        return self.read("version", {"Client": {"ApiVersion": "1.56"}, "Server": {
            "Version": "29.9.1", "ApiVersion": "1.56", "MinAPIVersion": "1.40", "Os": "linux", "Arch": "amd64"}})

    def info(self):
        return self.read("info", self.details)

    def image(self):
        policy = SandboxPolicy()
        return self.read("image", {"Id": LOCAL_IMAGE_ID, "Os": "linux", "Architecture": "amd64", "RepoDigests": [],
            "Descriptor": {"digest": LOCAL_IMAGE_ID, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "annotations": {"config.digest": LOCAL_CONFIG_DIGEST}},
            "Config": {"User": "10001:10001", "Entrypoint": list(policy.entrypoint), "Cmd": ["smoke-v1"],
                "WorkingDir": "/work", "StopSignal": "SIGTERM", "Env": [f"{k}={v}" for k, v in policy.environment],
                "ArgsEscaped": True, "Labels": {"org.opencontainers.image.title": "SheetSafe fixed smoke fixture",
                    "org.opencontainers.image.version": "smoke-v1", "io.sheetsafe.policy": policy.version}}})


class FakeHost:
    def __init__(self):
        self.os = "Linux"
        self.arch = "x86_64"
        self.calls = []
        self.data = {
            "kernel": "6.8.0-generic\n", "controllers": "cpu memory pids io\n",
            "lsm": "capability,landlock,yama,apparmor\n", "apparmor_enabled": "Y\n",
            "apparmor_profiles": "other-profile (complain)\ndocker-default (enforce)\n",
            "selinux_enforce": None, "swaps": "Filename Type Size Used Priority\n", "swap_limit": None,
            "cpu_accounting": "usage_usec 0\n", "memory_events": None, "pid_accounting": None,
            "passwd": "\n".join(f"{name}:x:{20011+i}:{20011+i}::/nonexistent:/usr/sbin/nologin" for i, name in enumerate(host.SERVICE_NAMES)),
            "group": "docker:x:999:sheetsafe-runner\n",
        }
        self.files = {
            "socket": host.FileFacts(0, 999, stat.S_IFSOCK | 0o660),
            "api_storage": host.FileFacts(20011, 20011, stat.S_IFDIR | 0o700),
            "runner_storage": host.FileFacts(20013, 20013, stat.S_IFDIR | 0o700),
        }
        self.missing_namespaces = set()

    def system(self):
        return self.os

    def architecture(self):
        return self.arch

    def uid(self):
        return 20013

    def text(self, name):
        self.calls.append(("text", name))
        value = self.data.get(name)
        if isinstance(value, Exception):
            raise value
        if type(value) is host.Observation:
            return value
        return host.Observation(host.State.MISSING if value is None else host.State.OBSERVED, value)

    def metadata(self, name):
        self.calls.append(("metadata", name))
        value = self.files.get(name)
        if isinstance(value, Exception):
            raise value
        if value is None:
            raise FileNotFoundError(PRIVATE)
        return value

    def namespace(self, name):
        self.calls.append(("namespace", name))
        return name not in self.missing_namespaces

    def pidfd_api(self):
        return True


@pytest.fixture(autouse=True)
def no_processes(monkeypatch):
    calls = []
    def forbidden(*args, **kwargs):
        calls.append(True)
        raise AssertionError("Host assessment attempted a real process")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    yield
    assert not calls


@pytest.fixture
def evidence():
    return FakeHost(), FakeEngine()


def checks(report):
    return {item.name: item.state for item in report.checks}


def test_enforcing_apparmor_is_host_evidence_not_execution_permission(evidence):
    reader, engine = evidence
    report = host.assess_host(reader, engine)
    assert report.lsms[0].classification is host.LSMState.ENFORCING
    assert report.lsms[0].intended_profile is host.State.OBSERVED
    assert checks(report)["CPU_CONTROLLER"] is host.State.OBSERVED
    assert checks(report)["DISTINCT_SERVICE_IDENTITIES"] is host.State.OBSERVED
    assert checks(report)["DOCKER_SOCKET_LOCAL_DAC"] is host.State.OBSERVED
    assert report.daemon_kernel_matches_local is True
    assert report.native_linux_acceptance == "PENDING" and not report.execution_enabled
    assert len(report.unverified_controls) == 10
    assert engine.calls == ["channel", "version", "info", "image"]
    with pytest.raises(RunnerNotReady):
        require_execution_ready()
    with pytest.raises(FrozenInstanceError):
        report.execution_enabled = True


def test_enforcing_selinux_does_not_bypass_unsupported_container_mapping(evidence):
    reader, engine = evidence
    reader.data.update(lsm="capability,selinux\n", selinux_enforce="1\n", apparmor_enabled=None)
    reader.files["selinux_policy"] = host.FileFacts(0, 0, stat.S_IFREG | 0o600)
    engine.details["SecurityOptions"] = ["name=seccomp,profile=builtin", "name=cgroupns", "name=selinux"]
    report = host.assess_host(reader, engine)
    assert report.lsms[1].classification is host.LSMState.ENFORCING
    assert report.lsms[1].intended_profile is host.State.PENDING
    assert report.lsms[1].enforcement_scope == "global SELinux mode only"
    assert report.preflight.issues == ("LSM_MAPPING_UNSUPPORTED",)
    assert not report.preflight.metadata_prerequisites_met and not report.execution_enabled


@pytest.mark.parametrize("enabled,profiles,expected", [
    ("N\n", "docker-default (enforce)\n", host.LSMState.NON_ENFORCING),
    ("Y\n", "docker-default (complain)\n", host.LSMState.NON_ENFORCING),
    ("Y\n", "other (enforce)\n", host.LSMState.NON_ENFORCING),
    ("Y\n", PermissionError(PRIVATE), host.LSMState.UNKNOWN),
    ("Y\n", None, host.LSMState.UNKNOWN),
    ("malformed", "docker-default (enforce)\n", host.LSMState.UNKNOWN),
    (PermissionError(PRIVATE), "docker-default (enforce)\n", host.LSMState.UNKNOWN),
    ("Y\n", "docker-default (enforce)\ndocker-default (complain)\n", host.LSMState.NON_ENFORCING),
])
def test_apparmor_enforcement_needs_enabled_module_active_lsm_and_profile(evidence, enabled, profiles, expected):
    reader, engine = evidence
    reader.data.update(apparmor_enabled=enabled, apparmor_profiles=profiles)
    assert host.assess_host(reader, engine).lsms[0].classification is expected


@pytest.mark.parametrize("active", [None, PermissionError(PRIVATE), "apparmor,apparmor", "apparmor,\x00"])
def test_unknown_active_lsm_list_cannot_attest_enforcement(evidence, active):
    reader, engine = evidence
    reader.data["lsm"] = active
    report = host.assess_host(reader, engine)
    assert report.lsms[0].classification is host.LSMState.UNKNOWN


def test_missing_lsm_current_boot_is_unsupported_and_engine_gate_remains(evidence):
    reader, engine = evidence
    reader.data.update(lsm="capability,yama", apparmor_enabled=None)
    engine.details["SecurityOptions"].remove("name=apparmor")
    report = host.assess_host(reader, engine)
    assert report.lsms[0].classification is host.LSMState.UNSUPPORTED
    assert report.preflight.issues == ("LSM_NOT_ADVERTISED",)


@pytest.mark.parametrize("mode,policy,expected", [
    ("0", True, host.LSMState.NON_ENFORCING), ("1", False, host.LSMState.UNKNOWN),
    (None, True, host.LSMState.UNKNOWN), (PermissionError(PRIVATE), True, host.LSMState.UNKNOWN),
])
def test_selinux_global_mode_and_policy_need_independent_evidence(evidence, mode, policy, expected):
    reader, engine = evidence
    reader.data.update(lsm="capability,selinux", selinux_enforce=mode)
    if policy:
        reader.files["selinux_policy"] = host.FileFacts(0, 0, stat.S_IFREG | 0o600)
    assert host.assess_host(reader, engine).lsms[1].classification is expected


@pytest.mark.parametrize("name", ["cpu", "memory", "pids"])
def test_missing_controller_is_explicit(evidence, name):
    reader, engine = evidence
    reader.data["controllers"] = " ".join(value for value in ("cpu", "memory", "pids") if value != name)
    assert checks(host.assess_host(reader, engine))[name.upper() + "_CONTROLLER"] is host.State.MISSING


@pytest.mark.parametrize("name", host.NAMESPACES)
def test_missing_namespace_is_not_supported(evidence, name):
    reader, engine = evidence
    reader.missing_namespaces.add(name)
    assert checks(host.assess_host(reader, engine))[name.upper() + "_NAMESPACE_INTERFACE"] is host.State.MISSING


@pytest.mark.parametrize("field,value,issue", [
    ("Architecture", "aarch64", "ARCHITECTURE_UNSUPPORTED"),
    ("CgroupVersion", "1", "CGROUP_UNSUPPORTED"),
    ("DefaultRuntime", "other", "RUNTIME_UNSUPPORTED"),
    ("SwapLimit", False, "SWAPLIMIT_UNSUPPORTED"),
])
def test_existing_engine_capability_failures_survive_host_assessment(evidence, field, value, issue):
    reader, engine = evidence
    engine.details[field] = value
    report = host.assess_host(reader, engine)
    assert issue in report.preflight.issues and not report.execution_enabled


def test_missing_seccomp_stays_blocking(evidence):
    reader, engine = evidence
    engine.details["SecurityOptions"].remove("name=seccomp,profile=builtin")
    assert "BUILTIN_SECCOMP_REQUIRED" in host.assess_host(reader, engine).preflight.issues


@pytest.mark.parametrize("failure", ["channel", "version", "info", "image"])
def test_engine_permission_and_communication_errors_are_sanitized(evidence, failure, caplog):
    reader, engine = evidence
    engine.failure = failure
    report = host.assess_host(reader, engine)
    assert report.preflight.issues and not report.execution_enabled
    assert PRIVATE not in json.dumps(asdict(report)) + caplog.text


@pytest.mark.parametrize("os_name", ["Windows", "Darwin", PRIVATE])
def test_non_linux_never_reads_local_linux_paths_or_certifies_daemon_host(evidence, os_name):
    reader, engine = evidence
    reader.os = os_name
    engine.details["SecurityOptions"].remove("name=apparmor")
    report = host.assess_host(reader, engine)
    assert reader.calls == [] and report.kernel_release is None
    assert report.lsms[0].classification is host.LSMState.NOT_ADVERTISED
    assert report.native_linux_acceptance == "PENDING"
    assert PRIVATE not in repr(report)


def test_advertised_lsm_on_windows_is_still_unknown(evidence):
    reader, engine = evidence
    reader.os = "Windows"
    assert host.assess_host(reader, engine).lsms[0].classification is host.LSMState.UNKNOWN


@pytest.mark.parametrize("name", ["kernel", "controllers", "passwd", "group", "swaps"])
def test_host_permission_failures_are_unknown_not_success(evidence, name):
    reader, engine = evidence
    reader.data[name] = PermissionError(PRIVATE)
    report = host.assess_host(reader, engine)
    assert host.State.UNKNOWN in checks(report).values()
    assert PRIVATE not in json.dumps(asdict(report))


def test_web_or_validator_docker_group_membership_rejected(evidence):
    reader, engine = evidence
    reader.data["group"] = "docker:x:999:sheetsafe-runner,sheetsafe-api,sheetsafe-ui,sheetsafe-validator\n"
    assert checks(host.assess_host(reader, engine))["DOCKER_SOCKET_LOCAL_DAC"] is host.State.MISSING


@pytest.mark.parametrize("mode", [0o666, 0o660 | stat.S_IFREG, 0o777 | stat.S_IFSOCK])
def test_unsafe_socket_permissions_or_kind_rejected(evidence, mode):
    reader, engine = evidence
    reader.files["socket"] = host.FileFacts(0, 999, mode)
    assert checks(host.assess_host(reader, engine))["DOCKER_SOCKET_LOCAL_DAC"] is host.State.MISSING


def test_missing_service_accounts_do_not_pass(evidence):
    reader, engine = evidence
    reader.data["passwd"] = "root:x:0:0::/root:/bin/sh\n"
    assert checks(host.assess_host(reader, engine))["SERVICE_PERMISSION_EVIDENCE"] is host.State.UNKNOWN


def test_wrong_architecture_and_mismatched_daemon_kernel_are_visible(evidence):
    reader, engine = evidence
    reader.arch = "aarch64"
    reader.data["kernel"] = "6.1.0-other"
    report = host.assess_host(reader, engine)
    assert checks(report)["HOST_ARCHITECTURE"] is host.State.UNSUPPORTED
    assert report.daemon_kernel_matches_local is False


def test_current_host_enforcement_cannot_clear_engine_lsm_gate(evidence):
    reader, engine = evidence
    engine.details["SecurityOptions"].remove("name=apparmor")
    report = host.assess_host(reader, engine)
    assert report.lsms[0].classification is host.LSMState.ENFORCING
    assert report.preflight.issues == ("LSM_NOT_ADVERTISED",)
    assert not report.preflight.metadata_prerequisites_met


@pytest.mark.parametrize("name", ["../etc/shadow", "/etc/shadow", "unknown", "kernel; reboot"])
def test_local_reader_rejects_unallowlisted_paths(name):
    reader = host.LocalHostReader()
    for method in (reader.text, reader.metadata, reader.namespace):
        with pytest.raises(ValueError):
            method(name)


@pytest.mark.parametrize("payload,kind,expected", [
    (b"6.8.0\n", stat.S_IFREG, host.State.OBSERVED),
    (b"\xff", stat.S_IFREG, host.State.UNKNOWN),
    (b"x" * (host.MAX_READ_BYTES + 1), stat.S_IFREG, host.State.UNKNOWN),
    (b"never read FIFO", stat.S_IFIFO, host.State.UNKNOWN),
], ids=["regular", "invalid-utf8", "oversized", "fifo"])
def test_local_file_reads_are_bounded_readonly_and_closed(monkeypatch, payload, kind, expected):
    reader = host.LocalHostReader()
    monkeypatch.setattr(reader, "system", lambda: "Linux")
    for flag in ("O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC"):
        if not hasattr(host.os, flag):
            monkeypatch.setattr(host.os, flag, 0, raising=False)
    opened, closed = [], []
    remaining = bytearray(payload)
    def read(descriptor, count):
        assert count <= 4096
        chunk = bytes(remaining[:count])
        del remaining[:count]
        return chunk
    monkeypatch.setattr(host.os, "open", lambda path, flags: opened.append((path, flags)) or 123)
    monkeypatch.setattr(host.os, "read", read)
    monkeypatch.setattr(host.os, "fstat", lambda descriptor: SimpleNamespace(st_mode=kind))
    monkeypatch.setattr(host.os, "close", lambda descriptor: closed.append(descriptor))
    result = reader.text("kernel")
    assert result.state is expected and closed == [123]
    assert opened[0][0] == "/proc/sys/kernel/osrelease"
    assert not opened[0][1] & (host.os.O_WRONLY | host.os.O_RDWR | host.os.O_CREAT | host.os.O_TRUNC)


def test_local_permission_denial_is_not_file_absence(monkeypatch):
    reader = host.LocalHostReader()
    monkeypatch.setattr(reader, "system", lambda: "Linux")
    for flag in ("O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC"):
        if not hasattr(host.os, flag):
            monkeypatch.setattr(host.os, flag, 0, raising=False)
    def denied(*args, **kwargs):
        raise PermissionError(PRIVATE)
    monkeypatch.setattr(host.os, "open", denied)
    assert reader.text("lsm") == host.Observation(host.State.UNKNOWN)


def test_cli_only_collects_evidence_and_returns_nonready_status(evidence, monkeypatch, capsys):
    reader, engine = evidence
    monkeypatch.setattr(host, "LocalHostReader", lambda: reader)
    monkeypatch.setattr(host, "DockerReadOnlyClient", lambda context: engine)
    monkeypatch.setattr("sys.argv", ["host_readiness", "--context", "default"])
    assert host.main() == 2
    result = json.loads(capsys.readouterr().out)
    assert result["native_linux_acceptance"] == "PENDING" and result["execution_enabled"] is False
