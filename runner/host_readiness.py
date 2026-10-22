"""Operator-only, read-only host evidence. Never an execution authorization.

Run on the daemon's native Linux host, not inside a container or Desktop VM
client. Host/daemon co-location, ACLs and effective container controls still
require independent review. No configuration, profile, service or file is changed.
"""

import argparse
from dataclasses import asdict, dataclass, field
from enum import StrEnum
import json
import os
import platform
import re
import stat
from typing import Protocol

from runner.policy import SandboxPolicy
from runner.preflight import DockerReadOnlyClient, EngineReader, LocalContext, PreflightReport, run_preflight


MAX_READ_BYTES = 256 * 1024
TEXT_PATHS = {
    "kernel": "/proc/sys/kernel/osrelease",
    "controllers": "/sys/fs/cgroup/cgroup.controllers",
    "lsm": "/sys/kernel/security/lsm",
    "apparmor_enabled": "/sys/module/apparmor/parameters/enabled",
    "apparmor_profiles": "/sys/kernel/security/apparmor/profiles",
    "selinux_enforce": "/sys/fs/selinux/enforce",
    "passwd": "/etc/passwd", "group": "/etc/group",
    "swaps": "/proc/swaps", "swap_limit": "/sys/fs/cgroup/memory.swap.max",
    "cpu_accounting": "/sys/fs/cgroup/cpu.stat",
    "memory_events": "/sys/fs/cgroup/memory.events",
    "pid_accounting": "/sys/fs/cgroup/pids.current",
}
STAT_PATHS = {
    "socket": "/var/run/docker.sock",
    "api_storage": "/var/lib/sheetsafe/api",
    "runner_storage": "/var/lib/sheetsafe/runner",
    "selinux_policy": "/sys/fs/selinux/policy",
    "cgroup_kill": "/sys/fs/cgroup/cgroup.kill",
}
NAMESPACES = ("pid", "net", "mnt", "ipc", "uts", "user", "cgroup")
SERVICE_NAMES = ("sheetsafe-api", "sheetsafe-ui", "sheetsafe-runner", "sheetsafe-validator")


class State(StrEnum):
    OBSERVED = "OBSERVED"
    MISSING = "MISSING"
    UNSUPPORTED = "UNSUPPORTED"
    UNKNOWN = "UNKNOWN_OR_UNVERIFIED"
    PENDING = "PENDING"


class LSMState(StrEnum):
    ENFORCING = "AVAILABLE_AND_ENFORCING"
    NON_ENFORCING = "SUPPORTED_BUT_NOT_ENFORCING"
    NOT_ADVERTISED = "NOT_ADVERTISED"
    UNSUPPORTED = "UNSUPPORTED"
    UNKNOWN = "UNKNOWN_OR_UNVERIFIED"


@dataclass(frozen=True, slots=True)
class Observation:
    state: State
    value: str | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class FileFacts:
    uid: int
    gid: int
    mode: int


class HostReader(Protocol):
    def system(self) -> str: ...
    def architecture(self) -> str: ...
    def uid(self) -> int: ...
    def text(self, name: str) -> Observation: ...
    def metadata(self, name: str) -> FileFacts: ...
    def namespace(self, name: str) -> bool: ...
    def pidfd_api(self) -> bool: ...


class LocalHostReader:
    """Fixed local paths only. No shells, subprocesses, writes or elevation."""

    def system(self) -> str:
        return platform.system()

    def architecture(self) -> str:
        return platform.machine()

    def uid(self) -> int:
        return os.geteuid()

    def text(self, name: str) -> Observation:
        if name not in TEXT_PATHS or self.system() != "Linux":
            raise ValueError("Host observation is not permitted.")
        try:
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            descriptor = os.open(TEXT_PATHS[name], flags)
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    return Observation(State.UNKNOWN)
                data = bytearray()
                while len(data) <= MAX_READ_BYTES:
                    chunk = os.read(descriptor, min(4096, MAX_READ_BYTES + 1 - len(data)))
                    if not chunk:
                        break
                    data.extend(chunk)
                if len(data) > MAX_READ_BYTES:
                    return Observation(State.UNKNOWN)
                return Observation(State.OBSERVED, data.decode("utf-8", errors="strict"))
            finally:
                os.close(descriptor)
        except FileNotFoundError:
            return Observation(State.MISSING)
        except (OSError, UnicodeError):
            return Observation(State.UNKNOWN)  # Permission failures are not absence.

    def metadata(self, name: str) -> FileFacts:
        if name not in STAT_PATHS or self.system() != "Linux":
            raise ValueError("Host observation is not permitted.")
        value = os.stat(STAT_PATHS[name], follow_symlinks=False)
        return FileFacts(value.st_uid, value.st_gid, value.st_mode)

    def namespace(self, name: str) -> bool:
        if name not in NAMESPACES or self.system() != "Linux":
            raise ValueError("Host observation is not permitted.")
        return re.fullmatch(name + r":\[[0-9]+\]", os.readlink("/proc/self/ns/" + name)) is not None

    def pidfd_api(self) -> bool:
        # Python API presence only; no signal, process creation or pidfd syscall.
        return callable(getattr(os, "pidfd_open", None))


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    state: State


@dataclass(frozen=True, slots=True)
class LSMEvidence:
    name: str
    classification: LSMState
    docker_advertised: bool | None
    # SELinux global enforcement does not verify its intended container domain.
    enforcement_scope: str
    intended_profile: State


@dataclass(frozen=True, slots=True)
class HostReport:
    local_system: str
    local_architecture: str
    kernel_release: str | None
    daemon_kernel_release: str | None
    daemon_kernel_matches_local: bool | None
    checks: tuple[Check, ...]
    lsms: tuple[LSMEvidence, ...]
    preflight: PreflightReport
    native_linux_acceptance: str = field(default="PENDING", init=False)
    execution_enabled: bool = field(default=False, init=False)
    unverified_controls: tuple[str, ...] = field(default=SandboxPolicy().unverified_controls, init=False)


class _CaptureInfo:
    """Retain only the existing info response for kernel comparison; no extra CLI."""

    def __init__(self, reader: EngineReader) -> None:
        self.reader = reader
        self.raw_info = None

    def channel(self):
        return self.reader.channel()

    def version(self):
        return self.reader.version()

    def info(self):
        self.raw_info = self.reader.info()
        return self.raw_info

    def image(self):
        return self.reader.image()


def _text(reader: HostReader, name: str) -> Observation:
    try:
        result = reader.text(name)
        if (type(result) is Observation and type(result.state) is State
                and (result.state is not State.OBSERVED and result.value is None
                    or result.state is State.OBSERVED and type(result.value) is str
                    and len(result.value.encode("utf-8")) <= MAX_READ_BYTES)):
            return result
    except Exception:
        pass
    return Observation(State.UNKNOWN)


def _metadata(reader: HostReader, name: str) -> FileFacts | None:
    try:
        result = reader.metadata(name)
        if type(result) is FileFacts and all(type(v) is int and v >= 0 for v in (result.uid, result.gid, result.mode)):
            return result
    except Exception:
        pass
    return None


def _lsm(reader: HostReader, name: str, advertised: bool | None, native: bool) -> LSMEvidence:
    unknown = LSMState.NOT_ADVERTISED if advertised is False else LSMState.UNKNOWN
    scope = "docker-default profile" if name == "apparmor" else "global SELinux mode only"
    if not native:
        return LSMEvidence(name, unknown, advertised, scope, State.PENDING)
    active = _text(reader, "lsm")
    enabled = _text(reader, "apparmor_enabled" if name == "apparmor" else "selinux_enforce")
    active_names = active.value.strip().split(",") if active.state is State.OBSERVED and active.value else None
    if active_names is not None and (len(active_names) != len(set(active_names))
            or any(re.fullmatch(r"[a-z0-9_]+", value) is None for value in active_names)):
        active_names = None
    flag = enabled.value.strip() if enabled.state is State.OBSERVED and enabled.value else None
    if active_names is not None and name not in active_names:
        # Current boot lacks this active LSM, not proof of kernel build options.
        state = LSMState.UNKNOWN if advertised else LSMState.UNSUPPORTED
        return LSMEvidence(name, state, advertised, scope, State.UNKNOWN)
    if flag == ("N" if name == "apparmor" else "0"):
        return LSMEvidence(name, LSMState.NON_ENFORCING, advertised, scope, State.MISSING)
    if active_names is None or flag != ("Y" if name == "apparmor" else "1"):
        return LSMEvidence(name, LSMState.UNKNOWN, advertised, scope, State.UNKNOWN)
    if name == "selinux":
        policy = _metadata(reader, "selinux_policy")
        state = LSMState.ENFORCING if policy and stat.S_ISREG(policy.mode) else LSMState.UNKNOWN
        return LSMEvidence(name, state, advertised, scope, State.PENDING)
    profiles = _text(reader, "apparmor_profiles")
    if profiles.state is not State.OBSERVED or profiles.value is None:
        return LSMEvidence(name, LSMState.UNKNOWN, advertised, scope, State.UNKNOWN)
    lines = profiles.value.splitlines()
    if lines.count("docker-default (enforce)") == 1 and not any(
            line.startswith("docker-default ") and line != "docker-default (enforce)" for line in lines):
        return LSMEvidence(name, LSMState.ENFORCING, advertised, scope, State.OBSERVED)
    return LSMEvidence(name, LSMState.NON_ENFORCING, advertised, scope, State.MISSING)


def _accounts(reader: HostReader, checks: list[Check]) -> None:
    """Local account/DAC hints only; NSS, ACLs and live service credentials pending."""
    try:
        passwd, group = _text(reader, "passwd"), _text(reader, "group")
        if passwd.state is not State.OBSERVED or group.state is not State.OBSERVED:
            raise ValueError()
        accounts = {}
        for line in passwd.value.splitlines():
            parts = line.split(":")
            if len(parts) != 7 or parts[0] in accounts:
                raise ValueError()
            accounts[parts[0]] = (int(parts[2]), int(parts[3]))
            if min(accounts[parts[0]]) < 0:
                raise ValueError()
        groups = {}
        for line in group.value.splitlines():
            parts = line.split(":")
            if len(parts) != 4 or parts[0] in groups:
                raise ValueError()
            groups[parts[0]] = (int(parts[2]), set(parts[3].split(",")))
        ids = [accounts[name][0] for name in SERVICE_NAMES]
        safe = len(set(ids)) == 4 and all(uid not in {0, 10001} for uid in ids)
        checks.append(Check("DISTINCT_SERVICE_IDENTITIES", State.OBSERVED if safe else State.MISSING))
        for key, account in (("api_storage", "sheetsafe-api"), ("runner_storage", "sheetsafe-runner")):
            facts = _metadata(reader, key)
            safe_dir = facts and stat.S_ISDIR(facts.mode) and facts.uid == accounts[account][0] and stat.S_IMODE(facts.mode) == 0o700
            checks.append(Check(key.upper() + "_OWNER_MODE", State.OBSERVED if safe_dir else State.UNKNOWN))
        checks.append(Check("RUNNER_PROBE_SERVICE_UID", State.OBSERVED if reader.uid() == accounts["sheetsafe-runner"][0] else State.MISSING))
        socket = _metadata(reader, "socket")
        if socket is None:
            raise ValueError()
        def can_write(name):
            uid, primary = accounts[name]
            memberships = {primary} | {gid for gid, users in groups.values() if name in users}
            return uid == 0 or bool(socket.mode & (0o200 if uid == socket.uid else 0o020 if socket.gid in memberships else 0o002))
        forbidden = ("sheetsafe-api", "sheetsafe-ui", "sheetsafe-validator")
        privileged_membership = any(accounts[name][1] == 0 or any(
            name in groups.get(group_name, (0, set()))[1] for group_name in ("root", "docker", "sudo", "wheel")) for name in forbidden)
        boundary = (stat.S_ISSOCK(socket.mode) and socket.uid == 0 and not socket.mode & 0o007
            and not privileged_membership and not any(can_write(name) for name in forbidden)
            and can_write("sheetsafe-runner"))
        checks.append(Check("DOCKER_SOCKET_LOCAL_DAC", State.OBSERVED if boundary else State.MISSING))
    except Exception:
        checks.append(Check("SERVICE_PERMISSION_EVIDENCE", State.UNKNOWN))


def assess_host(reader: HostReader, engine_reader: EngineReader) -> HostReport:
    capture = _CaptureInfo(engine_reader)
    preflight = run_preflight(capture)  # Existing image/seccomp/LSM gates unchanged.
    try:
        system, architecture = reader.system(), reader.architecture()
    except Exception:
        system, architecture = "Unknown", "unknown"
    system = system if system in {"Linux", "Windows", "Darwin"} else "Unknown"
    architecture = architecture if architecture in {"x86_64", "amd64", "AMD64", "aarch64", "arm64"} else "unknown"
    native = system == "Linux"
    checks = [Check("NATIVE_LINUX_HOST", State.OBSERVED if native else State.PENDING)]
    kernel, matches = None, None
    daemon_kernel = capture.raw_info.get("KernelVersion") if type(capture.raw_info) is dict else None
    if type(daemon_kernel) is not str or re.fullmatch(r"[0-9][A-Za-z0-9._+-]{1,127}", daemon_kernel) is None:
        daemon_kernel = None
    if native:
        checks.append(Check("HOST_ARCHITECTURE", State.OBSERVED if architecture in {"x86_64", "amd64"} else State.UNSUPPORTED))
        release = _text(reader, "kernel")
        if release.value and re.fullmatch(r"[0-9][A-Za-z0-9._+-]{1,127}\s*", release.value):
            kernel = release.value.strip()
        checks.append(Check("KERNEL_IDENTIFICATION", State.OBSERVED if kernel else State.UNKNOWN))
        matches = kernel == daemon_kernel if kernel and type(daemon_kernel) is str else None
        checks.append(Check("DAEMON_KERNEL_STRING_MATCH", State.OBSERVED if matches else State.UNKNOWN))
        if kernel and any(marker in kernel.lower() for marker in ("microsoft", "wsl")):
            checks.append(Check("NATIVE_DEPLOYMENT_HOST", State.PENDING))
        controllers = _text(reader, "controllers")
        names = set(controllers.value.split()) if controllers.state is State.OBSERVED and controllers.value is not None else None
        checks.append(Check("CGROUP_V2_INTERFACE", controllers.state))
        for name in ("cpu", "memory", "pids"):
            checks.append(Check(name.upper() + "_CONTROLLER", State.UNKNOWN if names is None else State.OBSERVED if name in names else State.MISSING))
        for name in NAMESPACES:
            try:
                state = State.OBSERVED if reader.namespace(name) is True else State.MISSING
            except Exception:
                state = State.UNKNOWN
            checks.append(Check(name.upper() + "_NAMESPACE_INTERFACE", state))
        for name in ("cpu_accounting", "memory_events", "pid_accounting"):
            value = _text(reader, name)
            checks.append(Check(name.upper() + "_INTERFACE", value.state if value.value else State.UNKNOWN))
        swap = _text(reader, "swaps")
        checks.append(Check("HOST_SWAP_INVENTORY", swap.state))
        if swap.value and len(swap.value.splitlines()) > 1:
            checks.append(Check("ACTIVE_SWAP_PRIVACY_REVIEW", State.PENDING))
        swap_limit = _text(reader, "swap_limit")
        checks.append(Check("SWAP_LIMIT_INTERFACE", State.OBSERVED if swap_limit.value and re.fullmatch(r"(?:max|[0-9]+)\s*", swap_limit.value) else State.PENDING))
        kill = _metadata(reader, "cgroup_kill")
        checks.append(Check("CGROUP_KILL_INTERFACE", State.OBSERVED if kill and stat.S_ISREG(kill.mode) else State.PENDING))
        try:
            pidfd = reader.pidfd_api() is True
        except Exception:
            pidfd = False
        checks.append(Check("PIDFD_PYTHON_API", State.OBSERVED if pidfd else State.UNKNOWN))
        _accounts(reader, checks)
    engine = preflight.engine
    lsms = tuple(_lsm(reader, name, None if engine is None else getattr(engine, name + "_advertised"), native) for name in ("apparmor", "selinux"))
    checks.extend(Check(name, State.PENDING) for name in (
        "HOST_DAEMON_COLOCATION_REVIEW", "CGROUP_DELEGATION_AND_SWAP_ENFORCEMENT",
        "SERVICE_ACL_CAPABILITY_AND_LIVE_CREDENTIAL_REVIEW", "STORAGE_ANCESTORS_ENCRYPTION_AND_MOUNTS",
        "EFFECTIVE_CONTAINER_LSM_SECCOMP_AND_NAMESPACES", "WATCHDOG_CANCELLATION_AND_CPU_BUDGET",
        "DURABLE_CLEANUP_AND_ORPHAN_RECOVERY", "STOPPED_INPUT_AND_PRESTOP_COLLECTION",
    ))
    return HostReport(system, architecture, kernel, daemon_kernel, matches, tuple(checks), lsms, preflight)


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only host evidence; never execution readiness.")
    parser.add_argument("--context", choices=[item.value for item in LocalContext], default="default")
    args = parser.parse_args()
    report = assess_host(LocalHostReader(), DockerReadOnlyClient(LocalContext(args.context)))
    print(json.dumps(asdict(report), indent=2))
    # Evidence collection completion is not success/readiness; all runtime gates pending.
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
