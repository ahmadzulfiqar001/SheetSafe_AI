"""Operator-only, fixed-fixture native Linux Docker smoke adapter.

Accepts ONLY the reviewed 'smoke-v1' fixture. No arbitrary Python, real uploads,
inference keys, API-triggered execution, or result publication.
Defaults to read-only/dry-run mode. Actual native container execution requires
explicit operator approval flags on a verified Linux host.

IMPORTANT SECURITY BOUNDARIES:
- This is an operator diagnostic tool, NOT an execution authorization for production.
- execution_enabled remains False; production_authorized remains False.
- require_execution_ready() in runner.policy is preserved and not bypassed.
- No Docker socket access is provided to API, UI, or validator services.
- Container configuration preserves UID/GID 10001, network-none, read-only root,
  dropped capabilities (ALL), no-new-privileges, 1 GiB RAM (0 swap), 32 PIDs,
  10s cumulative CPU limit, and 20s wall deadline.
- Pre-execution inspect metadata passes through an explicit fail-closed
  normalization boundary before verify_configuration().
- Supervised by an independent monotonic watchdog; cleanup absence is verified
  against both container ID and container name. Any cleanup ambiguity permanently
  blocks admissions in memory and in the durable state ledger across restarts.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from typing import IO, Protocol

from runner.docker_backend import (
    API_TIMEOUT_SECONDS,
    LOCAL_IMAGE_ID,
    LOCAL_REVIEW_TAG,
    ContainerJobSpec,
    ContainerNotFound,
    CreateRejected,
    FailureCode,
    RunnerLifecycleError,
    _owned_id,
    _same,
    _valid_id,
    verify_configuration,
)
from runner.engine_metadata import (
    HOST_DEFAULTS,
    LOCAL_CONFIG_DIGEST,
    MASKED_PATHS,
    READONLY_PATHS,
    MetadataError,
    _review_fields,
    environment,
    exact,
    object_value,
    require,
    string,
)
from runner.policy import (
    FixtureRequest,
    RunnerPolicyError,
    SandboxPolicy,
    policy_for,
)
from runner.preflight import (
    DockerReadOnlyClient,
    EngineReader,
    LocalContext,
    PreflightReport,
    run_preflight,
)


FIXED_SMOKE_FIXTURE_ID = "smoke-v1"
MAX_LOG_BYTES_PER_STREAM = SandboxPolicy().log_bytes_per_stream  # 64 KiB budget
MAX_CONTROL_OUTPUT_BYTES = 256 * 1024  # 256 KiB cap for inspect/create CLI output
DEFAULT_WATCHDOG_POLL_INTERVAL_SECONDS = 0.05
DEFAULT_KILL_GRACE_SECONDS = float(SandboxPolicy().kill_grace_seconds)
DEFAULT_CANCELLATION_SECONDS = float(SandboxPolicy().cancellation_seconds)
DEFAULT_WALL_DEADLINE_SECONDS = float(SandboxPolicy().wall_seconds)
DEFAULT_CPU_LIMIT_SECONDS = float(SandboxPolicy().cpu_seconds)
DEFAULT_STATE_FILE_PATH = Path("var/smoke_adapter/state.json")


class SmokeFailureCode(StrEnum):
    UNSUPPORTED_FIXTURE = "UNSUPPORTED_FIXTURE"
    ADMISSIONS_BLOCKED = "ADMISSIONS_BLOCKED"
    JOB_ACTIVE = "JOB_ACTIVE"
    PREFLIGHT_FAILED = "PREFLIGHT_FAILED"
    NATIVE_LINUX_REQUIRED = "NATIVE_LINUX_REQUIRED"
    CREATE_FAILED = "CREATE_FAILED"
    INVALID_IDENTITY = "INVALID_IDENTITY"
    DUPLICATE_IDENTITY = "DUPLICATE_IDENTITY"
    INSPECT_FAILED = "INSPECT_FAILED"
    POLICY_MISMATCH = "POLICY_MISMATCH"
    START_FAILED = "START_FAILED"
    WATCHDOG_FAILED = "WATCHDOG_FAILED"
    TIMED_OUT = "TIMED_OUT"
    CANCELLED = "CANCELLED"
    CPU_LIMIT_EXCEEDED = "CPU_LIMIT_EXCEEDED"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    OOM_KILLED = "OOM_KILLED"
    LOG_RETRIEVAL_FAILED = "LOG_RETRIEVAL_FAILED"
    CLEANUP_UNRESOLVED = "CLEANUP_UNRESOLVED"
    REMOVE_FAILED = "REMOVE_FAILED"


class SmokeLifecycleState(StrEnum):
    ADMITTING = "ADMITTING"
    DRY_RUN = "DRY_RUN"
    CREATING = "CREATING"
    CREATED = "CREATED"
    CONFIGURATION_VERIFIED = "CONFIGURATION_VERIFIED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    EXITED = "EXITED"
    CLEANING = "CLEANING"
    ABSENT = "ABSENT"
    UNRESOLVED = "UNRESOLVED"


class SmokeOutcome(StrEnum):
    DRY_RUN_PASSED = "DRY_RUN_PASSED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    CANCELLED = "CANCELLED"


class SmokeAdmissionError(RuntimeError):
    def __init__(self, code: SmokeFailureCode, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        msg = f"Smoke adapter admission rejected: {code.value}"
        if detail:
            msg += f" ({detail})"
        super().__init__(msg)


@dataclass(frozen=True, slots=True)
class SmokeReceipt:
    job_id: str
    container_id: str | None
    fixture_id: str
    state: SmokeLifecycleState
    outcome: SmokeOutcome
    configuration_verified: bool
    started: bool
    exit_code: int | None
    oom_killed: bool
    timed_out: bool
    cancelled: bool
    cpu_limit_exceeded: bool
    wall_duration_seconds: float
    stdout_snippet: str | None
    stderr_snippet: str | None
    logs_truncated: bool
    cleanup_confirmed: bool
    failure: SmokeFailureCode | None
    cleanup_failure: SmokeFailureCode | None
    dry_run: bool
    execution_enabled: bool = field(default=False, init=False)
    production_authorized: bool = field(default=False, init=False)
    unverified_controls: tuple[str, ...] = field(
        default=SandboxPolicy().unverified_controls, init=False
    )

    def to_dict(self) -> dict[str, object]:
        return {
            "job_id": self.job_id,
            "container_id": self.container_id,
            "fixture_id": self.fixture_id,
            "state": self.state.value,
            "outcome": self.outcome.value,
            "configuration_verified": self.configuration_verified,
            "started": self.started,
            "exit_code": self.exit_code,
            "oom_killed": self.oom_killed,
            "timed_out": self.timed_out,
            "cancelled": self.cancelled,
            "cpu_limit_exceeded": self.cpu_limit_exceeded,
            "wall_duration_seconds": self.wall_duration_seconds,
            "stdout_snippet": self.stdout_snippet,
            "stderr_snippet": self.stderr_snippet,
            "logs_truncated": self.logs_truncated,
            "cleanup_confirmed": self.cleanup_confirmed,
            "failure": self.failure.value if self.failure else None,
            "cleanup_failure": (
                self.cleanup_failure.value if self.cleanup_failure else None
            ),
            "dry_run": self.dry_run,
            "execution_enabled": self.execution_enabled,
            "production_authorized": self.production_authorized,
            "unverified_controls": list(self.unverified_controls),
        }


class DockerSmokeTransport(Protocol):
    """Protocol for container lifecycle execution and inspection in smoke tests."""

    def create(self, spec: ContainerJobSpec, *, timeout: float) -> str: ...
    def inspect(self, reference: str, *, timeout: float) -> dict: ...
    def start(self, container_id: str, *, timeout: float) -> None: ...
    def kill(self, container_id: str, *, signal: str, timeout: float) -> None: ...
    def logs(
        self,
        container_id: str,
        *,
        stdout: bool,
        stderr: bool,
        max_bytes: int,
        timeout: float,
    ) -> bytes: ...
    def remove(self, container_id: str, *, force: bool, timeout: float) -> None: ...


class DryRunSmokeTransport:
    """Safe read-only transport used by default; never contacts Docker or starts processes."""

    def create(self, spec: ContainerJobSpec, *, timeout: float) -> str:
        raise SmokeAdmissionError(
            SmokeFailureCode.ADMISSIONS_BLOCKED,
            "Dry-run transport does not create containers.",
        )

    def inspect(self, reference: str, *, timeout: float) -> dict:
        raise SmokeAdmissionError(
            SmokeFailureCode.ADMISSIONS_BLOCKED,
            "Dry-run transport does not inspect containers.",
        )

    def start(self, container_id: str, *, timeout: float) -> None:
        raise SmokeAdmissionError(
            SmokeFailureCode.ADMISSIONS_BLOCKED,
            "Dry-run transport does not start containers.",
        )

    def kill(self, container_id: str, *, signal: str, timeout: float) -> None:
        raise SmokeAdmissionError(
            SmokeFailureCode.ADMISSIONS_BLOCKED,
            "Dry-run transport does not kill containers.",
        )

    def logs(
        self,
        container_id: str,
        *,
        stdout: bool,
        stderr: bool,
        max_bytes: int,
        timeout: float,
    ) -> bytes:
        raise SmokeAdmissionError(
            SmokeFailureCode.ADMISSIONS_BLOCKED,
            "Dry-run transport does not read container logs.",
        )

    def remove(self, container_id: str, *, force: bool, timeout: float) -> None:
        raise SmokeAdmissionError(
            SmokeFailureCode.ADMISSIONS_BLOCKED,
            "Dry-run transport does not remove containers.",
        )


def _validate_timeout(timeout: float) -> float:
    if (
        type(timeout) not in (int, float)
        or not math.isfinite(timeout)
        or timeout <= 0.0
    ):
        raise TimeoutError("Operation timeout must be a finite positive number.")
    return float(timeout)


def _is_explicit_not_found(stderr_text: str) -> bool:
    lowered = stderr_text.lower()
    return (
        "no such container" in lowered
        or "no such object" in lowered
        or ("container" in lowered and "not found" in lowered)
    )


def _is_explicit_create_rejected(stderr_text: str) -> bool:
    lowered = stderr_text.lower()
    return (
        "no such image" in lowered
        or "invalid reference format" in lowered
        or "unknown flag" in lowered
        or "unable to find image" in lowered
    )


class _BoundedStreamDrain:
    """Drains a pipe stream in a background thread, retaining at most max_bytes."""

    def __init__(self, stream: IO[bytes] | None, max_bytes: int) -> None:
        self._stream = stream
        self._max_bytes = max_bytes
        self._chunks: list[bytes] = []
        self._retained = 0
        self.total_bytes = 0
        self.overflowed = False
        self.error: BaseException | None = None
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        if self._stream is None:
            return
        try:
            while True:
                chunk = self._stream.read(4096)
                if not chunk:
                    break
                self.total_bytes += len(chunk)
                remaining = self._max_bytes - self._retained
                if remaining > 0:
                    kept = chunk[:remaining]
                    self._chunks.append(kept)
                    self._retained += len(kept)
                if len(chunk) > remaining:
                    self.overflowed = True
        except BaseException as exc:
            self.error = exc
        finally:
            try:
                self._stream.close()
            except Exception:
                pass

    def collect(self, timeout: float) -> bytes:
        self._thread.join(timeout=max(0.01, timeout))
        if self._thread.is_alive():
            raise TimeoutError("Timed out draining subprocess output stream.")
        if self.error is not None:
            raise RuntimeError(f"Stream drain failed: {self.error}") from self.error
        return b"".join(self._chunks)


class _AttachedContainerSession:
    """Supervises an attached `docker start --attach` process for bounded stdio capture.

    Because SandboxPolicy sets `daemon_log_driver = 'none'`, Docker does not persist
    container logs on the host filesystem (`docker logs` is unsupported). Instead,
    diagnostic stdout/stderr streams are captured directly from the attached start
    process with strict per-stream memory caps (64 KiB + 1 byte).
    """

    def __init__(self, process: subprocess.Popen[bytes], max_stream_bytes: int) -> None:
        self.process = process
        self.stdout_drain = _BoundedStreamDrain(process.stdout, max_stream_bytes)
        self.stderr_drain = _BoundedStreamDrain(process.stderr, max_stream_bytes)
        self._closed = False

    def terminate_process(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if self.process.poll() is None:
                self.process.kill()
        except Exception:
            pass
        try:
            self.process.wait(timeout=1.0)
        except Exception:
            pass

    def collect_stream(self, *, stdout: bool, max_bytes: int, timeout: float) -> bytes:
        budget = _validate_timeout(timeout)
        deadline = time.monotonic() + budget
        try:
            self.process.wait(timeout=budget)
        except subprocess.TimeoutExpired as exc:
            self.terminate_process()
            raise TimeoutError("Attached container stream did not close before timeout.") from exc

        rem_stdout = max(0.01, deadline - time.monotonic())
        out_bytes = self.stdout_drain.collect(timeout=rem_stdout)
        rem_stderr = max(0.01, deadline - time.monotonic())
        err_bytes = self.stderr_drain.collect(timeout=rem_stderr)

        # If docker start --attach itself failed before attaching (e.g. daemon error),
        # surface the failure if the stream is empty and stderr reported a daemon error.
        if (
            self.process.returncode not in (0, None)
            and not out_bytes
            and b"Error response from daemon" in err_bytes
        ):
            raise RuntimeError(
                f"Attached start failed: {err_bytes.decode('utf-8', errors='replace').strip()}"
            )

        data = out_bytes if stdout else err_bytes
        return data[:max_bytes]


class NativeCliSmokeTransport:
    """Bounded native Linux Docker CLI transport.

    Only active when running on native Linux with explicit operator approval.
    Commands are strictly mapped and bounded; no arbitrary user flags or shell execution.
    """

    def __init__(self, context: str = LocalContext.LINUX_DEFAULT.value) -> None:
        if sys.platform != "linux":
            raise SmokeAdmissionError(
                SmokeFailureCode.NATIVE_LINUX_REQUIRED,
                "Native CLI smoke transport requires a native Linux host.",
            )
        if type(context) is not str or not context:
            raise SmokeAdmissionError(
                SmokeFailureCode.PREFLIGHT_FAILED,
                "Docker context must be a non-empty string.",
            )
        self._context = context
        executable = shutil.which("docker")
        if executable is None:
            raise SmokeAdmissionError(
                SmokeFailureCode.PREFLIGHT_FAILED,
                "Docker CLI executable was not found on PATH.",
            )
        self._executable = executable
        self._sessions: dict[str, _AttachedContainerSession] = {}
        self._lock = threading.Lock()

    def _exec(
        self,
        arguments: list[str],
        *,
        timeout: float,
        max_bytes: int = MAX_CONTROL_OUTPUT_BYTES,
    ) -> bytes:
        budget = _validate_timeout(timeout)
        cmd = [self._executable, "--context", self._context, *arguments]
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except OSError as exc:
            raise RuntimeError(f"Docker command execution failed: {exc}") from exc

        stdout_drain = _BoundedStreamDrain(proc.stdout, max_bytes + 1)
        stderr_drain = _BoundedStreamDrain(proc.stderr, max_bytes + 1)
        deadline = time.monotonic() + budget

        try:
            proc.wait(timeout=budget)
        except subprocess.TimeoutExpired as exc:
            try:
                proc.kill()
            except Exception:
                pass
            try:
                proc.wait(timeout=1.0)
            except Exception:
                pass
            raise TimeoutError(f"Docker command timed out after {budget}s") from exc

        out_bytes = stdout_drain.collect(timeout=max(0.05, deadline - time.monotonic()))
        err_bytes = stderr_drain.collect(timeout=max(0.05, deadline - time.monotonic()))

        if stdout_drain.overflowed or len(out_bytes) > max_bytes:
            raise RuntimeError("Docker CLI stdout exceeded bounded control output limit.")
        if stderr_drain.overflowed or len(err_bytes) > max_bytes:
            raise RuntimeError("Docker CLI stderr exceeded bounded control output limit.")

        if proc.returncode != 0:
            err_msg = err_bytes.decode("utf-8", errors="replace").strip()
            op = arguments[0] if arguments else ""
            if op in {"inspect", "kill", "rm"} and _is_explicit_not_found(err_msg):
                raise ContainerNotFound(err_msg)
            if op == "create" and _is_explicit_create_rejected(err_msg):
                raise CreateRejected(err_msg)
            raise RuntimeError(f"Docker CLI exited with {proc.returncode}: {err_msg}")
        return out_bytes

    @staticmethod
    def build_create_args(spec: ContainerJobSpec) -> list[str]:
        """Construct the exact bounded `docker create` argument vector for spec."""
        if type(spec) is not ContainerJobSpec:
            raise TypeError("Expected ContainerJobSpec instance.")
        policy = SandboxPolicy()
        args = [
            "create",
            "--name",
            spec.name,
            "--platform",
            spec.platform,
            "--user",
            f"{policy.uid}:{policy.gid}",
            "--workdir",
            policy.workdir,
            "--stop-signal",
            "SIGTERM",
            "--no-healthcheck",
            "--network",
            policy.network_mode,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges=true",
            "--cpu-period",
            "100000",
            "--cpu-quota",
            str(policy.cpus * 100_000),
            "--memory",
            f"{policy.memory_bytes}b",
            "--memory-swap",
            f"{policy.memory_plus_swap_bytes}b",
            "--pids-limit",
            str(policy.pids_limit),
            "--ipc",
            "private",
            "--cgroupns",
            "private",
            "--runtime",
            "runc",
            "--restart",
            "no",
            "--log-driver",
            policy.daemon_log_driver,
        ]
        for mount in policy.tmpfs:
            mount_spec = ",".join(
                (
                    f"{mount.path}:rw",
                    *mount.options,
                    f"size={mount.byte_limit}",
                    f"uid={mount.uid}",
                    f"gid={mount.gid}",
                    f"mode={mount.mode:o}",
                )
            )
            args.extend(["--tmpfs", mount_spec])
        for name, value in policy.environment:
            args.extend(["--env", f"{name}={value}"])
        for k, v in spec.labels.items():
            args.extend(["--label", f"{k}={v}"])

        args.append(spec.image_id)
        args.append(spec.fixture_id)
        return args

    def create(self, spec: ContainerJobSpec, *, timeout: float) -> str:
        args = self.build_create_args(spec)
        out = self._exec(args, timeout=timeout).decode("utf-8", errors="replace").strip()
        lines = [line.strip() for line in out.splitlines() if line.strip()]
        if len(lines) != 1 or not _valid_id(lines[0]):
            raise RuntimeError("Docker create returned malformed container ID output.")
        return lines[0]

    def inspect(self, reference: str, *, timeout: float) -> dict:
        out = self._exec(["inspect", "--type", "container", reference], timeout=timeout)
        try:
            parsed = json.loads(out.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise RuntimeError("Malformed JSON returned by docker inspect.") from exc
        if not isinstance(parsed, list) or len(parsed) != 1 or type(parsed[0]) is not dict:
            raise RuntimeError("Docker inspect did not return a single container object.")
        return parsed[0]

    def start(self, container_id: str, *, timeout: float) -> None:
        budget = _validate_timeout(timeout)
        if not _valid_id(container_id):
            raise ValueError("Invalid container ID for start.")
        cmd = [
            self._executable,
            "--context",
            self._context,
            "start",
            "--attach",
            container_id,
        ]
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except OSError as exc:
            raise RuntimeError(f"Failed to launch attached docker start: {exc}") from exc

        session = _AttachedContainerSession(proc, MAX_LOG_BYTES_PER_STREAM + 1)
        # Brief check for immediate invocation failure (e.g. no such container)
        try:
            proc.wait(timeout=min(0.02, budget))
        except subprocess.TimeoutExpired:
            pass
        else:
            if proc.returncode not in (0, None):
                err_bytes = session.stderr_drain.collect(timeout=0.2)
                err_msg = err_bytes.decode("utf-8", errors="replace").strip()
                if (
                    "Error response from daemon" in err_msg
                    or "No such container" in err_msg
                    or "cannot start" in err_msg.lower()
                ):
                    session.terminate_process()
                    if _is_explicit_not_found(err_msg):
                        raise ContainerNotFound(err_msg)
                    raise RuntimeError(f"Docker start failed ({proc.returncode}): {err_msg}")

        with self._lock:
            self._sessions[container_id] = session

    def kill(self, container_id: str, *, signal: str, timeout: float) -> None:
        budget = _validate_timeout(timeout)
        try:
            self._exec(["kill", f"--signal={signal}", container_id], timeout=budget)
        except ContainerNotFound:
            pass
        except RuntimeError as exc:
            if "is not running" not in str(exc).lower():
                raise
        finally:
            with self._lock:
                session = self._sessions.get(container_id)
            if session is not None:
                session.terminate_process()

    def logs(
        self,
        container_id: str,
        *,
        stdout: bool,
        stderr: bool,
        max_bytes: int,
        timeout: float,
    ) -> bytes:
        if stdout == stderr:
            raise ValueError("Specify exactly one of stdout or stderr.")
        with self._lock:
            session = self._sessions.get(container_id)
        if session is None:
            raise RuntimeError(
                "No attached diagnostic stream session found for container; "
                "daemon log-driver is 'none'."
            )
        return session.collect_stream(stdout=stdout, max_bytes=max_bytes, timeout=timeout)

    def remove(self, container_id: str, *, force: bool, timeout: float) -> None:
        budget = _validate_timeout(timeout)
        with self._lock:
            session = self._sessions.pop(container_id, None)
        if session is not None:
            session.terminate_process()
        args = ["rm"]
        if force:
            args.append("-f")
        args.append(container_id)
        self._exec(args, timeout=budget)


def normalize_created_inspect(
    raw: object, spec: ContainerJobSpec, container_id: str
) -> dict:
    """Explicitly validated normalization boundary for pre-start container inspect metadata.

    Accepts either:
    1. The exact internal projection expected by verify_configuration (with zero extra/unreviewed fields), or
    2. Native Docker Engine inspect JSON, validated fail-closed against audited defaults
       (HOST_DEFAULTS, MASKED_PATHS, READONLY_PATHS, environment, network none, etc.).

    Never weakens verify_configuration or ignores unknown/unsafe metadata fields.
    """
    if not _valid_id(container_id) or _owned_id(raw, spec) != container_id:
        raise RunnerLifecycleError(FailureCode.INVALID_IDENTITY)

    raw_dict = object_value(raw)
    required_top = {
        "Id",
        "Name",
        "Image",
        "Config",
        "HostConfig",
        "State",
        "Mounts",
        "NetworkSettings",
        "AppArmorProfile",
    }
    optional_top = {
        "Created",
        "Path",
        "Args",
        "Platform",
        "RestartCount",
        "Driver",
        "ResolvConfPath",
        "HostnamePath",
        "HostsPath",
        "LogPath",
        "ProcessLabel",
        "MountLabel",
        "ExecIDs",
        "GraphDriver",
    }

    if not (
        required_top <= raw_dict.keys()
        and not (raw_dict.keys() - required_top - optional_top)
    ):
        raise RunnerLifecycleError(FailureCode.POLICY_MISMATCH)

    raw_host_obj = raw_dict.get("HostConfig")
    raw_state_obj = raw_dict.get("State")
    raw_config_obj = raw_dict.get("Config")
    is_internal_projection = (
        set(raw_dict.keys()) == required_top
        and type(raw_host_obj) is dict
        and "MaskedPaths" not in raw_host_obj
        and "ReadonlyPaths" not in raw_host_obj
        and type(raw_state_obj) is dict
        and set(raw_state_obj.keys())
        == {"Status", "Running", "Paused", "Restarting", "Dead", "Pid"}
        and type(raw_config_obj) is dict
        and "Hostname" not in raw_config_obj
    )
    if is_internal_projection:
        verify_configuration(raw_dict, spec, container_id)
        return raw_dict

    try:
        policy = SandboxPolicy()
        require(
            exact(raw_dict["Name"], "/" + spec.name) and type(raw_dict["Image"]) is str
        )
        require(raw_dict["Image"] in {spec.image_id, LOCAL_CONFIG_DIGEST})

        for name in (
            "Created",
            "Driver",
            "ResolvConfPath",
            "HostnamePath",
            "HostsPath",
        ):
            if name in raw_dict:
                string(raw_dict[name])

        for name, expected_val in {
            "Path": policy.entrypoint[0],
            "Args": [*policy.entrypoint[1:], "smoke-v1"],
            "Platform": "linux",
            "RestartCount": 0,
            "LogPath": "",
            "ProcessLabel": "",
            "MountLabel": "",
            "ExecIDs": None,
        }.items():
            if name in raw_dict:
                require(exact(raw_dict[name], expected_val))

        if "GraphDriver" in raw_dict:
            require(
                exact(raw_dict["GraphDriver"], {"Name": "overlay2", "Data": None})
            )

        expected_config = spec.create_body()
        expected_host = expected_config.pop("HostConfig")

        config = dict(object_value(raw_dict["Config"]))
        require(environment(config.get("Env")) == tuple(sorted(policy.environment)))
        config["Env"] = expected_config["Env"]
        config = _review_fields(
            config,
            expected_config,
            {
                "Hostname": container_id[:12],
                "Domainname": "",
                "AttachStdin": False,
                "AttachStdout": False,
                "AttachStderr": False,
                "OnBuild": None,
                "ArgsEscaped": True,
            },
        )

        host = dict(object_value(raw_dict["HostConfig"]))
        if exact(host.get("SecurityOpt"), ["no-new-privileges"]):
            host["SecurityOpt"] = ["no-new-privileges=true"]
        masked, readonly = host.get("MaskedPaths"), host.get("ReadonlyPaths")
        for paths in (masked, readonly):
            require(type(paths) is list and all(type(path) is str for path in paths))
            require(len(paths) <= 4096 and len(paths) == len(set(paths)))
        require(
            set(MASKED_PATHS) <= set(masked) and set(READONLY_PATHS) == set(readonly)
        )
        require(
            all(
                path in MASKED_PATHS
                or re.fullmatch(
                    r"/sys/devices/system/cpu/cpu[0-9]+/thermal_throttle", path
                )
                for path in masked
            )
        )
        host["MaskedPaths"], host["ReadonlyPaths"] = MASKED_PATHS, READONLY_PATHS
        required_host = {
            **expected_host,
            "MaskedPaths": MASKED_PATHS,
            "ReadonlyPaths": READONLY_PATHS,
        }
        host = _review_fields(host, required_host, HOST_DEFAULTS)
        host.pop("MaskedPaths")
        host.pop("ReadonlyPaths")

        state = _review_fields(
            object_value(raw_dict["State"]),
            {
                "Status": "created",
                "Running": False,
                "Paused": False,
                "Restarting": False,
                "Dead": False,
                "Pid": 0,
            },
            {
                "OOMKilled": False,
                "ExitCode": 0,
                "Error": "",
                "StartedAt": "0001-01-01T00:00:00Z",
                "FinishedAt": "0001-01-01T00:00:00Z",
            },
        )

        network = object_value(raw_dict["NetworkSettings"])
        require({"Ports", "Networks"} <= network.keys())
        require(
            not network.keys()
            - {
                "Ports",
                "Networks",
                "SandboxID",
                "SandboxKey",
                "Bridge",
                "HairpinMode",
                "LinkLocalIPv6Address",
                "LinkLocalIPv6PrefixLen",
            }
        )
        require(network["Ports"] is None or exact(network["Ports"], {}))
        endpoints = object_value(network["Networks"])
        require(set(endpoints) == {"none"})
        endpoint = object_value(endpoints["none"])
        for name in ("NetworkID", "EndpointID"):
            if name in endpoint:
                require(
                    type(endpoint[name]) is str
                    and re.fullmatch(r"(?:[0-9a-f]{64})?", endpoint[name]) is not None
                )
        _review_fields(
            {
                key: value
                for key, value in endpoint.items()
                if key not in {"NetworkID", "EndpointID"}
            },
            {},
            {
                "IPAMConfig": None,
                "Links": None,
                "Aliases": None,
                "DNSNames": None,
                "DriverOpts": None,
                "Gateway": "",
                "IPAddress": "",
                "IPPrefixLen": 0,
                "IPv6Gateway": "",
                "GlobalIPv6Address": "",
                "GlobalIPv6PrefixLen": 0,
                "MacAddress": "",
                "GwPriority": 0,
            },
        )
        for name in ("SandboxID", "SandboxKey"):
            if name in network:
                require(type(network[name]) is str and len(network[name]) <= 256)
        for name, expected_value in {
            "Bridge": "",
            "HairpinMode": False,
            "LinkLocalIPv6Address": "",
            "LinkLocalIPv6PrefixLen": 0,
        }.items():
            if name in network:
                require(exact(network[name], expected_value))

        mounts = raw_dict["Mounts"]
        if mounts is None:
            mounts = []
        projection = {
            "Id": container_id,
            "Name": raw_dict["Name"],
            "Image": spec.image_id,
            "Config": config,
            "HostConfig": host,
            "State": state,
            "Mounts": mounts,
            "NetworkSettings": {"Ports": {}, "Networks": {"none": {}}},
            "AppArmorProfile": raw_dict["AppArmorProfile"],
        }
    except MetadataError as exc:
        raise RunnerLifecycleError(FailureCode.POLICY_MISMATCH) from exc

    verify_configuration(projection, spec, container_id)
    return projection


def validate_runtime_inspect(
    raw: object, spec: ContainerJobSpec, container_id: str
) -> tuple[bool, int | None, bool, int]:
    """Validate runtime container inspect payload and return (is_running, exit_code, oom_killed, total_cpu_ns)."""
    if not _valid_id(container_id) or _owned_id(raw, spec) != container_id:
        raise RunnerLifecycleError(FailureCode.INVALID_IDENTITY)
    if type(raw) is not dict:
        raise SmokeAdmissionError(
            SmokeFailureCode.INSPECT_FAILED, "Inspect payload is not a dict."
        )
    state_dict = raw.get("State")
    if type(state_dict) is not dict:
        raise SmokeAdmissionError(
            SmokeFailureCode.INSPECT_FAILED, "Inspect State is missing or not a dict."
        )
    is_running = state_dict.get("Running")
    if type(is_running) is not bool:
        raise SmokeAdmissionError(
            SmokeFailureCode.INSPECT_FAILED, "Inspect State.Running is not a bool."
        )
    status = state_dict.get("Status")
    if type(status) is not str or status not in {
        "created",
        "running",
        "exited",
        "dead",
    }:
        raise SmokeAdmissionError(
            SmokeFailureCode.INSPECT_FAILED, "Inspect State.Status is invalid."
        )
    for flag_name in ("Paused", "Restarting"):
        if flag_name in state_dict and state_dict[flag_name] is not False:
            raise SmokeAdmissionError(
                SmokeFailureCode.INSPECT_FAILED,
                f"Unexpected container state {flag_name}.",
            )

    exit_code: int | None = None
    oom_killed = False
    if not is_running:
        raw_exit = state_dict.get("ExitCode")
        if type(raw_exit) is not int:
            raise SmokeAdmissionError(
                SmokeFailureCode.INSPECT_FAILED,
                "Exited container missing integer ExitCode.",
            )
        exit_code = raw_exit
        raw_oom = state_dict.get("OOMKilled", False)
        if type(raw_oom) is not bool:
            raise SmokeAdmissionError(
                SmokeFailureCode.INSPECT_FAILED,
                "Inspect State.OOMKilled is not a bool.",
            )
        oom_killed = raw_oom

    total_cpu_ns = 0
    if "CPUStats" in raw and raw["CPUStats"] is not None:
        cpu_stats = raw["CPUStats"]
        if type(cpu_stats) is not dict:
            raise SmokeAdmissionError(
                SmokeFailureCode.INSPECT_FAILED, "Inspect CPUStats is not a dict."
            )
        cpu_usage = cpu_stats.get("cpu_usage")
        if type(cpu_usage) is not dict:
            raise SmokeAdmissionError(
                SmokeFailureCode.INSPECT_FAILED,
                "Inspect CPUStats.cpu_usage is not a dict.",
            )
        raw_total = cpu_usage.get("total_usage", 0)
        if type(raw_total) is not int or raw_total < 0:
            raise SmokeAdmissionError(
                SmokeFailureCode.INSPECT_FAILED,
                "Inspect CPUStats.cpu_usage.total_usage is invalid.",
            )
        total_cpu_ns = raw_total

    return is_running, exit_code, oom_killed, total_cpu_ns


class _DurableSmokeLedger:
    """Persists admission blocking, in-flight intent, and seen container IDs across process restarts."""

    def __init__(self, path: Path | None) -> None:
        self.path = path

    def load(self) -> tuple[bool, set[str]]:
        """Return (blocked, seen_ids). Corrupt or unfinished IN_FLIGHT state fails closed (blocked=True)."""
        if self.path is None or not self.path.exists():
            return False, set()
        try:
            raw_bytes = self.path.read_bytes()
            if len(raw_bytes) > MAX_CONTROL_OUTPUT_BYTES:
                return True, set()
            data = json.loads(raw_bytes.decode("utf-8", errors="strict"))
            if type(data) is not dict or data.get("version") != 1:
                return True, set()
            status = data.get("status")
            blocked = data.get("blocked")
            raw_seen = data.get("seen_container_ids")
            if (
                type(status) is not str
                or status not in {"IDLE", "IN_FLIGHT", "UNRESOLVED"}
                or type(blocked) is not bool
                or type(raw_seen) is not list
                or not all(_valid_id(cid) for cid in raw_seen)
            ):
                return True, set()
            seen = set(raw_seen)
            if blocked or status != "IDLE":
                return True, seen
            return False, seen
        except Exception:
            return True, set()

    def save(
        self,
        *,
        status: str,
        blocked: bool,
        seen_ids: set[str],
        job_id: str | None = None,
        container_name: str | None = None,
        container_id: str | None = None,
        failure_reason: str | None = None,
    ) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "status": status,
            "blocked": blocked,
            "active_job_id": job_id,
            "active_container_name": container_name,
            "active_container_id": container_id,
            "failure_reason": failure_reason,
            "seen_container_ids": sorted(seen_ids),
        }
        encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
        fd, tmp_name = tempfile.mkstemp(
            prefix=".smoke-state-", dir=str(self.path.parent)
        )
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp_name, self.path)
        except BaseException:
            try:
                if os.path.exists(tmp_name):
                    os.unlink(tmp_name)
            except OSError:
                pass
            raise


class SmokeAdapter:
    """Operator-only, single-fixture isolated smoke adapter.

    Accepts ONLY smoke-v1 fixture.
    Enforces fail-closed admission, monotonic watchdog timeout, and verified cleanup.
    Uncertainty in cleanup permanently blocks this adapter instance and its durable
    ledger from further admissions across process restarts.
    """

    def __init__(
        self,
        transport: DockerSmokeTransport | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep_fn: Callable[[float], None] = time.sleep,
        preflight_reader: EngineReader | None = None,
        state_path: Path | str | None = None,
    ) -> None:
        self._transport = (
            transport if transport is not None else DryRunSmokeTransport()
        )
        self._clock = clock
        self._sleep = sleep_fn
        self._preflight_reader = preflight_reader
        resolved_path = Path(state_path) if state_path is not None else None
        self._ledger = _DurableSmokeLedger(resolved_path)
        self._lock = threading.Lock()
        self._active = False
        persisted_blocked, persisted_seen = self._ledger.load()
        self._blocked = persisted_blocked
        self._seen_ids: set[str] = persisted_seen
        self._last_receipt: SmokeReceipt | None = None

    def _sync_from_ledger_locked(self) -> None:
        persisted_blocked, persisted_seen = self._ledger.load()
        if persisted_blocked:
            self._blocked = True
        self._seen_ids.update(persisted_seen)

    @property
    def admissions_blocked(self) -> bool:
        with self._lock:
            self._sync_from_ledger_locked()
            return self._blocked

    @property
    def last_receipt(self) -> SmokeReceipt | None:
        with self._lock:
            return self._last_receipt

    def _absent(self, reference: str) -> bool:
        try:
            self._transport.inspect(reference, timeout=API_TIMEOUT_SECONDS)
        except ContainerNotFound:
            return True
        except Exception:
            return False
        return False

    def _terminate_and_verify_stopped(
        self,
        container_id: str,
        spec: ContainerJobSpec,
    ) -> bool:
        """Issue SIGKILL to container_id and verify it reaches a non-running state within grace window."""
        kill_succeeded = True
        try:
            self._transport.kill(
                container_id, signal="SIGKILL", timeout=API_TIMEOUT_SECONDS
            )
        except Exception:
            kill_succeeded = False

        grace_deadline = self._clock() + DEFAULT_KILL_GRACE_SECONDS
        while True:
            try:
                meta = self._transport.inspect(
                    container_id, timeout=API_TIMEOUT_SECONDS
                )
            except ContainerNotFound:
                return kill_succeeded
            except Exception:
                return False

            try:
                is_running, _, _, _ = validate_runtime_inspect(
                    meta, spec, container_id
                )
            except Exception:
                return False

            if not is_running:
                return kill_succeeded

            if self._clock() >= grace_deadline:
                return False
            self._sleep(DEFAULT_WATCHDOG_POLL_INTERVAL_SECONDS)

    def _cleanup_container(
        self,
        spec: ContainerJobSpec,
        container_id: str | None,
        create_rejected: bool,
    ) -> tuple[bool, SmokeFailureCode | None, str | None]:
        """Perform verified teardown. Absence must be verified on both ID and name."""
        cleanup_confirmed = False
        cleanup_failure: SmokeFailureCode | None = None
        resolved_id = container_id

        try:
            try:
                metadata = self._transport.inspect(
                    spec.name, timeout=API_TIMEOUT_SECONDS
                )
            except ContainerNotFound:
                # An ambiguous create with no valid ID can still materialize later.
                # Absence by name alone must not clear that uncertainty.
                if create_rejected or (
                    resolved_id is not None and self._absent(resolved_id)
                ):
                    cleanup_confirmed = True
                else:
                    cleanup_failure = SmokeFailureCode.CLEANUP_UNRESOLVED
            except Exception:
                cleanup_failure = SmokeFailureCode.CLEANUP_UNRESOLVED
            else:
                try:
                    candidate_id = _owned_id(metadata, spec)
                except RunnerLifecycleError:
                    cleanup_failure = SmokeFailureCode.INVALID_IDENTITY
                    return False, cleanup_failure, resolved_id

                if resolved_id is None:
                    with self._lock:
                        if candidate_id in self._seen_ids:
                            cleanup_failure = SmokeFailureCode.DUPLICATE_IDENTITY
                            return False, cleanup_failure, resolved_id
                        self._seen_ids.add(candidate_id)
                    resolved_id = candidate_id

                if candidate_id != resolved_id:
                    cleanup_failure = SmokeFailureCode.INVALID_IDENTITY
                    return False, cleanup_failure, resolved_id

                try:
                    by_id_meta = self._transport.inspect(
                        candidate_id, timeout=API_TIMEOUT_SECONDS
                    )
                    if _owned_id(by_id_meta, spec) != candidate_id:
                        cleanup_failure = SmokeFailureCode.INVALID_IDENTITY
                        return False, cleanup_failure, resolved_id
                except Exception:
                    cleanup_failure = SmokeFailureCode.INVALID_IDENTITY
                    return False, cleanup_failure, resolved_id

                try:
                    self._transport.remove(
                        candidate_id, force=True, timeout=API_TIMEOUT_SECONDS
                    )
                except Exception:
                    cleanup_failure = SmokeFailureCode.REMOVE_FAILED

                id_absent = self._absent(candidate_id)
                name_absent = self._absent(spec.name)
                cleanup_confirmed = (
                    cleanup_failure is None and id_absent and name_absent
                )
                if not cleanup_confirmed:
                    cleanup_failure = (
                        cleanup_failure or SmokeFailureCode.CLEANUP_UNRESOLVED
                    )
        except BaseException:
            cleanup_failure = (
                cleanup_failure or SmokeFailureCode.CLEANUP_UNRESOLVED
            )
            cleanup_confirmed = False

        return cleanup_confirmed, cleanup_failure, resolved_id

    def run_smoke(
        self,
        request: FixtureRequest | str,
        *,
        dry_run: bool = True,
        cancel_event: threading.Event | None = None,
        wall_deadline_seconds: float = DEFAULT_WALL_DEADLINE_SECONDS,
        cpu_limit_seconds: float = DEFAULT_CPU_LIMIT_SECONDS,
    ) -> SmokeReceipt:
        """Run the single fixed smoke-v1 fixture with strict containment boundaries."""
        # 1. Admission Gate: enforce single fixture identity
        if isinstance(request, str):
            if request != FIXED_SMOKE_FIXTURE_ID:
                raise SmokeAdmissionError(
                    SmokeFailureCode.UNSUPPORTED_FIXTURE,
                    f"Only '{FIXED_SMOKE_FIXTURE_ID}' is supported.",
                )
            req = FixtureRequest(FIXED_SMOKE_FIXTURE_ID)
        elif isinstance(request, FixtureRequest):
            if request.fixture_id != FIXED_SMOKE_FIXTURE_ID:
                raise SmokeAdmissionError(
                    SmokeFailureCode.UNSUPPORTED_FIXTURE,
                    f"Only '{FIXED_SMOKE_FIXTURE_ID}' is supported.",
                )
            req = request
        else:
            raise SmokeAdmissionError(
                SmokeFailureCode.UNSUPPORTED_FIXTURE,
                "Expected FixtureRequest instance.",
            )

        policy = policy_for(req)
        if (
            type(wall_deadline_seconds) not in (int, float)
            or not math.isfinite(wall_deadline_seconds)
            or wall_deadline_seconds <= 0.0
            or wall_deadline_seconds > float(policy.wall_seconds)
        ):
            raise SmokeAdmissionError(
                SmokeFailureCode.POLICY_MISMATCH,
                f"wall_deadline_seconds must be in (0, {policy.wall_seconds}].",
            )
        if (
            type(cpu_limit_seconds) not in (int, float)
            or not math.isfinite(cpu_limit_seconds)
            or cpu_limit_seconds <= 0.0
            or cpu_limit_seconds > float(policy.cpu_seconds)
        ):
            raise SmokeAdmissionError(
                SmokeFailureCode.POLICY_MISMATCH,
                f"cpu_limit_seconds must be in (0, {policy.cpu_seconds}].",
            )

        # 2. Concurrency and Durable Blocking Check
        with self._lock:
            self._sync_from_ledger_locked()
            if self._blocked:
                raise SmokeAdmissionError(
                    SmokeFailureCode.ADMISSIONS_BLOCKED,
                    "Adapter is permanently blocked due to prior unresolved cleanup.",
                )
            if self._active:
                raise SmokeAdmissionError(
                    SmokeFailureCode.JOB_ACTIVE,
                    "Another smoke job is currently running on this adapter.",
                )
            self._active = True

        spec = ContainerJobSpec.for_fixture(req)
        job_id = spec.job_id
        start_mono = self._clock()

        # 3. Optional preflight verification BEFORE any container creation or transport call
        if self._preflight_reader is not None:
            try:
                pf_report = run_preflight(self._preflight_reader)
            except Exception as exc:
                with self._lock:
                    self._active = False
                raise SmokeAdmissionError(
                    SmokeFailureCode.PREFLIGHT_FAILED,
                    f"Preflight execution failed: {exc}",
                ) from exc

            if not pf_report.metadata_prerequisites_met:
                with self._lock:
                    self._active = False
                raise SmokeAdmissionError(
                    SmokeFailureCode.PREFLIGHT_FAILED,
                    f"Preflight issues: {pf_report.issues}",
                )

        # 4. Dry-run early exit (Default safe path: zero transport calls, zero containers)
        if dry_run:
            wall_duration = max(0.0, self._clock() - start_mono)
            receipt = SmokeReceipt(
                job_id=job_id,
                container_id=None,
                fixture_id=FIXED_SMOKE_FIXTURE_ID,
                state=SmokeLifecycleState.DRY_RUN,
                outcome=SmokeOutcome.DRY_RUN_PASSED,
                configuration_verified=True,
                started=False,
                exit_code=None,
                oom_killed=False,
                timed_out=False,
                cancelled=False,
                cpu_limit_exceeded=False,
                wall_duration_seconds=round(wall_duration, 4),
                stdout_snippet=None,
                stderr_snippet=None,
                logs_truncated=False,
                cleanup_confirmed=True,
                failure=None,
                cleanup_failure=None,
                dry_run=True,
            )
            with self._lock:
                self._last_receipt = receipt
                self._active = False
            return receipt

        if isinstance(self._transport, DryRunSmokeTransport):
            with self._lock:
                self._active = False
            raise SmokeAdmissionError(
                SmokeFailureCode.ADMISSIONS_BLOCKED,
                "DryRunSmokeTransport cannot execute non-dry-run container jobs.",
            )

        # Record durable IN_FLIGHT intent BEFORE contacting Docker to create a container.
        # If the process crashes after this point, restart will fail closed (ADMISSIONS_BLOCKED).
        try:
            with self._lock:
                self._ledger.save(
                    status="IN_FLIGHT",
                    blocked=True,
                    seen_ids=self._seen_ids,
                    job_id=job_id,
                    container_name=spec.name,
                )
        except Exception as exc:
            with self._lock:
                self._blocked = True
                self._active = False
            raise SmokeAdmissionError(
                SmokeFailureCode.ADMISSIONS_BLOCKED,
                f"Failed to persist pre-dispatch state ledger: {exc}",
            ) from exc

        container_id: str | None = None
        state = SmokeLifecycleState.ADMITTING
        outcome = SmokeOutcome.FAILED
        config_verified = False
        started = False
        exit_code: int | None = None
        oom_killed = False
        timed_out = False
        cancelled = False
        cpu_limit_exceeded = False
        stdout_snippet: str | None = None
        stderr_snippet: str | None = None
        logs_truncated = False
        cleanup_confirmed = False
        failure: SmokeFailureCode | None = None
        cleanup_failure: SmokeFailureCode | None = None
        create_rejected = False
        watchdog_kill_unresolved = False

        try:
            # 5. Native Container Creation
            state = SmokeLifecycleState.CREATING
            try:
                container_id = self._transport.create(
                    spec, timeout=API_TIMEOUT_SECONDS
                )
            except CreateRejected:
                create_rejected = True
                failure = SmokeFailureCode.CREATE_FAILED
                raise
            except Exception:
                failure = SmokeFailureCode.CREATE_FAILED
                raise

            if not _valid_id(container_id):
                invalid_id = container_id
                container_id = None
                failure = SmokeFailureCode.INVALID_IDENTITY
                raise SmokeAdmissionError(
                    SmokeFailureCode.INVALID_IDENTITY,
                    f"Invalid container ID returned: {invalid_id!r}",
                )

            with self._lock:
                if container_id in self._seen_ids:
                    failure = SmokeFailureCode.DUPLICATE_IDENTITY
                    raise SmokeAdmissionError(
                        SmokeFailureCode.DUPLICATE_IDENTITY,
                        "Container ID reuse detected.",
                    )
                self._seen_ids.add(container_id)
                self._ledger.save(
                    status="IN_FLIGHT",
                    blocked=True,
                    seen_ids=self._seen_ids,
                    job_id=job_id,
                    container_name=spec.name,
                    container_id=container_id,
                )

            state = SmokeLifecycleState.CREATED

            # 6. Verify Exact Pre-Execution Configuration via Validated Normalization Boundary
            try:
                created_meta = self._transport.inspect(
                    container_id, timeout=API_TIMEOUT_SECONDS
                )
            except Exception as exc:
                failure = SmokeFailureCode.INSPECT_FAILED
                raise SmokeAdmissionError(
                    SmokeFailureCode.INSPECT_FAILED, str(exc)
                ) from exc

            try:
                normalize_created_inspect(created_meta, spec, container_id)
            except RunnerLifecycleError as exc:
                if exc.code is FailureCode.INVALID_IDENTITY:
                    failure = SmokeFailureCode.INVALID_IDENTITY
                else:
                    failure = SmokeFailureCode.POLICY_MISMATCH
                raise SmokeAdmissionError(failure, str(exc)) from exc
            except Exception as exc:
                failure = SmokeFailureCode.POLICY_MISMATCH
                raise SmokeAdmissionError(
                    SmokeFailureCode.POLICY_MISMATCH, str(exc)
                ) from exc

            config_verified = True
            state = SmokeLifecycleState.CONFIGURATION_VERIFIED

            # 7. Start Container Execution
            state = SmokeLifecycleState.STARTING
            try:
                self._transport.start(container_id, timeout=API_TIMEOUT_SECONDS)
            except Exception:
                failure = SmokeFailureCode.START_FAILED
                raise

            started = True
            state = SmokeLifecycleState.RUNNING
            exec_start_mono = self._clock()
            deadline_mono = exec_start_mono + wall_deadline_seconds

            # 8. Independent Watchdog Supervision
            # An asynchronous timer thread backs up the polling loop so that even if a
            # transport call blocks until API_TIMEOUT_SECONDS, SIGKILL is dispatched on deadline.
            stop_watchdog = threading.Event()
            watchdog_triggered_kill = threading.Event()

            def _async_watchdog() -> None:
                while not stop_watchdog.wait(timeout=0.02):
                    if (
                        cancel_event is not None and cancel_event.is_set()
                    ) or self._clock() >= deadline_mono:
                        watchdog_triggered_kill.set()
                        try:
                            self._transport.kill(
                                container_id,
                                signal="SIGKILL",
                                timeout=API_TIMEOUT_SECONDS,
                            )
                        except Exception:
                            pass
                        return

            watchdog_thread = threading.Thread(
                target=_async_watchdog, name=f"watchdog-{job_id[:8]}", daemon=True
            )
            watchdog_thread.start()

            try:
                while True:
                    now = self._clock()

                    # Check external cancellation
                    if cancel_event is not None and cancel_event.is_set():
                        cancelled = True
                        failure = SmokeFailureCode.CANCELLED
                        outcome = SmokeOutcome.CANCELLED
                        if not self._terminate_and_verify_stopped(
                            container_id, spec
                        ):
                            watchdog_kill_unresolved = True
                            failure = SmokeFailureCode.WATCHDOG_FAILED
                            outcome = SmokeOutcome.FAILED
                        break

                    # Check wall timeout
                    if now >= deadline_mono:
                        timed_out = True
                        failure = SmokeFailureCode.TIMED_OUT
                        outcome = SmokeOutcome.TIMED_OUT
                        if not self._terminate_and_verify_stopped(
                            container_id, spec
                        ):
                            watchdog_kill_unresolved = True
                            failure = SmokeFailureCode.WATCHDOG_FAILED
                            outcome = SmokeOutcome.FAILED
                        break

                    # Bound inspect timeout to remaining wall deadline
                    remaining_wall = max(0.01, deadline_mono - now)
                    inspect_timeout = min(API_TIMEOUT_SECONDS, remaining_wall)

                    try:
                        meta = self._transport.inspect(
                            container_id, timeout=inspect_timeout
                        )
                        is_running, obs_exit, obs_oom, total_cpu_ns = (
                            validate_runtime_inspect(meta, spec, container_id)
                        )
                    except RunnerLifecycleError as exc:
                        failure = (
                            SmokeFailureCode.INVALID_IDENTITY
                            if exc.code is FailureCode.INVALID_IDENTITY
                            else SmokeFailureCode.INSPECT_FAILED
                        )
                        outcome = SmokeOutcome.FAILED
                        if not self._terminate_and_verify_stopped(
                            container_id, spec
                        ):
                            watchdog_kill_unresolved = True
                        raise
                    except SmokeAdmissionError as exc:
                        failure = exc.code
                        outcome = SmokeOutcome.FAILED
                        if not self._terminate_and_verify_stopped(
                            container_id, spec
                        ):
                            watchdog_kill_unresolved = True
                        raise
                    except Exception as exc:
                        if self._clock() >= deadline_mono:
                            timed_out = True
                            failure = SmokeFailureCode.TIMED_OUT
                            outcome = SmokeOutcome.TIMED_OUT
                            if not self._terminate_and_verify_stopped(
                                container_id, spec
                            ):
                                watchdog_kill_unresolved = True
                                failure = SmokeFailureCode.WATCHDOG_FAILED
                                outcome = SmokeOutcome.FAILED
                            break
                        failure = SmokeFailureCode.INSPECT_FAILED
                        outcome = SmokeOutcome.FAILED
                        if not self._terminate_and_verify_stopped(
                            container_id, spec
                        ):
                            watchdog_kill_unresolved = True
                        raise SmokeAdmissionError(
                            SmokeFailureCode.INSPECT_FAILED, str(exc)
                        ) from exc

                    # Check cumulative CPU usage
                    if total_cpu_ns > 0:
                        cpu_seconds = total_cpu_ns / 1e9
                        if cpu_seconds > cpu_limit_seconds:
                            cpu_limit_exceeded = True
                            failure = SmokeFailureCode.CPU_LIMIT_EXCEEDED
                            outcome = SmokeOutcome.FAILED
                            if not self._terminate_and_verify_stopped(
                                container_id, spec
                            ):
                                watchdog_kill_unresolved = True
                                failure = SmokeFailureCode.WATCHDOG_FAILED
                            break

                    if not is_running:
                        if watchdog_triggered_kill.is_set():
                            if cancel_event is not None and cancel_event.is_set():
                                cancelled = True
                                failure = SmokeFailureCode.CANCELLED
                                outcome = SmokeOutcome.CANCELLED
                            else:
                                timed_out = True
                                failure = SmokeFailureCode.TIMED_OUT
                                outcome = SmokeOutcome.TIMED_OUT
                            break

                        state = SmokeLifecycleState.EXITED
                        exit_code = obs_exit
                        oom_killed = obs_oom
                        if oom_killed:
                            failure = SmokeFailureCode.OOM_KILLED
                            outcome = SmokeOutcome.FAILED
                        elif exit_code == 0:
                            outcome = SmokeOutcome.COMPLETED
                        else:
                            failure = SmokeFailureCode.EXECUTION_FAILED
                            outcome = SmokeOutcome.FAILED
                        break

                    self._sleep(DEFAULT_WATCHDOG_POLL_INTERVAL_SECONDS)
            finally:
                stop_watchdog.set()
                watchdog_thread.join(timeout=0.5)

            # 9. Bounded Log Collection
            try:
                raw_stdout = self._transport.logs(
                    container_id,
                    stdout=True,
                    stderr=False,
                    max_bytes=MAX_LOG_BYTES_PER_STREAM + 1,
                    timeout=API_TIMEOUT_SECONDS,
                )
                if type(raw_stdout) is not bytes:
                    raise TypeError("Transport logs() must return bytes.")
                if len(raw_stdout) > MAX_LOG_BYTES_PER_STREAM:
                    logs_truncated = True
                    raw_stdout = raw_stdout[:MAX_LOG_BYTES_PER_STREAM]
                stdout_snippet = raw_stdout.decode(
                    "utf-8", errors="replace"
                ).strip()

                raw_stderr = self._transport.logs(
                    container_id,
                    stdout=False,
                    stderr=True,
                    max_bytes=MAX_LOG_BYTES_PER_STREAM + 1,
                    timeout=API_TIMEOUT_SECONDS,
                )
                if type(raw_stderr) is not bytes:
                    raise TypeError("Transport logs() must return bytes.")
                if len(raw_stderr) > MAX_LOG_BYTES_PER_STREAM:
                    logs_truncated = True
                    raw_stderr = raw_stderr[:MAX_LOG_BYTES_PER_STREAM]
                stderr_snippet = raw_stderr.decode(
                    "utf-8", errors="replace"
                ).strip()
            except Exception:
                if failure is None:
                    failure = SmokeFailureCode.LOG_RETRIEVAL_FAILED
                if outcome is SmokeOutcome.COMPLETED:
                    outcome = SmokeOutcome.FAILED

        except BaseException:
            if failure is None:
                failure = SmokeFailureCode.CREATE_FAILED
            if outcome is SmokeOutcome.COMPLETED:
                outcome = SmokeOutcome.FAILED

        finally:
            # 10. Mandatory Scoped Cleanup & Absence Verification
            state = SmokeLifecycleState.CLEANING
            cleanup_confirmed, cleanup_failure, container_id = (
                self._cleanup_container(spec, container_id, create_rejected)
            )
            if watchdog_kill_unresolved and not cleanup_confirmed:
                cleanup_failure = (
                    cleanup_failure or SmokeFailureCode.CLEANUP_UNRESOLVED
                )
            if not cleanup_confirmed and outcome is SmokeOutcome.COMPLETED:
                outcome = SmokeOutcome.FAILED
                failure = failure or cleanup_failure or SmokeFailureCode.CLEANUP_UNRESOLVED

            state = (
                SmokeLifecycleState.ABSENT
                if cleanup_confirmed
                else SmokeLifecycleState.UNRESOLVED
            )

            with self._lock:
                if not cleanup_confirmed:
                    self._blocked = True
                try:
                    self._ledger.save(
                        status="IDLE" if cleanup_confirmed else "UNRESOLVED",
                        blocked=not cleanup_confirmed,
                        seen_ids=self._seen_ids,
                        job_id=None if cleanup_confirmed else job_id,
                        container_name=None if cleanup_confirmed else spec.name,
                        container_id=None if cleanup_confirmed else container_id,
                        failure_reason=(
                            cleanup_failure.value if cleanup_failure else None
                        ),
                    )
                except Exception:
                    cleanup_confirmed = False
                    cleanup_failure = (
                        cleanup_failure or SmokeFailureCode.CLEANUP_UNRESOLVED
                    )
                    state = SmokeLifecycleState.UNRESOLVED
                    outcome = SmokeOutcome.FAILED
                    failure = failure or cleanup_failure
                    self._blocked = True
                self._active = False

        receipt = SmokeReceipt(
            job_id=job_id,
            container_id=container_id,
            fixture_id=FIXED_SMOKE_FIXTURE_ID,
            state=state,
            outcome=outcome,
            configuration_verified=config_verified,
            started=started,
            exit_code=exit_code,
            oom_killed=oom_killed,
            timed_out=timed_out,
            cancelled=cancelled,
            cpu_limit_exceeded=cpu_limit_exceeded,
            wall_duration_seconds=round(max(0.0, self._clock() - start_mono), 4),
            stdout_snippet=stdout_snippet,
            stderr_snippet=stderr_snippet,
            logs_truncated=logs_truncated,
            cleanup_confirmed=cleanup_confirmed,
            failure=failure,
            cleanup_failure=cleanup_failure,
            dry_run=False,
        )

        with self._lock:
            self._last_receipt = receipt

        return receipt


def main(argv: list[str] | None = None) -> int:
    """Operator-only CLI entrypoint for native smoke testing."""
    parser = argparse.ArgumentParser(
        description="SheetSafe AI Operator Fixed Smoke Adapter (smoke-v1 only)"
    )
    parser.add_argument(
        "--context",
        default=LocalContext.LINUX_DEFAULT.value,
        choices=[c.value for c in LocalContext],
        help="Docker context to query",
    )
    parser.add_argument(
        "--fixture",
        default=FIXED_SMOKE_FIXTURE_ID,
        choices=[FIXED_SMOKE_FIXTURE_ID],
        help="Fixed fixture ID (only smoke-v1 is supported)",
    )
    parser.add_argument(
        "--execute-approved-native-smoke",
        action="store_true",
        default=False,
        help="Explicit operator authorization for native container execution on Linux.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Perform admission and preflight inspection only without container execution.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_WALL_DEADLINE_SECONDS,
        help="Wall-clock deadline in seconds (max 20.0s).",
    )
    parser.add_argument(
        "--state-file",
        type=Path,
        default=None,
        help="Durable state ledger file path (defaults to var/smoke_adapter/state.json for native runs).",
    )

    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    # Force dry_run=True unless explicit operator flag is passed
    is_dry_run = not args.execute_approved_native_smoke

    if not is_dry_run and sys.platform != "linux":
        sys.stderr.write(
            "ERROR: Native container execution requires a native Linux host.\n"
            "On Windows/WSL2/macOS, AppArmor LSM is not advertised (LSM_NOT_ADVERTISED).\n"
            "Execution is refused fail-closed. Run in default --dry-run mode.\n"
        )
        return 2

    state_path: Path | None = args.state_file
    if state_path is None:
        if not is_dry_run or DEFAULT_STATE_FILE_PATH.exists():
            state_path = DEFAULT_STATE_FILE_PATH

    transport: DockerSmokeTransport
    preflight_client: EngineReader | None = None

    if is_dry_run:
        transport = DryRunSmokeTransport()
    else:
        try:
            transport = NativeCliSmokeTransport(context=args.context)
            preflight_client = DockerReadOnlyClient(LocalContext(args.context))
        except Exception as exc:
            sys.stderr.write(f"ERROR initializing native transport: {exc}\n")
            return 2

    adapter = SmokeAdapter(
        transport,
        preflight_reader=preflight_client,
        state_path=state_path,
    )

    try:
        receipt = adapter.run_smoke(
            args.fixture,
            dry_run=is_dry_run,
            wall_deadline_seconds=min(args.timeout, DEFAULT_WALL_DEADLINE_SECONDS),
        )
    except Exception as exc:
        sys.stderr.write(f"ADMISSION REJECTED: {exc}\n")
        return 1

    sys.stdout.write(json.dumps(receipt.to_dict(), indent=2) + "\n")

    if receipt.outcome in (SmokeOutcome.COMPLETED, SmokeOutcome.DRY_RUN_PASSED):
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
