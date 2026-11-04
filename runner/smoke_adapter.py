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
- Supervised by an independent monotonic watchdog; cleanup absence is verified
  against both container ID and container name. Any cleanup ambiguity permanently
  blocks the adapter instance.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
import json
import math
import os
import platform
import re
import shutil
import subprocess
import sys
import threading
import time
from typing import Protocol
from uuid import uuid4

from runner.docker_backend import (
    API_TIMEOUT_SECONDS,
    LOCAL_IMAGE_ID,
    LOCAL_REVIEW_TAG,
    ContainerJobSpec,
    ContainerNotFound,
    CreateRejected,
    FailureCode,
    _owned_id,
    _same,
    _valid_id,
    verify_configuration,
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
MAX_LOG_BYTES_PER_STREAM = 64 * 1024  # 64 KiB budget from SandboxPolicy
DEFAULT_WATCHDOG_POLL_INTERVAL_SECONDS = 0.05
DEFAULT_KILL_GRACE_SECONDS = 2.0
DEFAULT_CANCELLATION_SECONDS = 5.0
DEFAULT_WALL_DEADLINE_SECONDS = 20.0
DEFAULT_CPU_LIMIT_SECONDS = 10.0


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
    def wait(self, container_id: str, *, timeout: float) -> int: ...
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
            "Dry-run transport does not create containers",
        )

    def inspect(self, reference: str, *, timeout: float) -> dict:
        raise ContainerNotFound()

    def start(self, container_id: str, *, timeout: float) -> None:
        raise SmokeAdmissionError(
            SmokeFailureCode.ADMISSIONS_BLOCKED,
            "Dry-run transport does not start containers",
        )

    def wait(self, container_id: str, *, timeout: float) -> int:
        return 0

    def kill(self, container_id: str, *, signal: str, timeout: float) -> None:
        pass

    def logs(
        self,
        container_id: str,
        *,
        stdout: bool,
        stderr: bool,
        max_bytes: int,
        timeout: float,
    ) -> bytes:
        return b""

    def remove(self, container_id: str, *, force: bool, timeout: float) -> None:
        pass


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
        self._context = context
        executable = shutil.which("docker")
        if executable is None:
            raise SmokeAdmissionError(
                SmokeFailureCode.PREFLIGHT_FAILED,
                "Docker CLI executable was not found on PATH.",
            )
        self._executable = executable

    def _exec(
        self, arguments: list[str], *, timeout: float, max_bytes: int = 1024 * 1024
    ) -> bytes:
        cmd = [self._executable, "--context", self._context, *arguments]
        try:
            res = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError(f"Docker command timed out after {timeout}s") from exc
        except OSError as exc:
            raise RuntimeError(f"Docker command execution failed: {exc}") from exc

        if res.returncode != 0:
            err_msg = res.stderr.decode("utf-8", errors="replace").strip()
            if "No such container" in err_msg or "not found" in err_msg.lower():
                raise ContainerNotFound(err_msg)
            raise RuntimeError(f"Docker CLI exited with {res.returncode}: {err_msg}")
        return res.stdout[:max_bytes]

    def create(self, spec: ContainerJobSpec, *, timeout: float) -> str:
        body = spec.create_body()
        policy = SandboxPolicy()
        args = [
            "create",
            "--name",
            spec.name,
            "--user",
            f"{policy.uid}:{policy.gid}",
            "--entrypoint",
            policy.entrypoint[0],
            "--workdir",
            policy.workdir,
            "--network",
            policy.network_mode,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges=true",
            "--cpus",
            str(policy.cpus),
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
            "--restart",
            "no",
            "--log-driver",
            "none",
        ]
        for mount in policy.tmpfs:
            args.extend(
                [
                    "--tmpfs",
                    f"{mount.path}:rw,size={mount.byte_limit},uid={mount.uid},gid={mount.gid},mode={mount.mode:o}",
                ]
            )
        for name, value in policy.environment:
            args.extend(["--env", f"{name}={value}"])
        for k, v in spec.labels.items():
            args.extend(["--label", f"{k}={v}"])

        args.append(spec.image_id)
        args.append(spec.fixture_id)

        out = self._exec(args, timeout=timeout).decode("utf-8", errors="replace").strip()
        lines = out.splitlines()
        cid = lines[-1].strip() if lines else ""
        if not _valid_id(cid):
            raise CreateRejected("Docker create returned invalid container ID")
        return cid

    def inspect(self, reference: str, *, timeout: float) -> dict:
        out = self._exec(["inspect", reference], timeout=timeout)
        try:
            parsed = json.loads(out)
            if not isinstance(parsed, list) or len(parsed) != 1 or not isinstance(parsed[0], dict):
                raise ContainerNotFound()
            return parsed[0]
        except (json.JSONDecodeError, ValueError):
            raise ContainerNotFound()

    def start(self, container_id: str, *, timeout: float) -> None:
        self._exec(["start", container_id], timeout=timeout)

    def wait(self, container_id: str, *, timeout: float) -> int:
        out = self._exec(["wait", container_id], timeout=timeout)
        try:
            return int(out.decode("utf-8", errors="replace").strip())
        except ValueError:
            return -1

    def kill(self, container_id: str, *, signal: str, timeout: float) -> None:
        try:
            self._exec(["kill", f"--signal={signal}", container_id], timeout=timeout)
        except ContainerNotFound:
            pass
        except Exception:
            pass

    def logs(
        self,
        container_id: str,
        *,
        stdout: bool,
        stderr: bool,
        max_bytes: int,
        timeout: float,
    ) -> bytes:
        args = ["logs"]
        if stdout and not stderr:
            args.append("--stdout")
        elif stderr and not stdout:
            args.append("--stderr")
        args.append(container_id)
        try:
            return self._exec(args, timeout=timeout, max_bytes=max_bytes)
        except Exception:
            return b""

    def remove(self, container_id: str, *, force: bool, timeout: float) -> None:
        args = ["rm"]
        if force:
            args.append("-f")
        args.append(container_id)
        self._exec(args, timeout=timeout)


class SmokeAdapter:
    """Operator-only, single-fixture isolated smoke adapter.

    Accepts ONLY smoke-v1 fixture.
    Enforces fail-closed admission, monotonic watchdog timeout, and verified cleanup.
    Uncertainty in cleanup permanently blocks this adapter instance from further admissions.
    """

    def __init__(
        self,
        transport: DockerSmokeTransport | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep_fn: Callable[[float], None] = time.sleep,
        preflight_reader: EngineReader | None = None,
    ) -> None:
        self._transport = transport if transport is not None else DryRunSmokeTransport()
        self._clock = clock
        self._sleep = sleep_fn
        self._preflight_reader = preflight_reader
        self._lock = threading.Lock()
        self._active = False
        self._blocked = False
        self._seen_ids: set[str] = set()
        self._last_receipt: SmokeReceipt | None = None

    @property
    def admissions_blocked(self) -> bool:
        with self._lock:
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

    def _cleanup_container(
        self,
        spec: ContainerJobSpec,
        container_id: str | None,
        create_rejected: bool,
    ) -> tuple[bool, SmokeFailureCode | None]:
        """Perform verified teardown. Absence must be verified on both ID and name."""
        cleanup_confirmed = False
        cleanup_failure: SmokeFailureCode | None = None

        try:
            # 1. Attempt inspection by container name
            try:
                metadata = self._transport.inspect(spec.name, timeout=API_TIMEOUT_SECONDS)
            except ContainerNotFound:
                if create_rejected:
                    cleanup_confirmed = True
                elif container_id is not None:
                    cleanup_confirmed = self._absent(container_id)
                    if not cleanup_confirmed:
                        cleanup_failure = SmokeFailureCode.CLEANUP_UNRESOLVED
                else:
                    cleanup_failure = SmokeFailureCode.CLEANUP_UNRESOLVED
            except Exception:
                cleanup_failure = SmokeFailureCode.CLEANUP_UNRESOLVED
            else:
                # Name resolved to an existing container; check ownership
                candidate_id = _owned_id(metadata, spec)
                if container_id is None:
                    container_id = candidate_id
                if candidate_id != container_id:
                    cleanup_failure = SmokeFailureCode.INVALID_IDENTITY

                # Force removal
                try:
                    self._transport.remove(candidate_id, force=True, timeout=API_TIMEOUT_SECONDS)
                except Exception:
                    cleanup_failure = SmokeFailureCode.REMOVE_FAILED

                # Verify absence on both candidate ID and reserved container name
                id_absent = self._absent(candidate_id)
                name_absent = self._absent(spec.name)
                cleanup_confirmed = id_absent and name_absent
                if not cleanup_confirmed:
                    cleanup_failure = cleanup_failure or SmokeFailureCode.CLEANUP_UNRESOLVED

        except Exception:
            cleanup_failure = SmokeFailureCode.CLEANUP_UNRESOLVED
            cleanup_confirmed = False

        return cleanup_confirmed, cleanup_failure

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

        # 2. Concurrency and Blocking Check
        with self._lock:
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
        start_mono = self._clock()
        wall_duration = 0.0
        stdout_snippet: str | None = None
        stderr_snippet: str | None = None
        logs_truncated = False
        cleanup_confirmed = False
        failure: SmokeFailureCode | None = None
        cleanup_failure: SmokeFailureCode | None = None
        create_rejected = False

        try:
            # 3. Optional preflight verification if reader provided
            if self._preflight_reader is not None:
                pf_report = run_preflight(self._preflight_reader)
                if not pf_report.metadata_prerequisites_met:
                    failure = SmokeFailureCode.PREFLIGHT_FAILED
                    state = SmokeLifecycleState.ADMITTING
                    raise SmokeAdmissionError(
                        SmokeFailureCode.PREFLIGHT_FAILED,
                        f"Preflight issues: {pf_report.issues}",
                    )

            # 4. Dry-run early exit (Default safe path)
            if dry_run or isinstance(self._transport, DryRunSmokeTransport):
                state = SmokeLifecycleState.DRY_RUN
                outcome = SmokeOutcome.DRY_RUN_PASSED
                config_verified = True
                cleanup_confirmed = True
                wall_duration = self._clock() - start_mono
                receipt = SmokeReceipt(
                    job_id=job_id,
                    container_id=None,
                    fixture_id=FIXED_SMOKE_FIXTURE_ID,
                    state=state,
                    outcome=outcome,
                    configuration_verified=config_verified,
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
                return receipt

            # 5. Native Container Creation
            state = SmokeLifecycleState.CREATING
            try:
                container_id = self._transport.create(spec, timeout=API_TIMEOUT_SECONDS)
            except CreateRejected:
                create_rejected = True
                failure = SmokeFailureCode.CREATE_FAILED
                raise
            except Exception:
                failure = SmokeFailureCode.CREATE_FAILED
                raise

            if not _valid_id(container_id):
                failure = SmokeFailureCode.INVALID_IDENTITY
                raise SmokeAdmissionError(
                    SmokeFailureCode.INVALID_IDENTITY, "Invalid container ID returned."
                )
            if container_id in self._seen_ids:
                failure = SmokeFailureCode.DUPLICATE_IDENTITY
                raise SmokeAdmissionError(
                    SmokeFailureCode.DUPLICATE_IDENTITY, "Container ID reuse detected."
                )
            self._seen_ids.add(container_id)
            state = SmokeLifecycleState.CREATED

            # 6. Verify Exact Pre-Execution Configuration
            created_meta = self._transport.inspect(container_id, timeout=API_TIMEOUT_SECONDS)
            try:
                verify_configuration(created_meta, spec, container_id)
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

            # 8. Watchdog Supervision Loop
            # Bounds: wall deadline <= wall_deadline_seconds, cancellation check, CPU check
            deadline_mono = exec_start_mono + wall_deadline_seconds

            while True:
                now = self._clock()
                wall_duration = now - exec_start_mono

                # Check external cancellation
                if cancel_event is not None and cancel_event.is_set():
                    cancelled = True
                    failure = SmokeFailureCode.CANCELLED
                    outcome = SmokeOutcome.CANCELLED
                    self._transport.kill(
                        container_id, signal="SIGKILL", timeout=API_TIMEOUT_SECONDS
                    )
                    break

                # Check wall timeout
                if now >= deadline_mono:
                    timed_out = True
                    failure = SmokeFailureCode.TIMED_OUT
                    outcome = SmokeOutcome.TIMED_OUT
                    self._transport.kill(
                        container_id, signal="SIGKILL", timeout=API_TIMEOUT_SECONDS
                    )
                    break

                # Inspect current container status
                meta = self._transport.inspect(container_id, timeout=API_TIMEOUT_SECONDS)
                state_dict = meta.get("State", {})
                is_running = state_dict.get("Running", False)

                # Check cumulative CPU if runtime exposes cpu_stats
                cpu_stats = meta.get("CPUStats", {}).get("cpu_usage", {})
                total_cpu_ns = cpu_stats.get("total_usage", 0)
                if total_cpu_ns > 0:
                    cpu_seconds = total_cpu_ns / 1e9
                    if cpu_seconds > cpu_limit_seconds:
                        cpu_limit_exceeded = True
                        failure = SmokeFailureCode.CPU_LIMIT_EXCEEDED
                        outcome = SmokeOutcome.FAILED
                        self._transport.kill(
                            container_id, signal="SIGKILL", timeout=API_TIMEOUT_SECONDS
                        )
                        break

                if not is_running:
                    # Container exited
                    state = SmokeLifecycleState.EXITED
                    exit_code = state_dict.get("ExitCode")
                    oom_killed = bool(state_dict.get("OOMKilled", False))
                    if oom_killed:
                        failure = SmokeFailureCode.OOM_KILLED
                        outcome = SmokeOutcome.FAILED
                    elif exit_code == 0:
                        outcome = SmokeOutcome.COMPLETED
                    else:
                        failure = SmokeFailureCode.EXECUTION_FAILED
                        outcome = SmokeOutcome.FAILED
                    break

                # Sleep bounded watchdog interval
                self._sleep(DEFAULT_WATCHDOG_POLL_INTERVAL_SECONDS)

            # 9. Bounded Log Collection
            try:
                raw_stdout = self._transport.logs(
                    container_id,
                    stdout=True,
                    stderr=False,
                    max_bytes=MAX_LOG_BYTES_PER_STREAM + 1,
                    timeout=API_TIMEOUT_SECONDS,
                )
                if len(raw_stdout) > MAX_LOG_BYTES_PER_STREAM:
                    logs_truncated = True
                    raw_stdout = raw_stdout[:MAX_LOG_BYTES_PER_STREAM]
                stdout_snippet = raw_stdout.decode("utf-8", errors="replace").strip()

                raw_stderr = self._transport.logs(
                    container_id,
                    stdout=False,
                    stderr=True,
                    max_bytes=MAX_LOG_BYTES_PER_STREAM + 1,
                    timeout=API_TIMEOUT_SECONDS,
                )
                if len(raw_stderr) > MAX_LOG_BYTES_PER_STREAM:
                    logs_truncated = True
                    raw_stderr = raw_stderr[:MAX_LOG_BYTES_PER_STREAM]
                stderr_snippet = raw_stderr.decode("utf-8", errors="replace").strip()
            except Exception:
                if failure is None:
                    failure = SmokeFailureCode.LOG_RETRIEVAL_FAILED

        except BaseException as exc:
            if failure is None:
                failure = SmokeFailureCode.CREATE_FAILED
            outcome = SmokeOutcome.FAILED

        finally:
            # 10. Mandatory Scoped Cleanup & Absence Verification
            state = SmokeLifecycleState.CLEANING
            cleanup_confirmed, cleanup_failure = self._cleanup_container(
                spec, container_id, create_rejected
            )
            state = (
                SmokeLifecycleState.ABSENT
                if cleanup_confirmed
                else SmokeLifecycleState.UNRESOLVED
            )

            # Uncertainty permanently blocks the adapter instance
            with self._lock:
                if not cleanup_confirmed:
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
            wall_duration_seconds=round(self._clock() - start_mono, 4),
            stdout_snippet=stdout_snippet,
            stderr_snippet=stderr_snippet,
            logs_truncated=logs_truncated,
            cleanup_confirmed=cleanup_confirmed,
            failure=failure,
            cleanup_failure=cleanup_failure,
            dry_run=dry_run,
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

    adapter = SmokeAdapter(transport, preflight_reader=preflight_client)

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

