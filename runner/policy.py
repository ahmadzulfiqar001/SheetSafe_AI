"""Server-owned target contract, not evidence of runtime enforcement.

Requests select a reviewed fixture, never Docker options. No environment files,
daemon clients, process launchers or backend modules are imported here. Frozen
objects prevent routine accidental changes; they do not isolate a compromised
Python process. The future privileged adapter must independently validate its
effective container configuration before admitting work.
"""

from dataclasses import dataclass, field
from typing import ClassVar


class RunnerPolicyError(ValueError):
    def __init__(self) -> None:
        super().__init__("Runner request is not permitted.")


class RunnerNotReady(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Runner execution is not implemented or verified.")


@dataclass(frozen=True, slots=True)
class FixtureRequest:
    """Internal operator request, not an authenticated public API contract."""

    fixture_id: str
    allowed_ids: ClassVar[frozenset[str]] = frozenset({"smoke-v1"})

    def __post_init__(self) -> None:
        if type(self.fixture_id) is not str or self.fixture_id not in self.allowed_ids:
            raise RunnerPolicyError()

    @classmethod
    def from_mapping(cls, payload: object) -> "FixtureRequest":
        # Reject unknown keys rather than silently ignoring an attempted override.
        # Accept plain decoded JSON objects, not user-defined mapping behavior.
        if type(payload) is not dict or set(payload) != {"fixture_id"}:
            raise RunnerPolicyError()
        return cls(fixture_id=payload["fixture_id"])


@dataclass(frozen=True, slots=True)
class TmpfsTarget:
    """Values below are supplied only by the canonical policy constructor."""

    path: str
    byte_limit: int
    uid: int = 10001
    gid: int = 10001
    mode: int = 0o700
    options: tuple[str, ...] = ("nodev", "nosuid", "noexec")


@dataclass(frozen=True, slots=True)
class SandboxPolicy:
    """No caller-settable constructor fields; all SEC controls remain unverified.

    Local static image selection is pinned separately from execution permission.
    No execution-approved final image digest is configured. The source image is
    separately pinned in the Dockerfile. No caller flag, tag, environment variable
    or readiness boolean can enable execution.
    """

    version: str = field(default="sheetsafe-smoke-policy-v1", init=False)
    execution_enabled: bool = field(default=False, init=False)
    final_image_digest: None = field(default=None, init=False)
    unverified_controls: tuple[str, ...] = field(
        default=tuple(f"SEC{number:02}" for number in range(1, 11)), init=False,
    )
    uid: int = field(default=10001, init=False)
    gid: int = field(default=10001, init=False)
    cap_drop: tuple[str, ...] = field(default=("ALL",), init=False)
    privileged: bool = field(default=False, init=False)
    no_new_privileges: bool = field(default=True, init=False)
    network_mode: str = field(default="none", init=False)
    published_ports: tuple[()] = field(default=(), init=False)
    host_bind_mounts: tuple[()] = field(default=(), init=False)
    shared_volumes: tuple[()] = field(default=(), init=False)
    read_only_root: bool = field(default=True, init=False)
    pid_namespace: str = field(default="private", init=False)
    ipc_namespace: str = field(default="private", init=False)
    cpus: int = field(default=1, init=False)
    cpu_seconds: int = field(default=10, init=False)
    memory_bytes: int = field(default=1024**3, init=False)
    memory_plus_swap_bytes: int = field(default=1024**3, init=False)
    pids_limit: int = field(default=32, init=False)
    wall_seconds: int = field(default=20, init=False)
    kill_grace_seconds: int = field(default=2, init=False)
    cancellation_seconds: int = field(default=5, init=False)
    tmpfs: tuple[TmpfsTarget, ...] = field(default=(
        TmpfsTarget("/work", 256 * 1024**2), TmpfsTarget("/tmp", 64 * 1024**2),
    ), init=False)
    artifact_bytes: int = field(default=10 * 1024**2, init=False)
    total_artifact_bytes: int = field(default=20 * 1024**2, init=False)
    artifact_count: int = field(default=10, init=False)
    log_bytes_per_stream: int = field(default=64 * 1024, init=False)
    daemon_log_driver: str = field(default="none", init=False)
    seccomp: str = field(default="docker-default", init=False)
    require_available_lsm: bool = field(default=True, init=False)
    environment: tuple[tuple[str, str], ...] = field(default=(
        ("LANG", "C.UTF-8"), ("HOME", "/nonexistent"),
        ("PATH", "/usr/local/bin:/usr/bin:/bin"),
    ), init=False)
    entrypoint: tuple[str, ...] = field(default=(
        "/usr/local/bin/python", "-I", "-S", "-B", "-u", "/opt/sheetsafe/bootstrap.py",
    ), init=False)
    workdir: str = field(default="/work", init=False)
    input_transport: str = field(default="stopped-container-archive", init=False)
    fresh_runtime: bool = field(default=True, init=False)
    verified_cleanup_required: bool = field(default=True, init=False)
    orphan_reaper_seconds: int = field(default=30, init=False)


def policy_for(request: FixtureRequest) -> SandboxPolicy:
    """Return a fresh canonical target; never merge request-provided options."""
    if type(request) is not FixtureRequest or request.fixture_id != "smoke-v1":
        raise RunnerPolicyError()
    return SandboxPolicy()


def require_execution_ready() -> None:
    """Explicit fail-closed gate until the later adapter and runtime checks exist."""
    raise RunnerNotReady()
