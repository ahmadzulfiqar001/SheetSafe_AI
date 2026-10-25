"""Separate parser target contract. No image/execution approval or Engine API."""

from dataclasses import dataclass, field

from runner.policy import RunnerNotReady, TmpfsTarget


@dataclass(frozen=True, slots=True)
class ParserPolicy:
    version: str = field(default="sheetsafe-parser-policy-v1", init=False)
    approved_image_id: None = field(default=None, init=False)
    execution_enabled: bool = field(default=False, init=False)
    platform: str = field(default="linux/amd64", init=False)
    source_image: str = field(default="docker.io/library/python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70", init=False)
    uid: int = field(default=10001, init=False)
    gid: int = field(default=10001, init=False)
    network_mode: str = field(default="none", init=False)
    host_bind_mounts: tuple[()] = field(default=(), init=False)
    socket_mounts: tuple[()] = field(default=(), init=False)
    shared_volumes: tuple[()] = field(default=(), init=False)
    privileged: bool = field(default=False, init=False)
    cap_drop: tuple[str, ...] = field(default=("ALL",), init=False)
    cap_add: tuple[()] = field(default=(), init=False)
    no_new_privileges: bool = field(default=True, init=False)
    read_only_root: bool = field(default=True, init=False)
    pid_namespace: str = field(default="private", init=False)
    ipc_namespace: str = field(default="private", init=False)
    seccomp: str = field(default="docker-default", init=False)
    require_enforcing_lsm: bool = field(default=True, init=False)
    cpus: int = field(default=1, init=False)
    cpu_seconds: int = field(default=10, init=False)
    memory_bytes: int = field(default=1024**3, init=False)
    memory_plus_swap_bytes: int = field(default=1024**3, init=False)
    pids_limit: int = field(default=32, init=False)
    wall_seconds: int = field(default=20, init=False)
    kill_grace_seconds: int = field(default=2, init=False)
    cancellation_seconds: int = field(default=5, init=False)
    tmpfs: tuple[TmpfsTarget, ...] = field(default=(
        TmpfsTarget("/work", 256 * 1024**2), TmpfsTarget("/tmp", 64 * 1024**2)), init=False)
    environment: tuple[tuple[str, str], ...] = field(default=(
        ("LANG", "C.UTF-8"), ("HOME", "/nonexistent"), ("PATH", "/usr/local/bin")), init=False)
    entrypoint: tuple[str, ...] = field(default=("/usr/local/bin/python3.12", "-I", "-S", "-B", "-u",
        "/opt/sheetsafe/bootstrap.py"), init=False)
    command: tuple[()] = field(default=(), init=False)
    subprocess_operations: tuple[()] = field(default=(), init=False)
    input_transport: str = field(default="UNIMPLEMENTED_PRD_DECISION_PENDING", init=False)
    daemon_log_driver: str = field(default="none", init=False)
    log_bytes_per_stream: int = field(default=64 * 1024, init=False)
    fresh_runtime: bool = field(default=True, init=False)
    verified_cleanup_required: bool = field(default=True, init=False)
    unverified_controls: tuple[str, ...] = field(default=tuple(f"SEC{i:02}" for i in range(1, 11)), init=False)


def require_parser_execution_ready() -> None:
    # A source pin is not a final image ID. Building never self-approves an image.
    raise RunnerNotReady()
