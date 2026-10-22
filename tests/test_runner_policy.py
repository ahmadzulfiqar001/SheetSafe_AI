"""Policy boundary tests only: no Docker access or fixture execution."""

from dataclasses import FrozenInstanceError, fields, replace
import importlib
import os

import pytest

from runner.policy import (
    FixtureRequest, RunnerNotReady, RunnerPolicyError, SandboxPolicy,
    policy_for, require_execution_ready,
)


def test_only_reviewed_smoke_request_is_accepted():
    request = FixtureRequest.from_mapping({"fixture_id": "smoke-v1"})
    assert request == FixtureRequest("smoke-v1")
    assert policy_for(request) == SandboxPolicy()


@pytest.mark.parametrize("payload", [
    None, [], (), "smoke-v1", {}, {"fixture_id": None}, {"fixture_id": True},
    {"fixture_id": ["smoke-v1"]}, {"fixture_id": "SMOKE-V1"},
    {"fixture_id": "../smoke-v1"}, {"fixture_id": "smoke-v1\n"},
    {"fixture_id": "python -c print(1)"},
])
def test_invalid_fixture_requests_fail_with_sanitized_error(payload):
    with pytest.raises(RunnerPolicyError) as error:
        FixtureRequest.from_mapping(payload)
    assert str(error.value) == "Runner request is not permitted."


@pytest.mark.parametrize("key,value", [
    ("command", ["sh", "-c", "echo synthetic"]), ("code", "print('synthetic')"),
    ("entrypoint", ["/bin/sh"]), ("args", ["--privileged"]),
    ("runtime_flags", ["--network=host"]), ("image", "untrusted/image:latest"),
    ("image_digest", "sha256:" + "a" * 64), ("build_args", {"BASE_IMAGE": "other"}),
    ("mounts", ["/:/host"]), ("volumes", ["/var/run/docker.sock:/var/run/docker.sock"]),
    ("privileged", True), ("uid", 0), ("gid", 0), ("user", "root"),
    ("cap_add", ["SYS_ADMIN"]), ("network_mode", "host"), ("ports", [8000]),
    ("pid_namespace", "host"), ("ipc_namespace", "host"),
    ("read_only_root", False), ("no_new_privileges", False),
    ("memory_bytes", 16 * 1024**3), ("pids_limit", 0), ("wall_seconds", 999),
    ("seccomp", "unconfined"), ("environment", {"SYNTHETIC_SECRET": "test-only"}),
    ("storage_path", "../outside"), ("policy", {}), ("execution_enabled", True),
])
def test_any_attempted_request_override_is_rejected(key, value):
    with pytest.raises(RunnerPolicyError):
        FixtureRequest.from_mapping({"fixture_id": "smoke-v1", key: value})


@pytest.mark.parametrize("field_name", [item.name for item in fields(SandboxPolicy)])
def test_policy_fields_cannot_be_supplied_or_replaced(field_name):
    with pytest.raises(TypeError):
        SandboxPolicy(**{field_name: None})
    with pytest.raises(ValueError):
        replace(SandboxPolicy(), **{field_name: None})


def test_policy_request_and_nested_configuration_are_frozen():
    policy = SandboxPolicy()
    with pytest.raises(FrozenInstanceError):
        policy.privileged = True
    with pytest.raises(FrozenInstanceError):
        policy.tmpfs[0].byte_limit = 1
    with pytest.raises(FrozenInstanceError):
        FixtureRequest("smoke-v1").fixture_id = "other"
    assert not hasattr(policy, "__dict__")


def test_prd_budgets_and_fail_closed_state():
    policy = SandboxPolicy()
    assert (policy.uid, policy.gid) == (10001, 10001)
    assert policy.cap_drop == ("ALL",) and policy.no_new_privileges
    assert not policy.privileged and policy.network_mode == "none"
    assert policy.published_ports == policy.host_bind_mounts == policy.shared_volumes == ()
    assert policy.read_only_root and policy.pid_namespace == policy.ipc_namespace == "private"
    assert (policy.cpus, policy.cpu_seconds, policy.pids_limit) == (1, 10, 32)
    assert policy.memory_bytes == policy.memory_plus_swap_bytes == 1024**3
    assert (policy.wall_seconds, policy.kill_grace_seconds, policy.cancellation_seconds) == (20, 2, 5)
    assert [(mount.path, mount.byte_limit) for mount in policy.tmpfs] == [
        ("/work", 256 * 1024**2), ("/tmp", 64 * 1024**2),
    ]
    assert all(mount.options == ("nodev", "nosuid", "noexec") for mount in policy.tmpfs)
    assert policy.artifact_bytes == 10 * 1024**2 and policy.total_artifact_bytes == 20 * 1024**2
    assert policy.artifact_count == 10 and policy.log_bytes_per_stream == 65536
    assert policy.daemon_log_driver == "none" and policy.seccomp == "docker-default"
    assert policy.input_transport == "stopped-container-archive"
    assert policy.fresh_runtime and policy.verified_cleanup_required
    assert policy.unverified_controls == tuple(f"SEC{i:02}" for i in range(1, 11))
    assert policy.final_image_digest is None and policy.execution_enabled is False
    with pytest.raises(RunnerNotReady):
        require_execution_ready()


def test_host_environment_cannot_override_policy(monkeypatch):
    for name in ("SHEETSAFE_RUNNER_IMAGE", "SHEETSAFE_RUNNER_PRIVILEGED", "DOCKER_HOST"):
        monkeypatch.setenv(name, "synthetic-untrusted-setting")
    assert dict(SandboxPolicy().environment) == {
        "LANG": "C.UTF-8", "HOME": "/nonexistent", "PATH": "/usr/local/bin:/usr/bin:/bin",
    }
    assert SandboxPolicy().privileged is False


def test_non_request_objects_are_rejected():
    for value in ({"fixture_id": "smoke-v1"}, "smoke-v1", None):
        with pytest.raises(RunnerPolicyError):
            policy_for(value)


def test_imports_cannot_launch_a_process_or_connect_to_docker(monkeypatch):
    import subprocess
    import socket
    import sys
    from pathlib import Path

    def forbidden(*args, **kwargs):
        pytest.fail("Policy import attempted external I/O")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    spec = importlib.util.spec_from_file_location(
        "policy_import_probe", Path(__file__).resolve().parents[1] / "runner" / "policy.py",
    )
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
