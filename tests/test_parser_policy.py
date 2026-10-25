"""Requested parser policy values are not runtime verification."""

from dataclasses import FrozenInstanceError, fields

import pytest

from runner.parser_policy import ParserPolicy, require_parser_execution_ready
from runner.policy import RunnerNotReady, SandboxPolicy


def test_separate_frozen_parser_profile_and_unapproved_image():
    policy = ParserPolicy()
    assert policy.version != SandboxPolicy().version
    assert policy.approved_image_id is None and policy.execution_enabled is False
    assert policy.uid == policy.gid == 10001 and policy.network_mode == "none"
    assert policy.read_only_root and policy.no_new_privileges and not policy.privileged
    assert policy.cap_drop == ("ALL",) and not policy.cap_add
    assert not policy.host_bind_mounts and not policy.socket_mounts and not policy.shared_volumes
    assert policy.pid_namespace == policy.ipc_namespace == "private"
    assert policy.seccomp == "docker-default" and policy.require_enforcing_lsm
    assert policy.cpus == 1 and policy.cpu_seconds == 10 and policy.wall_seconds == 20
    assert policy.memory_bytes == policy.memory_plus_swap_bytes == 1024**3 and policy.pids_limit == 32
    assert policy.kill_grace_seconds == 2 and policy.cancellation_seconds == 5
    assert [(m.path, m.byte_limit) for m in policy.tmpfs] == [("/work", 256 * 1024**2), ("/tmp", 64 * 1024**2)]
    assert all(m.options == ("nodev", "nosuid", "noexec") for m in policy.tmpfs)
    assert policy.fresh_runtime and policy.verified_cleanup_required
    assert policy.unverified_controls == tuple(f"SEC{i:02}" for i in range(1, 11))
    assert not policy.command and not policy.subprocess_operations
    assert set(dict(policy.environment)) == {"LANG", "HOME", "PATH"}
    with pytest.raises(FrozenInstanceError):
        policy.execution_enabled = True
    with pytest.raises(RunnerNotReady):
        require_parser_execution_ready()


@pytest.mark.parametrize("name", [f.name for f in fields(ParserPolicy)])
def test_no_policy_field_can_be_overridden(name):
    with pytest.raises(TypeError):
        ParserPolicy(**{name: "caller override"})


@pytest.mark.parametrize("name", ["image", "command_path", "mounts", "docker_flags", "credentials"])
def test_unknown_policy_overrides_rejected(name):
    with pytest.raises(TypeError):
        ParserPolicy(**{name: "untrusted"})
