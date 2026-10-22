"""All lifecycle operations use an in-memory fake; never contact a daemon."""

from asyncio import CancelledError
from copy import deepcopy
from dataclasses import FrozenInstanceError, fields
import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import sys
from threading import Event, Thread

import pytest

from runner.docker_backend import (
    API_TIMEOUT_SECONDS, LOCAL_IMAGE_ID, ContainerJobSpec, ContainerNotFound,
    CreateRejected, DockerLifecycleAdapter, FailureCode, JobOutcome,
    LifecycleState, RunnerLifecycleError,
)
from runner.policy import FixtureRequest, RunnerNotReady, RunnerPolicyError, require_execution_ready


REQUEST = FixtureRequest("smoke-v1")
SENSITIVE = "synthetic-private-diagnostic-do-not-log"


@pytest.fixture(autouse=True)
def no_external_io(monkeypatch):
    attempts = []
    def forbidden(*args, **kwargs):
        attempts.append(True)
        raise AssertionError("Lifecycle test attempted external execution or networking")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    yield
    assert not attempts, "External I/O was attempted, even if its exception was caught"


class FakeDocker:
    """Strict transport simulator, not evidence about an actual Docker engine."""

    def __init__(self):
        self.records = {}
        self.calls = []
        self.specs = []
        self.counter = 0
        self.create_hook = None
        self.inspect_hook = None
        self.remove_hook = None

    def create(self, spec, *, timeout):
        assert type(spec) is ContainerJobSpec
        assert timeout == API_TIMEOUT_SECONDS
        self.calls.append(("create", spec.name))
        self.specs.append(spec)
        if self.create_hook:
            return self.create_hook(self, spec)
        return self.store(spec)

    def store(self, spec):
        self.counter += 1
        container_id = f"{self.counter:064x}"
        config = spec.create_body()
        host = config.pop("HostConfig")
        self.records[container_id] = {
            "Id": container_id, "Name": "/" + spec.name, "Image": LOCAL_IMAGE_ID,
            "Config": config, "HostConfig": host,
            "State": {"Status": "created", "Running": False, "Paused": False,
                      "Restarting": False, "Dead": False, "Pid": 0},
            "Mounts": [], "NetworkSettings": {"Ports": {}, "Networks": {"none": {}}},
            "AppArmorProfile": "docker-default",
        }
        return container_id

    def inspect(self, reference, *, timeout):
        assert timeout == API_TIMEOUT_SECONDS
        self.calls.append(("inspect", reference))
        if self.inspect_hook:
            self.inspect_hook(self, reference)
        if reference in self.records:
            return deepcopy(self.records[reference])
        for metadata in self.records.values():
            if metadata["Name"] == "/" + reference:
                return deepcopy(metadata)
        raise ContainerNotFound()

    def remove(self, container_id, *, force, timeout):
        assert force is True and timeout == API_TIMEOUT_SECONDS
        assert len(container_id) == 64 and container_id in self.records
        self.calls.append(("remove", container_id))
        if self.remove_hook:
            return self.remove_hook(self, container_id)
        del self.records[container_id]


def enter(adapter):
    with adapter.prepared(REQUEST):
        pass


def removals(fake):
    return [reference for operation, reference in fake.calls if operation == "remove"]


def assert_error(adapter, code):
    with pytest.raises(RunnerLifecycleError) as caught:
        enter(adapter)
    assert caught.value.code == code
    assert str(caught.value) == f"Runner lifecycle failed: {code.value}."
    return adapter.last_receipt


def test_fixed_spec_security_fields_and_server_generated_identity(monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", SENSITIVE)
    monkeypatch.setenv("SHEETSAFE_RUNNER_IMAGE", "untrusted:latest")
    spec = ContainerJobSpec.for_fixture(REQUEST)
    other = ContainerJobSpec.for_fixture(REQUEST)
    assert len(spec.job_id) == len(spec.ownership_nonce) == 32
    assert spec.job_id != other.job_id and spec.ownership_nonce != other.ownership_nonce
    assert spec.name == "sheetsafe-smoke-" + spec.job_id
    assert spec.platform == "linux/amd64" and spec.image_id == LOCAL_IMAGE_ID
    body = spec.create_body()
    assert body["Image"] == "sha256:551ae45bad03b4a1856ae503c62c01a8078394a19d3c318b53fc9f2e98f66bc9"
    assert body["User"] == "10001:10001"
    assert body["Entrypoint"] == ["/usr/local/bin/python", "-I", "-S", "-B", "-u", "/opt/sheetsafe/bootstrap.py"]
    assert body["Cmd"] == ["smoke-v1"]
    assert set(body["Env"]) == {"LANG=C.UTF-8", "HOME=/nonexistent", "PATH=/usr/local/bin:/usr/bin:/bin"}
    assert not body["Volumes"] and not body["ExposedPorts"]
    assert body["NetworkDisabled"] and not body["OpenStdin"] and not body["Tty"]
    host = body["HostConfig"]
    assert host["CapDrop"] == ["ALL"] and host["CapAdd"] == []
    assert host["SecurityOpt"] == ["no-new-privileges=true"]
    assert host["NetworkMode"] == "none" and host["ReadonlyRootfs"] is True
    assert host["Tmpfs"] == {
        "/work": "rw,nodev,nosuid,noexec,size=268435456,uid=10001,gid=10001,mode=700",
        "/tmp": "rw,nodev,nosuid,noexec,size=67108864,uid=10001,gid=10001,mode=700",
    }
    assert (host["CpuPeriod"], host["CpuQuota"]) == (100000, 100000)
    assert host["Memory"] == host["MemorySwap"] == 1073741824
    assert host["PidsLimit"] == 32 and host["PidMode"] == "" and host["IpcMode"] == "private"
    assert host["CgroupnsMode"] == "private" and host["Privileged"] is False
    for key in ("Binds", "Mounts", "VolumesFrom", "Devices", "DeviceRequests", "DeviceCgroupRules"):
        assert host[key] == []
    assert host["LogConfig"] == {"Type": "none", "Config": {}}
    assert host["AutoRemove"] is False and host["RestartPolicy"]["Name"] == "no"
    assert SENSITIVE not in repr(body)


@pytest.mark.parametrize("name", [item.name for item in fields(ContainerJobSpec)] + ["command", "mounts", "privileged", "policy"])
def test_job_spec_has_no_override_constructor(name):
    with pytest.raises(TypeError):
        ContainerJobSpec(**{name: SENSITIVE})


def test_spec_is_frozen_and_request_bodies_do_not_share_mutable_state():
    spec = ContainerJobSpec.for_fixture(REQUEST)
    with pytest.raises(FrozenInstanceError):
        spec.image_id = "bad:latest"
    body = spec.create_body()
    body["HostConfig"]["Privileged"] = True
    body["Labels"]["io.sheetsafe.owner"] = "other"
    assert spec.create_body()["HostConfig"]["Privileged"] is False
    assert spec.labels["io.sheetsafe.owner"] == spec.ownership_nonce


@pytest.mark.parametrize("payload", [None, "smoke-v1", {}, {"fixture_id": "smoke-v1", "image": "bad"}])
def test_invalid_requests_make_no_transport_calls(payload):
    fake = FakeDocker()
    with pytest.raises(RunnerPolicyError):
        with DockerLifecycleAdapter(fake).prepared(payload):
            pytest.fail("Invalid request admitted")
    assert fake.calls == []


def test_stopped_lifecycle_and_verified_removal():
    fake = FakeDocker()
    adapter = DockerLifecycleAdapter(fake)
    with adapter.prepared(REQUEST) as prepared:
        assert prepared.state == LifecycleState.CONFIGURATION_VERIFIED
        assert prepared.configuration_verified and not prepared.cleanup_confirmed
        assert not prepared.execution_enabled and len(prepared.unverified_controls) == 10
        assert fake.records[prepared.container_id]["State"]["Status"] == "created"
        with pytest.raises(RunnerNotReady):
            require_execution_ready()
    receipt = adapter.last_receipt
    assert receipt.state == LifecycleState.ABSENT and receipt.cleanup_confirmed
    assert receipt.outcome == JobOutcome.CONFIGURATION_ONLY and receipt.failure is None
    assert not adapter.admissions_blocked and not fake.records
    assert removals(fake) == [receipt.container_id]
    assert fake.calls[-2:] == [("inspect", receipt.container_id), ("inspect", fake.specs[0].name)]


@pytest.mark.parametrize("section,key,value", [
    ("Config", "Image", "other:latest"), ("Config", "User", "0:0"),
    ("Config", "Cmd", ["sh"]), ("Config", "Entrypoint", ["/bin/sh"]),
    ("Config", "Env", ["LANG=C.UTF-8", "PRIVATE=synthetic"]),
    ("Config", "WorkingDir", "/"), ("Config", "Volumes", {"/host": {}}),
    ("Config", "OpenStdin", True), ("Config", "Tty", True),
    ("HostConfig", "Privileged", True), ("HostConfig", "Privileged", 0),
    ("HostConfig", "ReadonlyRootfs", False), ("HostConfig", "CapDrop", []),
    ("HostConfig", "CapAdd", ["SYS_ADMIN"]),
    ("HostConfig", "SecurityOpt", ["seccomp=unconfined"]),
    ("HostConfig", "NetworkMode", "host"), ("HostConfig", "PublishAllPorts", True),
    ("HostConfig", "PortBindings", {"8000/tcp": [{"HostPort": "8000"}]}),
    ("HostConfig", "Dns", ["1.1.1.1"]), ("HostConfig", "ExtraHosts", ["host:1.2.3.4"]),
    ("HostConfig", "Tmpfs", {}), ("HostConfig", "CpuQuota", -1),
    ("HostConfig", "CpuPeriod", 200000), ("HostConfig", "NanoCpus", 2000000000),
    ("HostConfig", "Memory", 0), ("HostConfig", "MemorySwap", -1),
    ("HostConfig", "PidsLimit", 0), ("HostConfig", "PidMode", "host"),
    ("HostConfig", "IpcMode", "host"), ("HostConfig", "CgroupnsMode", "host"),
    ("HostConfig", "Binds", ["/:/host"]), ("HostConfig", "VolumesFrom", ["other"]),
    ("HostConfig", "Mounts", [{"Source": "/var/run/docker.sock", "Target": "/socket"}]),
    ("HostConfig", "Devices", [{"PathOnHost": "/dev/sda"}]),
    ("HostConfig", "DeviceRequests", [{"Count": -1}]),
    ("HostConfig", "AutoRemove", True), ("HostConfig", "Runtime", "other"),
    ("HostConfig", "LogConfig", {"Type": "json-file", "Config": {}}),
    ("HostConfig", "RestartPolicy", {"Name": "always", "MaximumRetryCount": 0}),
    ("State", "Running", True), ("State", "Status", "running"),
    ("State", "Pid", 1234), ("State", "Dead", True),
])
def test_weakened_or_unexpected_configuration_rejected_and_owned_container_cleaned(section, key, value):
    fake = FakeDocker()
    def create(fake, spec):
        identity = fake.store(spec)
        fake.records[identity][section][key] = value
        return identity
    fake.create_hook = create
    adapter = DockerLifecycleAdapter(fake)
    receipt = assert_error(adapter, FailureCode.POLICY_MISMATCH)
    assert receipt.cleanup_confirmed and not fake.records and len(removals(fake)) == 1


@pytest.mark.parametrize("key,value", [
    ("Image", "sha256:" + "f" * 64), ("Mounts", [{"Type": "bind", "Source": "/host"}]),
    ("NetworkSettings", {"Ports": {}, "Networks": {"bridge": {}}}),
    ("AppArmorProfile", "unconfined"), ("Unexpected", SENSITIVE),
])
def test_unexpected_metadata_is_not_ignored(key, value):
    fake = FakeDocker()
    def create(fake, spec):
        identity = fake.store(spec)
        fake.records[identity][key] = value
        return identity
    fake.create_hook = create
    receipt = assert_error(DockerLifecycleAdapter(fake), FailureCode.POLICY_MISMATCH)
    assert receipt.cleanup_confirmed


def test_actual_step7b_inherited_environment_remains_a_runtime_admission_blocker():
    fake = FakeDocker()
    def create(fake, spec):
        identity = fake.store(spec)
        # These public names were actually found in the built base image.
        fake.records[identity]["Config"]["Env"] += [
            "GPG_KEY=public-signing-identity", "PYTHON_VERSION=3.12.15", "PYTHON_SHA256=public-release-hash",
        ]
        return identity
    fake.create_hook = create
    assert_error(DockerLifecycleAdapter(fake), FailureCode.POLICY_MISMATCH)


def test_definite_failed_creation_is_not_claimed_as_removed():
    fake = FakeDocker()
    def reject(fake, spec):
        raise CreateRejected(SENSITIVE)
    fake.create_hook = reject
    adapter = DockerLifecycleAdapter(fake)
    receipt = assert_error(adapter, FailureCode.CREATE_FAILED)
    assert receipt.state == LifecycleState.ABSENT and receipt.cleanup_confirmed
    assert not receipt.configuration_verified and receipt.container_id is None
    assert not adapter.admissions_blocked and not removals(fake)


@pytest.mark.parametrize("created", [False, True])
def test_ambiguous_create_failure_recovers_only_owned_identity_or_blocks(created):
    fake = FakeDocker()
    def lost_response(fake, spec):
        if created:
            fake.store(spec)
        raise TimeoutError(SENSITIVE)
    fake.create_hook = lost_response
    adapter = DockerLifecycleAdapter(fake)
    receipt = assert_error(adapter, FailureCode.CREATE_FAILED)
    assert receipt.cleanup_confirmed is created
    assert adapter.admissions_blocked is not created
    assert len(removals(fake)) == int(created)


@pytest.mark.parametrize("invalid", [None, "", "a" * 12, "A" * 64, "g" * 64, "a" * 64 + "\n", "--force", ["a" * 64]])
def test_invalid_create_id_rejected_without_untrusted_target_lookup(invalid):
    fake = FakeDocker()
    fake.create_hook = lambda fake, spec: invalid
    adapter = DockerLifecycleAdapter(fake)
    receipt = assert_error(adapter, FailureCode.INVALID_IDENTITY)
    assert not receipt.cleanup_confirmed and adapter.admissions_blocked
    assert not removals(fake)
    assert fake.calls == [("create", fake.specs[0].name), ("inspect", fake.specs[0].name)]


def test_malformed_create_result_can_recover_by_reserved_name_without_using_bad_id():
    fake = FakeDocker()
    def create(fake, spec):
        fake.store(spec)
        return "--bad-id"
    fake.create_hook = create
    receipt = assert_error(DockerLifecycleAdapter(fake), FailureCode.INVALID_IDENTITY)
    assert receipt.cleanup_confirmed and len(removals(fake)) == 1
    assert not any(reference == "--bad-id" for _, reference in fake.calls)


@pytest.mark.parametrize("field", ["name", "job", "owner", "id"])
def test_foreign_or_inconsistent_ownership_is_never_removed(field):
    fake = FakeDocker()
    def create(fake, spec):
        identity = fake.store(spec)
        if field == "name":
            fake.records[identity]["Name"] = "/foreign"
        elif field == "id":
            fake.records[identity]["Id"] = "f" * 64
        else:
            fake.records[identity]["Config"]["Labels"]["io.sheetsafe." + field] = "foreign"
        return identity
    fake.create_hook = create
    adapter = DockerLifecycleAdapter(fake)
    receipt = assert_error(adapter, FailureCode.INVALID_IDENTITY)
    assert not receipt.cleanup_confirmed and adapter.admissions_blocked and not removals(fake)


def test_duplicate_id_is_not_removed_again_and_blocks_admission():
    fake = FakeDocker()
    adapter = DockerLifecycleAdapter(fake)
    enter(adapter)
    old_id = adapter.last_receipt.container_id
    fake.create_hook = lambda fake, spec: old_id
    assert_error(adapter, FailureCode.DUPLICATE_IDENTITY)
    assert removals(fake) == [old_id]
    assert adapter.admissions_blocked


def test_inspect_api_failure_cleans_owned_container_and_sanitizes_errors(caplog, capsys):
    fake = FakeDocker()
    failed = False
    def inspect(fake, reference):
        nonlocal failed
        if not failed:
            failed = True
            raise RuntimeError(SENSITIVE)
    fake.inspect_hook = inspect
    receipt = assert_error(DockerLifecycleAdapter(fake), FailureCode.INSPECT_FAILED)
    assert receipt.cleanup_confirmed and len(removals(fake)) == 1
    assert SENSITIVE not in repr(receipt) + caplog.text + repr(capsys.readouterr())


@pytest.mark.parametrize("mode", ["exception", "noop", "verification-error", "removed-then-error", "replacement"])
def test_removal_requires_explicit_absence_and_preserves_api_errors(mode):
    fake = FakeDocker()
    def remove(fake, identity):
        if mode == "exception":
            raise RuntimeError(SENSITIVE)
        if mode == "noop":
            return
        del fake.records[identity]
        if mode == "removed-then-error":
            raise RuntimeError(SENSITIVE)
        if mode == "replacement":
            fake.store(fake.specs[-1])  # Do not delete a replacement by name.
        if mode == "verification-error":
            def fail(fake, reference):
                raise RuntimeError(SENSITIVE)
            fake.inspect_hook = fail
    fake.remove_hook = remove
    adapter = DockerLifecycleAdapter(fake)
    receipt = assert_error(adapter, FailureCode.REMOVE_FAILED if mode in {"exception", "removed-then-error"} else FailureCode.CLEANUP_UNRESOLVED)
    assert receipt.cleanup_confirmed is (mode == "removed-then-error")
    assert adapter.admissions_blocked is (mode != "removed-then-error")
    assert len(removals(fake)) == 1
    if adapter.admissions_blocked:
        before = list(fake.calls)
        assert_error(adapter, FailureCode.ADMISSIONS_BLOCKED)
        assert fake.calls == before and adapter.last_receipt == receipt


@pytest.mark.parametrize("exception", [ValueError(SENSITIVE), CancelledError(), KeyboardInterrupt(), GeneratorExit()])
def test_scope_failure_and_cancellation_always_cleanup(exception):
    fake = FakeDocker()
    adapter = DockerLifecycleAdapter(fake)
    expected = RunnerLifecycleError if isinstance(exception, Exception) else type(exception)
    with pytest.raises(expected):
        with adapter.prepared(REQUEST):
            raise exception
    receipt = adapter.last_receipt
    assert receipt.cleanup_confirmed and not fake.records and len(removals(fake)) == 1
    assert receipt.outcome == (JobOutcome.FAILED if isinstance(exception, Exception) else JobOutcome.CANCELLED)


def test_cancelled_create_recovers_after_lost_response():
    fake = FakeDocker()
    def cancel(fake, spec):
        fake.store(spec)
        raise CancelledError()
    fake.create_hook = cancel
    adapter = DockerLifecycleAdapter(fake)
    with pytest.raises(CancelledError):
        enter(adapter)
    assert adapter.last_receipt.cleanup_confirmed and not fake.records
    assert adapter.last_receipt.outcome == JobOutcome.CANCELLED


def test_cancellation_is_preserved_when_cleanup_is_unresolved():
    fake = FakeDocker()
    fake.remove_hook = lambda fake, identity: None
    adapter = DockerLifecycleAdapter(fake)
    with pytest.raises(CancelledError):
        with adapter.prepared(REQUEST):
            raise CancelledError()
    assert adapter.admissions_blocked
    assert adapter.last_receipt.failure == FailureCode.CANCELLED
    assert adapter.last_receipt.cleanup_failure == FailureCode.CLEANUP_UNRESOLVED


@pytest.mark.parametrize("removed", [False, True])
def test_cancellation_during_removal_has_accurate_state_and_outcome(removed):
    fake = FakeDocker()
    def cancel(fake, identity):
        if removed:
            del fake.records[identity]
        raise CancelledError()
    fake.remove_hook = cancel
    adapter = DockerLifecycleAdapter(fake)
    with pytest.raises(CancelledError):
        enter(adapter)
    receipt = adapter.last_receipt
    assert receipt.outcome == JobOutcome.CANCELLED and receipt.failure == FailureCode.CANCELLED
    assert receipt.cleanup_confirmed is removed
    assert adapter.admissions_blocked is not removed
    assert receipt.cleanup_failure == FailureCode.REMOVE_FAILED


def test_another_adapters_container_is_never_removed():
    fake = FakeDocker()
    first = DockerLifecycleAdapter(fake)
    second = DockerLifecycleAdapter(fake)
    with first.prepared(REQUEST) as prepared:
        fake.create_hook = lambda fake, spec: prepared.container_id
        receipt = assert_error(second, FailureCode.INVALID_IDENTITY)
        assert not receipt.cleanup_confirmed and second.admissions_blocked
        assert not removals(fake) and prepared.container_id in fake.records
    assert removals(fake) == [prepared.container_id]
    assert first.last_receipt.cleanup_confirmed


def test_nested_admission_is_rejected_without_double_removal():
    fake = FakeDocker()
    adapter = DockerLifecycleAdapter(fake)
    with adapter.prepared(REQUEST):
        assert_error(adapter, FailureCode.JOB_ACTIVE)
    assert len(removals(fake)) == 1 and not adapter.admissions_blocked


def test_concurrent_admission_cannot_replace_active_job():
    fake = FakeDocker()
    adapter = DockerLifecycleAdapter(fake)
    active = Event()
    release = Event()
    errors = []
    def worker():
        try:
            with adapter.prepared(REQUEST):
                active.set()
                assert release.wait(5)
        except BaseException as error:
            errors.append(error)
    thread = Thread(target=worker)
    thread.start()
    try:
        assert active.wait(5)
        assert_error(adapter, FailureCode.JOB_ACTIVE)
    finally:
        release.set()
        thread.join(5)
    assert not thread.is_alive() and not errors
    assert len(removals(fake)) == 1 and not fake.records


def test_sequential_jobs_have_fresh_names_and_no_public_remove_or_start_api():
    fake = FakeDocker()
    adapter = DockerLifecycleAdapter(fake)
    for _ in range(2):
        enter(adapter)
    assert fake.specs[0].job_id != fake.specs[1].job_id
    assert fake.specs[0].name != fake.specs[1].name
    assert len(set(removals(fake))) == 2
    for name in ("start", "exec", "run", "remove", "reset"):
        assert not hasattr(adapter, name)


def test_adapter_import_has_no_external_io(monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "runner_adapter_import_probe", Path(__file__).resolve().parents[1] / "runner/docker_backend.py",
    )
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    assert module.LOCAL_IMAGE_ID == LOCAL_IMAGE_ID
