"""Synthetic Engine responses only. No Docker daemon calls or container payloads."""

from copy import deepcopy
from dataclasses import FrozenInstanceError
import io
import json
import subprocess

import pytest

from runner.docker_backend import ContainerJobSpec, LOCAL_IMAGE_ID, verify_configuration
from runner.engine_metadata import (
    LOCAL_CONFIG_DIGEST, MetadataError, map_container, parse_engine, parse_image,
)
from runner.policy import FixtureRequest, SandboxPolicy
from runner import preflight


PRIVATE = "synthetic-private-error-never-publish"
READ_INFO = ["--context", "desktop-linux", "info", "--format", "{{json .}}"]


def version_response():
    return {"Client": {"Version": "29.9.1", "ApiVersion": "1.56"}, "Server": {
        "Version": "29.9.1", "ApiVersion": "1.56", "MinAPIVersion": "1.40", "Os": "linux", "Arch": "amd64"}}


def info_response():
    return {"OSType": "linux", "Architecture": "x86_64", "CgroupVersion": "2", "CgroupDriver": "cgroupfs",
        "MemoryLimit": True, "SwapLimit": True, "CpuCfsPeriod": True, "CpuCfsQuota": True, "PidsLimit": True,
        "SecurityOptions": ["name=seccomp,profile=builtin", "name=cgroupns", "name=apparmor"],
        "DefaultRuntime": "runc", "Runtimes": {"runc": {"path": "runc"}}, "Warnings": None}


def image_response():
    # Synthetic target metadata, NOT the actual Step 7B environment (tested below).
    policy = SandboxPolicy()
    return {"Id": LOCAL_IMAGE_ID, "Os": "linux", "Architecture": "amd64", "RepoDigests": [],
        "Descriptor": {"digest": LOCAL_IMAGE_ID, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                       "annotations": {"config.digest": LOCAL_CONFIG_DIGEST}},
        "Config": {"User": "10001:10001", "Entrypoint": list(policy.entrypoint), "Cmd": ["smoke-v1"],
            "WorkingDir": "/work", "StopSignal": "SIGTERM", "Env": [f"{k}={v}" for k, v in policy.environment]}}


def native_response(spec):
    identity = "1" * 64
    body = spec.create_body()
    host = body.pop("HostConfig")
    host.update({"MaskedPaths": ["/proc/acpi", "/proc/asound", "/proc/interrupts", "/proc/kcore",
        "/proc/keys", "/proc/latency_stats", "/proc/sched_debug", "/proc/scsi", "/proc/timer_list",
        "/proc/timer_stats", "/sys/devices/virtual/powercap", "/sys/firmware"],
        "ReadonlyPaths": ["/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"],
        "ShmSize": 67108864, "MemoryReservation": 0, "Ulimits": None})
    # Actual Engine-style optional/default/null encodings, not just 7C's projection.
    host["Binds"] = None
    host["CapAdd"] = None
    host["SecurityOpt"] = ["no-new-privileges"]
    body.update({"Hostname": identity[:12], "Domainname": "", "AttachStdin": False,
                 "AttachStdout": False, "AttachStderr": False})
    body["Env"].reverse()
    return {"Id": identity, "Name": "/" + spec.name, "Image": LOCAL_CONFIG_DIGEST,
        "Config": body, "HostConfig": host, "State": {"Status": "created", "Running": False,
            "Paused": False, "Restarting": False, "Dead": False, "Pid": 0, "OOMKilled": False,
            "ExitCode": 0, "Error": "", "StartedAt": "0001-01-01T00:00:00Z", "FinishedAt": "0001-01-01T00:00:00Z"},
        "Mounts": [], "NetworkSettings": {"Ports": None, "SandboxID": "", "SandboxKey": "", "Networks": {
            "none": {"IPAMConfig": None, "Links": None, "Aliases": None, "NetworkID": "2" * 64,
                "EndpointID": "", "Gateway": "", "IPAddress": "", "IPPrefixLen": 0}}},
        "AppArmorProfile": "docker-default", "Platform": "linux", "RestartCount": 0,
        "Path": "/usr/local/bin/python", "Args": [*SandboxPolicy().entrypoint[1:], "smoke-v1"]}


class FakeReader:
    def __init__(self, fail=None):
        self.fail = fail
        self.calls = []

    def read(self, name, value):
        self.calls.append(name)
        if self.fail == name:
            raise RuntimeError(PRIVATE)
        return value

    def channel(self):
        return self.read("channel", {"Host": "npipe:////./pipe/dockerDesktopLinuxEngine", "SkipTLSVerify": False})

    def version(self):
        return self.read("version", version_response())

    def info(self):
        return self.read("info", info_response())

    def image(self):
        return self.read("image", image_response())


@pytest.fixture(autouse=True)
def no_real_process(monkeypatch):
    attempts = []
    def forbidden(*args, **kwargs):
        attempts.append(True)
        raise AssertionError("Unexpected actual process launch")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    yield
    assert not attempts


def test_valid_preflight_is_never_execution_readiness():
    reader = FakeReader()
    report = preflight.run_preflight(reader)
    assert report.metadata_prerequisites_met and report.engine.seccomp_builtin
    assert reader.calls == ["channel", "version", "info", "image"]
    assert report.image.local_image_id == LOCAL_IMAGE_ID
    assert report.image.config_digest == LOCAL_CONFIG_DIGEST
    assert report.image.verified_registry_digest is report.image.final_approved_identity is None
    assert not report.execution_enabled and len(report.unverified_controls) == 10


@pytest.mark.parametrize("field", list(info_response()))
def test_engine_missing_required_field_rejected(field):
    info = info_response()
    del info[field]
    with pytest.raises(MetadataError):
        parse_engine(version_response(), info)


@pytest.mark.parametrize("field", ["MemoryLimit", "SwapLimit", "CpuCfsPeriod", "CpuCfsQuota", "PidsLimit"])
def test_unsupported_resource_capability(field):
    info = info_response()
    info[field] = False
    assert parse_engine(version_response(), info).issues
    info[field] = 1
    with pytest.raises(MetadataError):
        parse_engine(version_response(), info)


@pytest.mark.parametrize("options,issue", [
    (["name=cgroupns", "name=apparmor"], "BUILTIN_SECCOMP_REQUIRED"),
    (["name=seccomp,profile=unconfined", "name=apparmor"], "SECURITY_OPTIONS_UNSUPPORTED"),
    (["name=seccomp,profile=builtin", "name=cgroupns"], "LSM_NOT_ADVERTISED"),
    (["name=seccomp,profile=builtin", "name=cgroupns", "name=selinux"], "LSM_MAPPING_UNSUPPORTED"),
])
def test_seccomp_lsm_prerequisites(options, issue):
    info = info_response()
    info["SecurityOptions"] = options
    assert issue in parse_engine(version_response(), info).issues


@pytest.mark.parametrize("section,field,value,issue", [
    ("info", "OSType", "windows", "LINUX_REQUIRED"),
    ("info", "Architecture", "aarch64", "ARCHITECTURE_UNSUPPORTED"),
    ("info", "CgroupVersion", "1", "CGROUP_UNSUPPORTED"),
    ("info", "DefaultRuntime", "nvidia", "RUNTIME_UNSUPPORTED"),
    ("info", "Warnings", [PRIVATE], "ENGINE_WARNINGS_PRESENT"),
    ("server", "ApiVersion", "1.45", "API_UNSUPPORTED"),
    ("server", "MinAPIVersion", "1.57", "API_UNSUPPORTED"),
])
def test_platform_api_and_runtime_blockers(section, field, value, issue):
    version, info = version_response(), info_response()
    (info if section == "info" else version["Server"])[field] = value
    result = parse_engine(version, info)
    assert issue in result.issues and PRIVATE not in repr(result)


def test_rootless_and_userns_are_advertisement_not_verified_delegation():
    info = info_response()
    info["SecurityOptions"] += ["name=rootless", "name=userns"]
    facts = parse_engine(version_response(), info)
    assert facts.rootless_advertised and facts.userns_advertised


@pytest.mark.parametrize("host", ["tcp://localhost:2375", "ssh://operator@host", "unix:///tmp/other.sock", "npipe:////./pipe/docker_engine", None])
def test_unsupported_control_channel_stops_before_engine_queries(host):
    reader = FakeReader()
    reader.channel = lambda: {"Host": host, "SkipTLSVerify": False}
    report = preflight.run_preflight(reader)
    assert report.issues == ("CONTROL_CHANNEL_UNAVAILABLE",) and not reader.calls


@pytest.mark.parametrize("host", ["unix:///var/run/docker.sock", "unix:///run/user/1000/docker.sock"])
def test_reviewed_linux_local_channels(host):
    assert preflight.validate_channel({"Host": host, "SkipTLSVerify": False}) == "local-unix"


@pytest.mark.parametrize("failure", ["channel", "version", "info", "image"])
def test_engine_communication_errors_are_sanitized(failure, caplog):
    report = preflight.run_preflight(FakeReader(failure))
    assert report.issues and not report.metadata_prerequisites_met
    assert PRIVATE not in repr(report) + caplog.text


@pytest.mark.parametrize("field", ["Id", "Descriptor", "Os", "Architecture", "RepoDigests", "Config"])
def test_missing_required_image_metadata(field):
    image = image_response()
    del image[field]
    with pytest.raises(MetadataError):
        parse_image(image)


@pytest.mark.parametrize("section,key,value", [
    (None, "Id", "sha256:" + "f" * 64), (None, "Architecture", "arm64"),
    ("Config", "User", "0:0"), ("Config", "Entrypoint", ["sh"]),
    ("Config", "Cmd", ["arbitrary"]), ("Descriptor", "digest", LOCAL_CONFIG_DIGEST),
])
def test_image_identity_and_startup_mismatch(section, key, value):
    image = image_response()
    (image if section is None else image[section])[key] = value
    with pytest.raises(MetadataError):
        parse_image(image)


def test_actual_inherited_environment_is_blocked_and_repo_digest_is_not_promoted():
    image = image_response()
    image["Config"]["Env"] += ["GPG_KEY=public", "PYTHON_VERSION=3.12.15", "PYTHON_SHA256=public"]
    image["RepoDigests"] = ["sheetsafe-runner@" + LOCAL_IMAGE_ID]
    result = parse_image(image)
    assert result.issues == ("IMAGE_ENVIRONMENT_MISMATCH",)
    assert result.reported_repo_digests == ("sheetsafe-runner@" + LOCAL_IMAGE_ID,)
    assert result.verified_registry_digest is result.final_approved_identity is None
    image["Config"]["Env"].append("LANG=duplicate")
    with pytest.raises(MetadataError):
        parse_image(image)


@pytest.fixture
def mapping_case():
    spec = ContainerJobSpec.for_fixture(FixtureRequest("smoke-v1"))
    return native_response(spec), spec, parse_engine(version_response(), info_response()), parse_image(image_response())


def test_native_mapping_preserves_identity_binding_and_existing_lifecycle_contract(mapping_case):
    raw, spec, engine, image = mapping_case
    original = deepcopy(raw)
    facts = map_container(raw, spec, engine, image)
    assert raw == original and facts.native_image_id == LOCAL_CONFIG_DIGEST
    assert facts.local_image_id == LOCAL_IMAGE_ID and not facts.execution_enabled
    projection = facts.lifecycle_projection()
    verify_configuration(projection, spec, raw["Id"])
    projection["HostConfig"]["Privileged"] = True
    assert facts.lifecycle_projection()["HostConfig"]["Privileged"] is False
    with pytest.raises(FrozenInstanceError):
        facts.local_image_id = "other"


REQUIRED_CONFIG = list(ContainerJobSpec().create_body())
REQUIRED_CONFIG.remove("HostConfig")
REQUIRED_HOST = list(ContainerJobSpec().create_body()["HostConfig"]) + ["MaskedPaths", "ReadonlyPaths"]


@pytest.mark.parametrize("section,key", [(None, name) for name in (
    "Id", "Name", "Image", "Config", "HostConfig", "State", "Mounts", "NetworkSettings", "AppArmorProfile")]
    + [("Config", key) for key in REQUIRED_CONFIG] + [("HostConfig", key) for key in REQUIRED_HOST]
    + [("State", key) for key in ("Status", "Running", "Paused", "Restarting", "Dead", "Pid")])
def test_every_required_native_security_field_is_mandatory(mapping_case, section, key):
    raw, spec, engine, image = mapping_case
    del (raw if section is None else raw[section])[key]
    with pytest.raises(MetadataError):
        map_container(raw, spec, engine, image)


@pytest.mark.parametrize("section,key,value", [
    (None, "Image", "sha256:" + "f" * 64), (None, "Name", "/foreign"), (None, "Id", "short"),
    (None, "AppArmorProfile", "unconfined"), (None, "Unexpected", PRIVATE),
    (None, "Mounts", [{"Type": "bind", "Source": "/var/run/docker.sock"}]),
    ("Config", "Image", "sheetsafe-runner:smoke-v1"), ("Config", "User", "root"),
    ("Config", "Cmd", ["sh"]), ("Config", "Env", ["PRIVATE=synthetic"]),
    ("HostConfig", "Privileged", True), ("HostConfig", "Privileged", 0),
    ("HostConfig", "CapAdd", ["SYS_ADMIN"]), ("HostConfig", "CapDrop", []),
    ("HostConfig", "SecurityOpt", ["seccomp=unconfined"]),
    ("HostConfig", "NetworkMode", "host"), ("HostConfig", "PidMode", "host"),
    ("HostConfig", "IpcMode", "shareable"), ("HostConfig", "CgroupnsMode", "host"),
    ("HostConfig", "Binds", ["/var/run/docker.sock:/socket"]),
    ("HostConfig", "Mounts", [{"Type": "volume"}]), ("HostConfig", "ReadonlyRootfs", False),
    ("HostConfig", "Tmpfs", {}), ("HostConfig", "CpuQuota", -1),
    ("HostConfig", "Memory", 0), ("HostConfig", "MemorySwap", -1), ("HostConfig", "PidsLimit", 0),
    ("HostConfig", "ReadonlyPaths", []), ("HostConfig", "MaskedPaths", []),
    ("HostConfig", "Unexpected", PRIVATE), ("State", "Running", True), ("State", "Pid", 5),
])
def test_native_weakened_or_unknown_fields_rejected(mapping_case, section, key, value):
    raw, spec, engine, image = mapping_case
    (raw if section is None else raw[section])[key] = value
    with pytest.raises(MetadataError):
        map_container(raw, spec, engine, image)


def test_unknown_endpoint_routes_and_unsafe_mask_paths_rejected(mapping_case):
    raw, spec, engine, image = mapping_case
    raw["NetworkSettings"]["Networks"]["none"]["IPAddress"] = "192.0.2.10"
    with pytest.raises(MetadataError):
        map_container(raw, spec, engine, image)
    raw["NetworkSettings"]["Networks"]["none"]["IPAddress"] = ""
    raw["HostConfig"]["MaskedPaths"].append("/sys/devices/system/cpu/cpu0/thermal_throttle")
    assert map_container(raw, spec, engine, image).masked_paths[-1].endswith("thermal_throttle")
    raw["HostConfig"]["MaskedPaths"].append("/etc/passwd")
    with pytest.raises(MetadataError):
        map_container(raw, spec, engine, image)


def test_prerequisite_failure_prevents_mapping(mapping_case):
    raw, spec, _, image = mapping_case
    info = info_response()
    info["SecurityOptions"].remove("name=apparmor")
    with pytest.raises(MetadataError):
        map_container(raw, spec, parse_engine(version_response(), info), image)


def test_client_has_only_fixed_read_commands_and_no_mutations(monkeypatch):
    commands = []
    def capture(arguments):
        commands.append(arguments)
        if arguments[0] == "context":
            return {"Host": "npipe:////./pipe/dockerDesktopLinuxEngine", "SkipTLSVerify": False}
        if "image" in arguments:
            return [image_response()]
        return version_response() if "version" in arguments else info_response()
    monkeypatch.setattr(preflight, "_capture", capture)
    client = preflight.DockerReadOnlyClient(preflight.LocalContext.DESKTOP_LINUX)
    assert preflight.run_preflight(client).metadata_prerequisites_met
    assert len(commands) == 7
    for command in commands:
        assert not set(command) & {"create", "start", "stop", "rm", "run", "exec", "build", "pull", "push", "update"}
    assert commands[-1] == ["--context", "desktop-linux", "image", "inspect", LOCAL_IMAGE_ID]
    for name in ("create", "start", "stop", "remove", "exec"):
        assert not hasattr(client, name)
    with pytest.raises(preflight.QueryError):
        preflight.DockerReadOnlyClient("desktop-linux; arbitrary")


class FakeProcess:
    def __init__(self, stdout=b"{}", stderr=b"", code=0, timeout=False):
        self.stdout, self.stderr = io.BytesIO(stdout), io.BytesIO(stderr)
        self.returncode = code
        self.timeout = timeout
        self.killed = False

    def wait(self, *, timeout):
        if self.timeout and not self.killed:
            raise subprocess.TimeoutExpired("synthetic-read-only-cli", timeout)
        return self.returncode

    def poll(self):
        return None if self.timeout and not self.killed else self.returncode

    def kill(self):
        self.killed = True


def test_bounded_cli_uses_minimal_environment_and_argument_array(monkeypatch):
    calls = []
    monkeypatch.setenv("VULTR_API_KEY", PRIVATE)
    monkeypatch.setenv("DOCKER_HOST", "tcp://untrusted:2375")
    monkeypatch.setattr(preflight.shutil, "which", lambda *args, **kwargs: "/trusted/docker")
    def popen(arguments, **kwargs):
        calls.append((arguments, kwargs))
        return FakeProcess(b'{"valid":true}')
    monkeypatch.setattr(subprocess, "Popen", popen)
    assert preflight._capture(READ_INFO) == {"valid": True}
    arguments, settings = calls[0]
    assert arguments == ["/trusted/docker", *READ_INFO] and settings["shell"] is False
    assert settings["env"]["DOCKER_API_VERSION"] == "1.56"
    assert "DOCKER_HOST" not in settings["env"] and "VULTR_API_KEY" not in settings["env"]
    assert settings["stdin"] == subprocess.DEVNULL


@pytest.mark.parametrize("mode", ["exit", "stderr", "overflow", "invalid-json", "duplicate-json", "nonfinite", "timeout"])
def test_cli_failure_output_limits_and_timeout_are_sanitized(monkeypatch, mode):
    process = FakeProcess(stdout={"overflow": b"x" * (preflight.MAX_OUTPUT_BYTES + 1),
        "invalid-json": PRIVATE.encode(), "duplicate-json": b'{"x":1,"x":2}',
        "nonfinite": b'{"x":NaN}'}.get(mode, b"{}"),
        stderr=PRIVATE.encode() if mode == "stderr" else b"", code=1 if mode == "exit" else 0,
        timeout=mode == "timeout")
    monkeypatch.setattr(preflight.shutil, "which", lambda *args, **kwargs: "/trusted/docker")
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: process)
    with pytest.raises(preflight.QueryError) as caught:
        preflight._capture(READ_INFO)
    assert PRIVATE not in str(caught.value)
    assert process.killed is (mode == "timeout")


@pytest.mark.parametrize("arguments", [
    ["run", "alpine"], ["create", "--privileged", "alpine"], ["ps"],
    ["--context", "other", "info", "--format", "{{json .}}"],
    ["--context", "desktop-linux", "image", "inspect", "other:latest"],
    [*READ_INFO, "--host=tcp://untrusted"], "info", None,
])
def test_even_internal_capture_rejects_commands_and_overrides(arguments):
    with pytest.raises(preflight.QueryError):
        preflight._capture(arguments)
