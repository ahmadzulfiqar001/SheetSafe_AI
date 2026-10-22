"""Pure, fail-closed interpretation of Engine metadata; no runtime admission."""

from dataclasses import dataclass, field
import json
import re

from runner.docker_backend import ContainerJobSpec, LOCAL_IMAGE_ID, verify_configuration
from runner.policy import SandboxPolicy


INSPECTION_API = "1.56"  # Reviewed initial schema, not a claim of all-version support.
LOCAL_CONFIG_DIGEST = "sha256:0d78a20a59527cde284674316413b4d1bd5ba66ac95a7639be6b4823fdba1965"


class MetadataError(ValueError):
    def __init__(self) -> None:
        super().__init__("Docker metadata is missing, unsupported or unsafe.")


def require(condition: bool) -> None:
    if not condition:
        raise MetadataError()


def object_value(value: object) -> dict:
    require(type(value) is dict)
    return value


def string(value: object) -> str:
    require(type(value) is str and 0 < len(value) <= 256 and not any(ord(c) < 32 for c in value))
    return value


def exact(actual: object, expected: object) -> bool:
    if type(actual) is not type(expected):
        return False
    if type(expected) is dict:
        return actual.keys() == expected.keys() and all(exact(actual[key], item) for key, item in expected.items())
    if type(expected) is list:
        return len(actual) == len(expected) and all(exact(a, b) for a, b in zip(actual, expected))
    return actual == expected


def _api(value: object) -> tuple[int, int]:
    require(type(value) is str and re.fullmatch(r"1\.[0-9]{2}", value) is not None)
    return tuple(int(part) for part in value.split("."))


def environment(value: object) -> tuple[tuple[str, str], ...]:
    require(type(value) is list and len(value) <= 32)
    result = {}
    for item in value:
        require(type(item) is str and len(item) <= 4096 and "=" in item)
        key, content = item.split("=", 1)
        require(re.fullmatch(r"[A-Z][A-Z0-9_]*", key) is not None and key not in result)
        result[key] = content
    return tuple(sorted(result.items()))


@dataclass(frozen=True, slots=True)
class EngineFacts:
    version: str
    api: str
    minimum_api: str
    os: str
    architecture: str
    cgroup_version: str
    cgroup_driver: str
    seccomp_builtin: bool
    apparmor_advertised: bool
    selinux_advertised: bool
    rootless_advertised: bool
    userns_advertised: bool
    resource_support: tuple[tuple[str, bool], ...]
    issues: tuple[str, ...]


def parse_engine(version: object, info: object) -> EngineFacts:
    root, info = object_value(version), object_value(info)
    client, server = object_value(root.get("Client")), object_value(root.get("Server"))
    engine_version = string(server.get("Version"))
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", engine_version) is not None)
    maximum, minimum = _api(server.get("ApiVersion")), _api(server.get("MinAPIVersion"))
    client_api = _api(client.get("ApiVersion"))
    issues = []
    if not minimum <= _api(INSPECTION_API) <= maximum or client_api < _api(INSPECTION_API):
        issues.append("API_UNSUPPORTED")
    os_name, arch = string(info.get("OSType")), string(info.get("Architecture"))
    string(server.get("Os"))
    string(server.get("Arch"))
    if os_name != "linux" or server.get("Os") != "linux":
        issues.append("LINUX_REQUIRED")
    if arch not in {"amd64", "x86_64"} or server.get("Arch") != "amd64":
        issues.append("ARCHITECTURE_UNSUPPORTED")
    cgroup, driver = string(info.get("CgroupVersion")), string(info.get("CgroupDriver"))
    if cgroup != "2" or driver not in {"cgroupfs", "systemd"}:
        issues.append("CGROUP_UNSUPPORTED")
    resources = []
    for name in ("MemoryLimit", "SwapLimit", "CpuCfsPeriod", "CpuCfsQuota", "PidsLimit"):
        require(type(info.get(name)) is bool)
        resources.append((name, info[name]))
        if not info[name]:
            issues.append(name.upper() + "_UNSUPPORTED")
    options = info.get("SecurityOptions")
    require(type(options) is list and len(options) <= 10 and all(type(v) is str for v in options))
    require(len(options) == len(set(options)))
    allowed = {"name=seccomp,profile=builtin", "name=apparmor", "name=selinux", "name=cgroupns", "name=rootless", "name=userns"}
    if set(options) - allowed:
        issues.append("SECURITY_OPTIONS_UNSUPPORTED")
    builtin = "name=seccomp,profile=builtin" in options
    apparmor, selinux = "name=apparmor" in options, "name=selinux" in options
    if not builtin:
        issues.append("BUILTIN_SECCOMP_REQUIRED")
    if "name=cgroupns" not in options:
        issues.append("CGROUP_NAMESPACE_REQUIRED")
    if not apparmor:
        issues.append("LSM_MAPPING_UNSUPPORTED" if selinux else "LSM_NOT_ADVERTISED")
    runtimes = object_value(info.get("Runtimes"))
    string(info.get("DefaultRuntime"))
    if "runc" in runtimes:
        runtime = object_value(runtimes["runc"])
        string(runtime.get("path"))
    if "runc" not in runtimes or info.get("DefaultRuntime") != "runc":
        issues.append("RUNTIME_UNSUPPORTED")
    # Warnings are not printed (may contain host details) and cannot be ignored.
    require("Warnings" in info and (info["Warnings"] is None or type(info["Warnings"]) is list))
    if info["Warnings"]:
        issues.append("ENGINE_WARNINGS_PRESENT")
    return EngineFacts(engine_version, server["ApiVersion"], server["MinAPIVersion"],
        os_name, arch, cgroup, driver, builtin, apparmor, selinux,
        "name=rootless" in options, "name=userns" in options, tuple(resources), tuple(issues))


@dataclass(frozen=True, slots=True)
class ImageFacts:
    local_image_id: str
    config_digest: str
    platform: str
    configured_user: str
    environment_names: tuple[str, ...]
    reported_repo_digests: tuple[str, ...]
    issues: tuple[str, ...]
    verified_registry_digest: None = field(default=None, init=False)
    final_approved_identity: None = field(default=None, init=False)


def parse_image(raw: object) -> ImageFacts:
    raw = object_value(raw)
    require(raw.get("Id") == LOCAL_IMAGE_ID)
    descriptor = object_value(raw.get("Descriptor"))
    require(descriptor.get("digest") == LOCAL_IMAGE_ID)
    require(descriptor.get("mediaType") == "application/vnd.oci.image.manifest.v1+json")
    annotations = object_value(descriptor.get("annotations"))
    require(annotations.get("config.digest") == LOCAL_CONFIG_DIGEST)
    config = object_value(raw.get("Config"))
    policy = SandboxPolicy()
    require(raw.get("Os") == "linux" and raw.get("Architecture") == "amd64")
    for name, expected in {"User": "10001:10001", "Entrypoint": list(policy.entrypoint),
            "Cmd": ["smoke-v1"], "WorkingDir": "/work", "StopSignal": "SIGTERM"}.items():
        require(exact(config.get(name), expected))
    for name in ("Volumes", "ExposedPorts", "OnBuild"):
        require(name not in config or config[name] is None or exact(config[name], {} if name != "OnBuild" else []))
    inherited = environment(config.get("Env"))
    issues = () if inherited == tuple(sorted(policy.environment)) else ("IMAGE_ENVIRONMENT_MISMATCH",)
    digests = raw.get("RepoDigests")
    require(type(digests) is list and len(digests) <= 8)
    for digest in digests:
        require(type(digest) is str and re.fullmatch(r"[a-z0-9./:_-]+@sha256:[0-9a-f]{64}", digest) is not None)
    return ImageFacts(raw["Id"], LOCAL_CONFIG_DIGEST, "linux/amd64", config["User"],
        tuple(name for name, _ in inherited), tuple(digests), issues)


# Audited native defaults, not fields to silently discard. Unknown fields fail.
HOST_DEFAULTS = {
    "ContainerIDFile": "", "ConsoleSize": [0, 0], "Cgroup": "", "CgroupParent": "",
    "GroupAdd": None, "VolumeDriver": "", "StorageOpt": None, "DnsOptions": None,
    "DnsSearch": None, "UTSMode": "", "Isolation": "", "Annotations": None,
    "CpuShares": 0, "CpusetCpus": "", "CpusetMems": "", "CpuRealtimePeriod": 0,
    "CpuRealtimeRuntime": 0, "CpuCount": 0, "CpuPercent": 0,
    "MemoryReservation": 0, "MemorySwappiness": None, "OomScoreAdj": 0,
    "BlkioWeight": 0, "BlkioWeightDevice": None, "BlkioDeviceReadBps": None,
    "BlkioDeviceWriteBps": None, "BlkioDeviceReadIOps": None, "BlkioDeviceWriteIOps": None,
    "Ulimits": None, "Init": None, "ShmSize": 67108864,
}
MASKED_PATHS = ["/proc/asound", "/proc/acpi", "/proc/interrupts", "/proc/kcore", "/proc/keys",
    "/proc/latency_stats", "/proc/timer_list", "/proc/timer_stats", "/proc/sched_debug",
    "/proc/scsi", "/sys/firmware", "/sys/devices/virtual/powercap"]
READONLY_PATHS = ["/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"]


def _review_fields(raw: dict, required: dict, optional: dict) -> dict:
    require(required.keys() <= raw.keys() and not raw.keys() - required.keys() - optional.keys())
    result = {}
    for name, expected in {**optional, **required}.items():
        if name in raw:
            value = raw[name]
            # Only reviewed Engine nil collection encodings are normalized.
            if name in required and value is None and (exact(expected, []) or exact(expected, {})):
                value = expected
            require(exact(value, expected))
            if name in required:
                result[name] = value
    return result


@dataclass(frozen=True, slots=True)
class ContainerMetadata:
    container_id: str
    native_image_id: str
    local_image_id: str
    job_id: str
    masked_paths: tuple[str, ...]
    readonly_paths: tuple[str, ...]
    serialized_projection: str = field(repr=False)
    execution_enabled: bool = field(default=False, init=False)
    unverified_controls: tuple[str, ...] = field(default=SandboxPolicy().unverified_controls, init=False)

    def lifecycle_projection(self) -> dict:
        return json.loads(self.serialized_projection)


def map_container(raw: object, spec: ContainerJobSpec, engine: EngineFacts, image: ImageFacts) -> ContainerMetadata:
    """Validate native metadata, then produce the existing lifecycle projection.

    No actual container has been inspected for this milestone. The versioned
    mapping is a conservative, fake-tested schema, never an execution permit.
    """
    require(type(spec) is ContainerJobSpec and type(engine) is EngineFacts and type(image) is ImageFacts)
    require(not engine.issues and not image.issues)
    require(image.local_image_id == spec.image_id == LOCAL_IMAGE_ID and image.config_digest == LOCAL_CONFIG_DIGEST)
    raw = object_value(raw)
    required_top = {"Id", "Name", "Image", "Config", "HostConfig", "State", "Mounts", "NetworkSettings", "AppArmorProfile"}
    optional_top = {"Created", "Path", "Args", "Platform", "RestartCount", "Driver", "ResolvConfPath",
        "HostnamePath", "HostsPath", "LogPath", "ProcessLabel", "MountLabel", "ExecIDs", "GraphDriver"}
    require(required_top <= raw.keys() and not raw.keys() - required_top - optional_top)
    container_id = raw["Id"]
    require(type(container_id) is str and re.fullmatch(r"[0-9a-f]{64}", container_id) is not None)
    require(exact(raw["Name"], "/" + spec.name) and type(raw["Image"]) is str)
    require(raw["Image"] in {spec.image_id, image.config_digest})
    for name in ("Created", "Driver", "ResolvConfPath", "HostnamePath", "HostsPath"):
        if name in raw:
            string(raw[name])  # Informational daemon metadata; never exported.
    for name, expected in {"Path": SandboxPolicy().entrypoint[0], "Args": [*SandboxPolicy().entrypoint[1:], "smoke-v1"],
            "Platform": "linux", "RestartCount": 0, "LogPath": "", "ProcessLabel": "", "MountLabel": "", "ExecIDs": None}.items():
        if name in raw:
            require(exact(raw[name], expected))
    if "GraphDriver" in raw:
        # Snapshotter internals are not yet reviewed for admission.
        require(exact(raw["GraphDriver"], {"Name": "overlay2", "Data": None}))
    expected = spec.create_body()
    expected_host = expected.pop("HostConfig")
    config = dict(object_value(raw["Config"]))
    require(environment(config.get("Env")) == tuple(sorted(SandboxPolicy().environment)))
    config["Env"] = expected["Env"]
    config = _review_fields(config, expected, {"Hostname": container_id[:12], "Domainname": "",
        "AttachStdin": False, "AttachStdout": False, "AttachStderr": False, "OnBuild": None, "ArgsEscaped": True})
    host = dict(object_value(raw["HostConfig"]))
    if exact(host.get("SecurityOpt"), ["no-new-privileges"]):
        host["SecurityOpt"] = ["no-new-privileges=true"]
    masked, readonly = host.get("MaskedPaths"), host.get("ReadonlyPaths")
    for paths in (masked, readonly):
        require(type(paths) is list and all(type(path) is str for path in paths))
        require(len(paths) <= 4096 and len(paths) == len(set(paths)))
    require(set(MASKED_PATHS) <= set(masked) and set(READONLY_PATHS) == set(readonly))
    require(all(path in MASKED_PATHS or re.fullmatch(r"/sys/devices/system/cpu/cpu[0-9]+/thermal_throttle", path)
                for path in masked))
    host["MaskedPaths"], host["ReadonlyPaths"] = MASKED_PATHS, READONLY_PATHS
    required_host = {**expected_host, "MaskedPaths": MASKED_PATHS, "ReadonlyPaths": READONLY_PATHS}
    host = _review_fields(host, required_host, HOST_DEFAULTS)
    host.pop("MaskedPaths")
    host.pop("ReadonlyPaths")
    state = _review_fields(object_value(raw["State"]), {
        "Status": "created", "Running": False, "Paused": False, "Restarting": False, "Dead": False, "Pid": 0,
    }, {"OOMKilled": False, "ExitCode": 0, "Error": "", "StartedAt": "0001-01-01T00:00:00Z", "FinishedAt": "0001-01-01T00:00:00Z"})
    # A stopped none-network endpoint must contain no assigned addresses/routes.
    network = object_value(raw["NetworkSettings"])
    require({"Ports", "Networks"} <= network.keys())
    require(not network.keys() - {"Ports", "Networks", "SandboxID", "SandboxKey", "Bridge",
        "HairpinMode", "LinkLocalIPv6Address", "LinkLocalIPv6PrefixLen"})
    require(network["Ports"] is None or exact(network["Ports"], {}))
    endpoints = object_value(network["Networks"])
    require(set(endpoints) == {"none"})
    endpoint = object_value(endpoints["none"])
    for name in ("NetworkID", "EndpointID"):
        if name in endpoint:
            require(type(endpoint[name]) is str and re.fullmatch(r"(?:[0-9a-f]{64})?", endpoint[name]) is not None)
    _review_fields({key: value for key, value in endpoint.items() if key not in {"NetworkID", "EndpointID"}}, {}, {
        "IPAMConfig": None, "Links": None, "Aliases": None, "DNSNames": None, "DriverOpts": None,
        "Gateway": "", "IPAddress": "", "IPPrefixLen": 0, "IPv6Gateway": "", "GlobalIPv6Address": "",
        "GlobalIPv6PrefixLen": 0, "MacAddress": "", "GwPriority": 0,
    })
    for name in ("SandboxID", "SandboxKey"):
        if name in network:
            require(type(network[name]) is str and len(network[name]) <= 256)
    for name, expected_value in {"Bridge": "", "HairpinMode": False, "LinkLocalIPv6Address": "", "LinkLocalIPv6PrefixLen": 0}.items():
        if name in network:
            require(exact(network[name], expected_value))
    projection = {"Id": container_id, "Name": raw["Name"], "Image": spec.image_id,
        "Config": config, "HostConfig": host, "State": state, "Mounts": raw["Mounts"],
        "NetworkSettings": {"Ports": {}, "Networks": {"none": {}}}, "AppArmorProfile": raw["AppArmorProfile"]}
    try:
        verify_configuration(projection, spec, container_id)
    except (ValueError, RuntimeError):
        raise MetadataError() from None
    return ContainerMetadata(container_id, raw["Image"], spec.image_id, spec.job_id, tuple(masked), tuple(readonly),
        json.dumps(projection, separators=(",", ":"), sort_keys=True))
