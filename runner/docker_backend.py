"""Stopped-container lifecycle contract; no concrete Docker client or start API.

The injected transport is trusted operator infrastructure. This increment uses
only a fake transport. Inspect responses are a strict internal projection, not
an assertion that raw Engine JSON has already been mapped/tested. A future real
driver must bound I/O, distinguish explicit not-found from API failure, preserve
all security-relevant metadata, and verify image identity before creating jobs.
"""

from asyncio import CancelledError
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import StrEnum
import re
from threading import Lock
from typing import Iterator, Protocol
from uuid import uuid4

from runner.policy import FixtureRequest, SandboxPolicy, policy_for


# Step 7G static selection approval of Step 7F's LOCAL manifest identity.
# Not a registry-published RepoDigest or permission to create/execute containers.
LOCAL_IMAGE_ID = "sha256:551ae45bad03b4a1856ae503c62c01a8078394a19d3c318b53fc9f2e98f66bc9"
LOCAL_REVIEW_TAG = "sheetsafe-runner:environment-review"  # Consistency check only.
API_TIMEOUT_SECONDS = 1.0
_ID = re.compile(r"[0-9a-f]{64}\Z")


class FailureCode(StrEnum):
    ADMISSIONS_BLOCKED = "ADMISSIONS_BLOCKED"
    JOB_ACTIVE = "JOB_ACTIVE"
    CREATE_FAILED = "CREATE_FAILED"
    INVALID_IDENTITY = "INVALID_IDENTITY"
    DUPLICATE_IDENTITY = "DUPLICATE_IDENTITY"
    INSPECT_FAILED = "INSPECT_FAILED"
    POLICY_MISMATCH = "POLICY_MISMATCH"
    SCOPE_FAILED = "SCOPE_FAILED"
    CANCELLED = "CANCELLED"
    CLEANUP_UNRESOLVED = "CLEANUP_UNRESOLVED"
    REMOVE_FAILED = "REMOVE_FAILED"


class RunnerLifecycleError(RuntimeError):
    def __init__(self, code: FailureCode) -> None:
        self.code = code
        super().__init__(f"Runner lifecycle failed: {code.value}.")


class ContainerNotFound(Exception):
    """Only a validated, explicit not-found response; never a timeout/error."""


class CreateRejected(Exception):
    """Transport guarantees creation never occurred; not an ambiguous timeout."""


@dataclass(frozen=True, slots=True)
class ContainerJobSpec:
    """No caller-settable fields. Instances are not accepted by the adapter API."""

    job_id: str = field(default_factory=lambda: uuid4().hex, init=False)
    ownership_nonce: str = field(default_factory=lambda: uuid4().hex, init=False, repr=False)
    fixture_id: str = field(default="smoke-v1", init=False)
    image_id: str = field(default=LOCAL_IMAGE_ID, init=False)
    platform: str = field(default="linux/amd64", init=False)

    @classmethod
    def for_fixture(cls, request: FixtureRequest) -> "ContainerJobSpec":
        policy_for(request)  # Reject mappings, subclasses and unsupported fixtures.
        return cls()

    @property
    def name(self) -> str:
        return f"sheetsafe-smoke-{self.job_id}"

    @property
    def labels(self) -> dict[str, str]:
        return {
            "org.opencontainers.image.title": "SheetSafe fixed smoke fixture",
            "org.opencontainers.image.version": "smoke-v1",
            "io.sheetsafe.policy": SandboxPolicy().version,
            "io.sheetsafe.job": self.job_id,
            "io.sheetsafe.owner": self.ownership_nonce,
        }

    def create_body(self) -> dict:
        """Fresh Engine-style request body; no host environment or override merge."""
        policy = SandboxPolicy()
        return {
            "Image": self.image_id, "User": f"{policy.uid}:{policy.gid}",
            "Entrypoint": list(policy.entrypoint), "Cmd": [self.fixture_id],
            "Env": [f"{name}={value}" for name, value in policy.environment],
            "WorkingDir": policy.workdir, "StopSignal": "SIGTERM",
            "Labels": self.labels, "Volumes": {}, "ExposedPorts": {},
            "OpenStdin": False, "StdinOnce": False, "Tty": False,
            "NetworkDisabled": True, "Healthcheck": {"Test": ["NONE"]},
            "HostConfig": {
                "Privileged": policy.privileged, "CapDrop": list(policy.cap_drop),
                "CapAdd": [], "SecurityOpt": ["no-new-privileges=true"],
                # Omit a seccomp override: Docker's default must remain enabled.
                # Effective seccomp/LSM enforcement still needs runtime evidence.
                "NetworkMode": policy.network_mode, "PortBindings": {},
                "PublishAllPorts": False, "Dns": [], "ExtraHosts": [], "Links": [],
                "ReadonlyRootfs": policy.read_only_root,
                "Tmpfs": {
                    mount.path: ",".join(("rw", *mount.options,
                        f"size={mount.byte_limit}", f"uid={mount.uid}",
                        f"gid={mount.gid}", f"mode={mount.mode:o}"))
                    for mount in policy.tmpfs
                },
                "CpuPeriod": 100_000, "CpuQuota": policy.cpus * 100_000,
                "NanoCpus": 0, "Memory": policy.memory_bytes,
                "MemorySwap": policy.memory_plus_swap_bytes,
                "PidsLimit": policy.pids_limit, "OomKillDisable": False,
                # Engine's empty PID mode means a new private PID namespace.
                "PidMode": "", "IpcMode": "private", "CgroupnsMode": "private",
                "Binds": [], "Mounts": [], "VolumesFrom": [], "Devices": [],
                "DeviceRequests": [], "DeviceCgroupRules": [], "Sysctls": {},
                "Runtime": "runc", "UsernsMode": "",
                "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                "AutoRemove": False,
                "LogConfig": {"Type": policy.daemon_log_driver, "Config": {}},
            },
        }


class DockerTransport(Protocol):
    """No start/exec/build/pull/archive/general-command methods are permitted.

    A future real implementation must verify the reviewed local manifest/config
    pair, critical image metadata and fixed-tag consistency before create; use
    only the exact ID in the spec, without pulling or tag/old-image fallback.
    Static selection never clears execution/runtime gates. It must also honor
    the supplied timeout and map daemon metadata conservatively. No production
    lifecycle transport that contacts Docker is supplied by this milestone.
    """

    def create(self, spec: ContainerJobSpec, *, timeout: float) -> str: ...
    def inspect(self, reference: str, *, timeout: float) -> dict: ...
    def remove(self, container_id: str, *, force: bool, timeout: float) -> None: ...


class LifecycleState(StrEnum):
    CREATING = "CREATING"
    CREATED = "CREATED"
    CONFIGURATION_VERIFIED = "CONFIGURATION_VERIFIED"
    CLEANING = "CLEANING"
    ABSENT = "ABSENT"
    UNRESOLVED = "UNRESOLVED"


class JobOutcome(StrEnum):
    PENDING = "PENDING"
    CONFIGURATION_ONLY = "CONFIGURATION_ONLY"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


@dataclass(frozen=True, slots=True)
class LifecycleReceipt:
    job_id: str
    container_id: str | None
    state: LifecycleState
    outcome: JobOutcome
    configuration_verified: bool
    cleanup_confirmed: bool
    failure: FailureCode | None
    cleanup_failure: FailureCode | None
    execution_enabled: bool = field(default=False, init=False)
    unverified_controls: tuple[str, ...] = field(default=SandboxPolicy().unverified_controls, init=False)


@dataclass(slots=True)
class _Job:
    spec: ContainerJobSpec
    container_id: str | None = None
    state: LifecycleState = LifecycleState.CREATING
    outcome: JobOutcome = JobOutcome.PENDING
    configuration_verified: bool = False
    cleanup_confirmed: bool = False
    failure: FailureCode | None = None
    cleanup_failure: FailureCode | None = None
    create_rejected: bool = False

    def receipt(self) -> LifecycleReceipt:
        return LifecycleReceipt(self.spec.job_id, self.container_id, self.state,
            self.outcome, self.configuration_verified, self.cleanup_confirmed,
            self.failure, self.cleanup_failure)


def _same(actual: object, expected: object) -> bool:
    """Exact types prevent False/0 and True/1 from passing security comparisons."""
    if type(actual) is not type(expected):
        return False
    if type(expected) is dict:
        return actual.keys() == expected.keys() and all(_same(actual[key], value) for key, value in expected.items())
    if type(expected) is list:
        return len(actual) == len(expected) and all(_same(a, b) for a, b in zip(actual, expected))
    return actual == expected


def _valid_id(value: object) -> bool:
    return type(value) is str and _ID.fullmatch(value) is not None


def _owned_id(metadata: object, spec: ContainerJobSpec) -> str:
    if (type(metadata) is not dict or not _valid_id(metadata.get("Id"))
            or not _same(metadata.get("Name"), "/" + spec.name)
            or type(metadata.get("Config")) is not dict
            or not _same(metadata["Config"].get("Labels"), spec.labels)):
        raise RunnerLifecycleError(FailureCode.INVALID_IDENTITY)
    return metadata["Id"]


def verify_configuration(metadata: object, spec: ContainerJobSpec, container_id: str) -> None:
    """Verify the strict transport contract; this is not a runtime SEC receipt."""
    if not _valid_id(container_id) or _owned_id(metadata, spec) != container_id:
        raise RunnerLifecycleError(FailureCode.INVALID_IDENTITY)
    config = spec.create_body()
    host = config.pop("HostConfig")
    expected = {
        "Id": container_id, "Name": "/" + spec.name, "Image": spec.image_id,
        "Config": config, "HostConfig": host,
        "State": {"Status": "created", "Running": False, "Paused": False,
                  "Restarting": False, "Dead": False, "Pid": 0},
        # No extra mounts or network attachments in the internal projection.
        # The real driver must separately examine effective tmpfs mounts/LSM.
        "Mounts": [], "NetworkSettings": {"Ports": {}, "Networks": {"none": {}}},
        "AppArmorProfile": "docker-default",
    }
    if not _same(metadata, expected):
        raise RunnerLifecycleError(FailureCode.POLICY_MISMATCH)


class DockerLifecycleAdapter:
    """One scoped job at a time; uncertainty permanently blocks this instance.

    State is in-memory. Durable journal/reaper and authenticated operator broker
    are required before a real transport can be admitted. There is no reset,
    public remove-by-ID operation, or path that enables execution.
    """

    def __init__(self, transport: DockerTransport) -> None:
        self._transport = transport
        self._lock = Lock()
        self._active = False
        self._blocked = False
        self._seen_ids: set[str] = set()
        self._last_receipt: LifecycleReceipt | None = None

    @property
    def admissions_blocked(self) -> bool:
        with self._lock:
            return self._blocked

    @property
    def last_receipt(self) -> LifecycleReceipt | None:
        with self._lock:
            return self._last_receipt

    def _inspect(self, reference: str) -> dict:
        return self._transport.inspect(reference, timeout=API_TIMEOUT_SECONDS)

    def _absent(self, reference: str) -> bool:
        try:
            self._inspect(reference)
        except ContainerNotFound:
            return True
        return False  # Every other error propagates; no inferred absence.

    def _cleanup(self, job: _Job) -> BaseException | None:
        job.state = LifecycleState.CLEANING
        interrupt = None
        try:
            try:
                metadata = self._inspect(job.spec.name)
            except ContainerNotFound:
                # An ambiguous create with no valid ID can still materialize
                # later. Absence by name alone must not clear that uncertainty.
                if job.create_rejected or (job.container_id is not None and self._absent(job.container_id)):
                    job.cleanup_confirmed = True
                else:
                    job.cleanup_failure = FailureCode.CLEANUP_UNRESOLVED
            else:
                candidate = _owned_id(metadata, job.spec)
                if job.container_id is None:
                    if candidate in self._seen_ids:
                        raise RunnerLifecycleError(FailureCode.DUPLICATE_IDENTITY)
                    self._seen_ids.add(candidate)
                    job.container_id = candidate
                if candidate != job.container_id or _owned_id(self._inspect(candidate), job.spec) != candidate:
                    raise RunnerLifecycleError(FailureCode.INVALID_IDENTITY)
                try:
                    self._transport.remove(candidate, force=True, timeout=API_TIMEOUT_SECONDS)
                except BaseException as error:
                    job.cleanup_failure = FailureCode.REMOVE_FAILED
                    if not isinstance(error, Exception):
                        interrupt = error
                # A successful remove response is insufficient. Check the exact
                # ID and reserved name separately; never remove a replacement.
                id_absent = self._absent(candidate)
                name_absent = self._absent(job.spec.name)
                job.cleanup_confirmed = id_absent and name_absent
        except BaseException as error:
            job.cleanup_failure = FailureCode.CLEANUP_UNRESOLVED
            if not isinstance(error, Exception):
                interrupt = error
        if not job.cleanup_confirmed:
            job.cleanup_failure = job.cleanup_failure or FailureCode.CLEANUP_UNRESOLVED
        job.state = LifecycleState.ABSENT if job.cleanup_confirmed else LifecycleState.UNRESOLVED
        return interrupt

    @contextmanager
    def prepared(self, request: FixtureRequest) -> Iterator[LifecycleReceipt]:
        """Create/inspect a stopped fixture, then verify scoped removal on exit."""
        spec = ContainerJobSpec.for_fixture(request)
        with self._lock:
            if self._blocked:
                raise RunnerLifecycleError(FailureCode.ADMISSIONS_BLOCKED)
            if self._active:
                raise RunnerLifecycleError(FailureCode.JOB_ACTIVE)
            self._active = True
        job = _Job(spec)
        failure = None
        phase = FailureCode.CREATE_FAILED
        try:
            try:
                container_id = self._transport.create(spec, timeout=API_TIMEOUT_SECONDS)
            except CreateRejected:
                job.create_rejected = True
                raise RunnerLifecycleError(FailureCode.CREATE_FAILED) from None
            if not _valid_id(container_id):
                raise RunnerLifecycleError(FailureCode.INVALID_IDENTITY)
            if container_id in self._seen_ids:
                raise RunnerLifecycleError(FailureCode.DUPLICATE_IDENTITY)
            self._seen_ids.add(container_id)
            job.container_id = container_id
            job.state = LifecycleState.CREATED
            phase = FailureCode.INSPECT_FAILED
            verify_configuration(self._inspect(container_id), spec, container_id)
            job.configuration_verified = True
            job.state = LifecycleState.CONFIGURATION_VERIFIED
            with self._lock:
                self._last_receipt = job.receipt()
            phase = FailureCode.SCOPE_FAILED
            yield job.receipt()
            job.outcome = JobOutcome.CONFIGURATION_ONLY
        except BaseException as error:
            cancelled = isinstance(error, (CancelledError, KeyboardInterrupt, GeneratorExit))
            job.outcome = JobOutcome.CANCELLED if cancelled else JobOutcome.FAILED
            job.failure = FailureCode.CANCELLED if cancelled else (error.code if isinstance(error, RunnerLifecycleError) else phase)
            failure = error if not isinstance(error, Exception) else RunnerLifecycleError(job.failure)
        finally:
            interrupt = self._cleanup(job)
            if job.cleanup_failure is not None:
                if failure is None:
                    cancelled = isinstance(interrupt, (CancelledError, KeyboardInterrupt, GeneratorExit))
                    job.failure = FailureCode.CANCELLED if cancelled else job.cleanup_failure
                    job.outcome = JobOutcome.CANCELLED if cancelled else JobOutcome.FAILED
                    failure = interrupt or RunnerLifecycleError(job.cleanup_failure)
            with self._lock:
                self._blocked = self._blocked or not job.cleanup_confirmed
                self._last_receipt = job.receipt()
                self._active = False
        if failure is not None:
            raise failure from None
