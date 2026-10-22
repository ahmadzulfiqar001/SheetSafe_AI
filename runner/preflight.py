"""Operator-only read-only Docker CLI queries; never a lifecycle transport."""

from dataclasses import dataclass, field
from enum import StrEnum
import json
import os
import re
import shutil
import subprocess
from threading import Event, Thread
from typing import Protocol

from runner.docker_backend import LOCAL_IMAGE_ID, LOCAL_REVIEW_TAG
from runner.engine_metadata import INSPECTION_API, EngineFacts, ImageFacts, MetadataError, parse_engine, parse_image, require
from runner.policy import SandboxPolicy


QUERY_TIMEOUT = 5.0
MAX_OUTPUT_BYTES = 1024 * 1024


class QueryError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Docker read-only query failed.")


class ImageTagMismatch(QueryError):
    """A diagnostic tag resolved to another image; never select that replacement."""


class LocalContext(StrEnum):
    DESKTOP_LINUX = "desktop-linux"
    LINUX_DEFAULT = "default"


class EngineReader(Protocol):
    def channel(self) -> object: ...
    def version(self) -> object: ...
    def info(self) -> object: ...
    def image(self) -> object: ...


def _json(data: bytes) -> object:
    def no_duplicates(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise QueryError()
            result[name] = value
        return result
    def non_finite(value):
        raise QueryError()
    try:
        return json.loads(data, object_pairs_hook=no_duplicates, parse_constant=non_finite)
    except (ValueError, UnicodeError, RecursionError):
        raise QueryError() from None


def _capture(arguments: list[str]) -> object:
    """Bound both streams and time; kill only the local read-only CLI if needed."""
    allowed_commands = []
    for context in LocalContext:
        allowed_commands.extend([
            ["context", "inspect", context.value, "--format", "{{json .Endpoints.docker}}"],
            ["--context", context.value, "version", "--format", "{{json .}}"],
            ["--context", context.value, "info", "--format", "{{json .}}"],
            ["--context", context.value, "image", "inspect", LOCAL_IMAGE_ID],
            ["--context", context.value, "image", "inspect", LOCAL_REVIEW_TAG],
        ])
    if type(arguments) is not list or arguments not in allowed_commands:
        raise QueryError()
    allowed_env = {"PATH", "SYSTEMROOT", "WINDIR", "USERPROFILE", "HOME", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP"}
    env = {key: value for key, value in os.environ.items() if key.upper() in allowed_env}
    env["DOCKER_API_VERSION"] = INSPECTION_API
    executable = shutil.which("docker", path=env.get("PATH", env.get("Path", "")))
    if executable is None:
        raise QueryError()
    process = None
    workers = []
    buffers = [bytearray(), bytearray()]
    overflow = Event()
    read_error = Event()
    def drain(stream, index):
        try:
            while chunk := stream.read(4096):
                if len(buffers[index]) + len(chunk) > MAX_OUTPUT_BYTES:
                    overflow.set()
                    return
                buffers[index].extend(chunk)
        except (OSError, ValueError):
            read_error.set()
    try:
        process = subprocess.Popen([executable, *arguments], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, env=env, bufsize=0,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        for index, stream in enumerate((process.stdout, process.stderr)):
            worker = Thread(target=drain, args=(stream, index), daemon=True)
            workers.append(worker)
            worker.start()
        process.wait(timeout=QUERY_TIMEOUT)
        for worker in workers:
            worker.join(timeout=1)
        if process.returncode != 0 or buffers[1] or overflow.is_set() or read_error.is_set() or any(t.is_alive() for t in workers):
            raise QueryError()
        return _json(bytes(buffers[0]))
    except (OSError, subprocess.SubprocessError):
        raise QueryError() from None
    finally:
        if process is not None:
            cleanup_failed = False
            if process.poll() is None:
                try:
                    process.kill()
                    process.wait(timeout=1)
                except (OSError, subprocess.SubprocessError):
                    cleanup_failed = True
            for worker in workers:
                worker.join(timeout=1)
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
            if cleanup_failed:
                raise QueryError() from None


class DockerReadOnlyClient:
    """Fixed local context and five queries only; no arbitrary command arguments."""

    def __init__(self, context: LocalContext) -> None:
        if type(context) is not LocalContext:
            raise QueryError()
        self._context = context

    def channel(self) -> object:
        return _capture(["context", "inspect", self._context.value, "--format", "{{json .Endpoints.docker}}"])

    def version(self) -> object:
        validate_channel(self.channel())
        return _capture(["--context", self._context.value, "version", "--format", "{{json .}}"])

    def info(self) -> object:
        validate_channel(self.channel())
        return _capture(["--context", self._context.value, "info", "--format", "{{json .}}"])

    def image(self) -> object:
        # Select by immutable ID, never a tag or caller input. The separately
        # queried fixed tag detects reassignment; it is not a fallback selector.
        validate_channel(self.channel())
        result = _capture(["--context", self._context.value, "image", "inspect", LOCAL_IMAGE_ID])
        if type(result) is not list or len(result) != 1:
            raise QueryError()
        selected = parse_image(result[0])
        validate_channel(self.channel())
        tagged = _capture(["--context", self._context.value, "image", "inspect", LOCAL_REVIEW_TAG])
        if type(tagged) is not list or len(tagged) != 1 or type(tagged[0]) is not dict or "Id" not in tagged[0]:
            raise QueryError()
        if tagged[0]["Id"] != LOCAL_IMAGE_ID:
            raise ImageTagMismatch()
        # Both responses must satisfy the same critical configuration contract.
        require(parse_image(tagged[0]).issues == selected.issues)
        return result[0]


def validate_channel(raw: object) -> str:
    require(type(raw) is dict and set(raw) == {"Host", "SkipTLSVerify"} and raw["SkipTLSVerify"] is False)
    host = raw["Host"]
    require(type(host) is str)
    if host == "npipe:////./pipe/dockerDesktopLinuxEngine":
        return "local-npipe"
    if host == "unix:///var/run/docker.sock" or re.fullmatch(r"unix:///run/user/[1-9][0-9]*/docker.sock", host):
        return "local-unix"
    raise MetadataError()  # No tcp/ssh endpoints, caller hosts or TLS bypasses.


@dataclass(frozen=True, slots=True)
class PreflightReport:
    channel_kind: str | None
    engine: EngineFacts | None
    image: ImageFacts | None
    issues: tuple[str, ...]
    execution_enabled: bool = field(default=False, init=False)
    unverified_controls: tuple[str, ...] = field(default=SandboxPolicy().unverified_controls, init=False)

    @property
    def metadata_prerequisites_met(self) -> bool:
        return not self.issues  # Never an execution readiness decision.


def run_preflight(reader: EngineReader) -> PreflightReport:
    channel = None
    engine = None
    image = None
    issues = []
    try:
        channel = validate_channel(reader.channel())
    except Exception:
        return PreflightReport(None, None, None, ("CONTROL_CHANNEL_UNAVAILABLE",))
    try:
        engine = parse_engine(reader.version(), reader.info())
        issues.extend(engine.issues)
    except Exception:
        issues.append("ENGINE_METADATA_UNAVAILABLE")
    try:
        image = parse_image(reader.image())
        issues.extend(image.issues)
    except ImageTagMismatch:
        issues.append("IMAGE_TAG_MISMATCH")
    except Exception:
        issues.append("IMAGE_METADATA_UNAVAILABLE")
    return PreflightReport(channel, engine, image, tuple(issues))
