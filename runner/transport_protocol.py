"""Transport-neutral synthetic metadata and byte validation, never admission.

No streams, filesystem, Docker, backend, data-format parsing or code execution.
Expected bindings/manifests/slots must come from trusted server state. Comparing
them is not session authentication or a persistent lease check.
"""

from dataclasses import dataclass, field
from enum import StrEnum
import hashlib
import hmac
import json
import re
import struct
from uuid import uuid4


PROTOCOL_VERSION = 1
FIXTURE_ID = "smoke-v1"
MAX_MANIFEST_BYTES = 4096
MAX_OUTPUT_MANIFEST_BYTES = 16 * 1024
MAX_DATA_BYTES = 64 * 1024
MAX_PAYLOAD_BYTES = 256 * 1024  # Synthetic validation profile, not dataset admission.
MAX_ARTIFACTS = 10
MAX_ARTIFACT_BYTES = 10 * 1024**2
MAX_OUTPUT_BYTES = 20 * 1024**2
FRAME_HEADER = struct.Struct("!4sB16s32sII")
MAX_FRAME_BYTES = FRAME_HEADER.size + MAX_DATA_BYTES
_MAGIC = b"SSFT"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_FILE_TYPES = frozenset({"csv", "png", "json", "txt"})


class TransportCode(StrEnum):
    MALFORMED_MANIFEST = "MALFORMED_MANIFEST"
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    INVALID_LENGTH = "INVALID_LENGTH"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    DIGEST_MISMATCH = "DIGEST_MISMATCH"
    INVALID_FRAME = "INVALID_FRAME"
    FRAME_ORDER = "FRAME_ORDER"
    TRUNCATED = "TRUNCATED"
    TRAILING_BYTES = "TRAILING_BYTES"
    CLOSED = "CLOSED"
    INVALID_ARTIFACT = "INVALID_ARTIFACT"
    DUPLICATE_DELIVERY = "DUPLICATE_DELIVERY"
    STALE_LEASE = "STALE_LEASE"
    TIMED_OUT = "TIMED_OUT"
    CANCELLED = "CANCELLED"
    INTERRUPTED = "INTERRUPTED"
    UNEXPECTED_TRANSPORT = "UNEXPECTED_TRANSPORT"
    READ_LIMIT = "READ_LIMIT"


class TransportError(ValueError):
    def __init__(self, code: TransportCode) -> None:
        self.code = code
        super().__init__(f"Transport validation failed: {code.value}.")


def _require(condition: bool, code: TransportCode) -> None:
    if not condition:
        raise TransportError(code)


def _integer(value: object, minimum: int, maximum: int) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _sha256(value: object) -> bool:
    return type(value) is str and _DIGEST.fullmatch(value) is not None


def _json_bytes(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _decode(data: object, maximum: int) -> dict:
    _require(type(data) is bytes and 0 < len(data) <= maximum, TransportCode.MALFORMED_MANIFEST)
    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result, TransportCode.MALFORMED_MANIFEST)
            result[key] = value
        return result
    def integer(value):
        _require(len(value) <= 19, TransportCode.MALFORMED_MANIFEST)
        return int(value)
    def unsupported(value):
        raise TransportError(TransportCode.MALFORMED_MANIFEST)
    try:
        result = json.loads(data.decode("utf-8", errors="strict"), object_pairs_hook=pairs,
            parse_int=integer, parse_float=unsupported, parse_constant=unsupported)
    except TransportError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise TransportError(TransportCode.MALFORMED_MANIFEST) from None
    _require(type(result) is dict, TransportCode.MALFORMED_MANIFEST)
    return result


@dataclass(frozen=True, slots=True)
class JobBinding:
    """Internal server context; it does not prove ownership or a live DB lease."""

    session_id: str
    run_id: str
    lease_epoch: int
    job_id: str = field(default_factory=lambda: uuid4().hex, init=False)

    def __post_init__(self) -> None:
        _require(all(type(value) is str and _IDENTIFIER.fullmatch(value) is not None
            for value in (self.session_id, self.run_id)), TransportCode.IDENTITY_MISMATCH)
        _require(_integer(self.lease_epoch, 1, 2**63 - 1), TransportCode.IDENTITY_MISMATCH)

    def fields(self) -> dict:
        return {"protocol_version": PROTOCOL_VERSION, "fixture_id": FIXTURE_ID,
            "job_id": self.job_id, "session_id": self.session_id,
            "run_id": self.run_id, "lease_epoch": self.lease_epoch}

    @classmethod
    def _from_trusted_record(cls, *, job_id: str, session_id: str,
            run_id: str, lease_epoch: int) -> "JobBinding":
        """Internal DB hydration only; never call with transport/HTTP fields.

        This is validation, not authorization. The repository must first check
        the session, ownership and fenced lease in its transaction.
        """
        _require(type(job_id) is str and re.fullmatch(r"[0-9a-f]{32}", job_id) is not None,
            TransportCode.IDENTITY_MISMATCH)
        binding = cls(session_id, run_id, lease_epoch)
        object.__setattr__(binding, "job_id", job_id)
        return binding


def _binding(raw: dict, expected: JobBinding) -> None:
    _require(type(expected) is JobBinding, TransportCode.IDENTITY_MISMATCH)
    _require(type(raw.get("protocol_version")) is int and raw["protocol_version"] == PROTOCOL_VERSION,
        TransportCode.UNSUPPORTED_VERSION)
    for name, value in expected.fields().items():
        _require(type(raw.get(name)) is type(value) and raw[name] == value, TransportCode.IDENTITY_MISMATCH)


@dataclass(frozen=True, slots=True)
class InputManifest:
    binding: JobBinding
    payload_length: int
    sha256: str

    def __post_init__(self) -> None:
        _require(type(self.binding) is JobBinding, TransportCode.IDENTITY_MISMATCH)
        _require(_integer(self.payload_length, 1, MAX_PAYLOAD_BYTES), TransportCode.INVALID_LENGTH)
        _require(_sha256(self.sha256), TransportCode.DIGEST_MISMATCH)

    @classmethod
    def for_payload(cls, binding: JobBinding, payload: bytes) -> "InputManifest":
        _require(type(payload) is bytes and 0 < len(payload) <= MAX_PAYLOAD_BYTES, TransportCode.INVALID_LENGTH)
        return cls(binding, len(payload), hashlib.sha256(payload).hexdigest())

    def fields(self) -> dict:
        return {**self.binding.fields(), "payload_length": self.payload_length,
            "sha256": self.sha256, "metadata": {"purpose": "synthetic-transport-check"}}

    def to_bytes(self) -> bytes:
        return _json_bytes(self.fields())

    @property
    def binding_digest(self) -> bytes:
        # Unkeyed integrity binding, never sender/owner authentication.
        return hashlib.sha256(self.to_bytes()).digest()


def validate_manifest(encoded: bytes, expected: InputManifest) -> InputManifest:
    _require(type(expected) is InputManifest, TransportCode.MALFORMED_MANIFEST)
    raw = _decode(encoded, MAX_MANIFEST_BYTES)
    _require(raw.keys() == expected.fields().keys(), TransportCode.MALFORMED_MANIFEST)
    _binding(raw, expected.binding)
    _require(_integer(raw["payload_length"], 1, MAX_PAYLOAD_BYTES)
        and raw["payload_length"] == expected.payload_length, TransportCode.INVALID_LENGTH)
    _require(_sha256(raw["sha256"]) and hmac.compare_digest(raw["sha256"], expected.sha256), TransportCode.DIGEST_MISMATCH)
    _require(type(raw["metadata"]) is dict and raw["metadata"] == expected.fields()["metadata"], TransportCode.MALFORMED_MANIFEST)
    return expected  # Never mint a new job/authority from untrusted metadata.


def encode_frame(manifest: InputManifest, sequence: int, payload: bytes) -> bytes:
    """Bounded fixture/test encoder, no transport or dispatch capability."""
    _require(type(manifest) is InputManifest, TransportCode.INVALID_FRAME)
    count = (manifest.payload_length + MAX_DATA_BYTES - 1) // MAX_DATA_BYTES
    _require(_integer(sequence, 0, count - 1), TransportCode.FRAME_ORDER)
    expected = min(MAX_DATA_BYTES, manifest.payload_length - sequence * MAX_DATA_BYTES)
    _require(type(payload) is bytes and len(payload) == expected, TransportCode.INVALID_LENGTH)
    return FRAME_HEADER.pack(_MAGIC, PROTOCOL_VERSION, bytes.fromhex(manifest.binding.job_id),
        manifest.binding_digest, sequence, len(payload)) + payload


@dataclass(frozen=True, slots=True)
class PayloadEvidence:
    job_id: str
    received_bytes: int
    sha256: str
    lease_epoch: int
    execution_enabled: bool = field(default=False, init=False)


class FrameValidator:
    """Incremental byte validation: header-sized buffer; payload is never retained.

    feed accepts bounded fragments, not assumed socket/message boundaries. EOF
    must be explicitly confirmed with finish. Any error permanently poisons the
    instance. A successful hash is neither immutable storage nor authorization.
    """

    def __init__(self, manifest: InputManifest) -> None:
        _require(type(manifest) is InputManifest, TransportCode.MALFORMED_MANIFEST)
        self._manifest = manifest
        self._header = bytearray()
        self._remaining = 0
        self._sequence = 0
        self._received = 0
        self._digest = hashlib.sha256()
        self._error: TransportCode | None = None
        self._closed = False

    @property
    def buffered_bytes(self) -> int:
        return len(self._header)

    def _fail(self, code: TransportCode) -> None:
        self._error = self._error or code
        self._header.clear()
        raise TransportError(self._error)

    def _open(self) -> None:
        if self._error is not None:
            raise TransportError(self._error)
        if self._closed:
            raise TransportError(TransportCode.CLOSED)

    def feed(self, chunk: bytes) -> None:
        self._open()
        if type(chunk) is not bytes or not 0 < len(chunk) <= MAX_FRAME_BYTES:
            self._fail(TransportCode.INVALID_FRAME)
        view, offset = memoryview(chunk), 0
        while offset < len(view):
            if self._received == self._manifest.payload_length and self._remaining == 0:
                self._fail(TransportCode.TRAILING_BYTES)
            if self._remaining == 0:
                take = min(FRAME_HEADER.size - len(self._header), len(view) - offset)
                self._header.extend(view[offset:offset + take])
                offset += take
                if len(self._header) < FRAME_HEADER.size:
                    continue
                magic, version, job, binding, sequence, length = FRAME_HEADER.unpack(self._header)
                self._header.clear()
                if magic != _MAGIC:
                    self._fail(TransportCode.INVALID_FRAME)
                if version != PROTOCOL_VERSION:
                    self._fail(TransportCode.UNSUPPORTED_VERSION)
                if job != bytes.fromhex(self._manifest.binding.job_id) or binding != self._manifest.binding_digest:
                    self._fail(TransportCode.IDENTITY_MISMATCH)
                if sequence != self._sequence:
                    self._fail(TransportCode.FRAME_ORDER)
                expected = min(MAX_DATA_BYTES, self._manifest.payload_length - self._received)
                if not 0 < length <= MAX_DATA_BYTES or length != expected:
                    self._fail(TransportCode.INVALID_LENGTH)
                self._remaining = length
            take = min(self._remaining, len(view) - offset)
            if take > MAX_PAYLOAD_BYTES - self._received or take > self._manifest.payload_length - self._received:
                self._fail(TransportCode.INVALID_LENGTH)
            self._digest.update(view[offset:offset + take])
            self._received += take
            self._remaining -= take
            offset += take
            if self._remaining == 0:
                self._sequence += 1

    def finish(self) -> PayloadEvidence:
        self._open()
        if self._header or self._remaining or self._received != self._manifest.payload_length:
            self._fail(TransportCode.TRUNCATED)
        digest = self._digest.hexdigest()
        if not hmac.compare_digest(digest, self._manifest.sha256):
            self._fail(TransportCode.DIGEST_MISMATCH)
        self._closed = True
        return PayloadEvidence(self._manifest.binding.job_id, self._received, digest,
            self._manifest.binding.lease_epoch)


@dataclass(frozen=True, slots=True)
class ArtifactSlot:
    """Server-issued output slot, not a candidate-chosen path or identifier."""

    binding: JobBinding
    file_type: str
    artifact_id: str = field(default_factory=lambda: uuid4().hex, init=False)

    def __post_init__(self) -> None:
        _require(type(self.binding) is JobBinding and type(self.file_type) is str
            and self.file_type in _FILE_TYPES, TransportCode.INVALID_ARTIFACT)

    @property
    def filename(self) -> str:
        return f"a_{self.artifact_id}.{self.file_type}"


@dataclass(frozen=True, slots=True)
class ArtifactClaim:
    artifact_id: str
    filename: str
    declared_bytes: int
    declared_sha256: str
    status: str = field(default="QUARANTINED", init=False)
    content_verified: bool = field(default=False, init=False)


@dataclass(frozen=True, slots=True)
class OutputClaims:
    job_id: str
    artifacts: tuple[ArtifactClaim, ...]
    total_declared_bytes: int
    status: str = field(default="QUARANTINED", init=False)
    publication_allowed: bool = field(default=False, init=False)


def validate_output_manifest(encoded: bytes, expected: JobBinding, slots: tuple[ArtifactSlot, ...]) -> OutputClaims:
    _require(type(expected) is JobBinding and type(slots) is tuple and len(slots) <= MAX_ARTIFACTS,
        TransportCode.INVALID_ARTIFACT)
    _require(all(type(slot) is ArtifactSlot and slot.binding == expected for slot in slots), TransportCode.IDENTITY_MISMATCH)
    allowed = {slot.artifact_id: slot for slot in slots}
    _require(len(allowed) == len(slots), TransportCode.INVALID_ARTIFACT)
    raw = _decode(encoded, MAX_OUTPUT_MANIFEST_BYTES)
    _require(raw.keys() == expected.fields().keys() | {"artifacts"}, TransportCode.MALFORMED_MANIFEST)
    _binding(raw, expected)
    rows = raw["artifacts"]
    _require(type(rows) is list and len(rows) == len(slots) <= MAX_ARTIFACTS, TransportCode.INVALID_ARTIFACT)
    seen, claims, total = set(), [], 0
    for row in rows:
        _require(type(row) is dict and row.keys() == {"artifact_id", "filename", "kind", "byte_count", "sha256"},
            TransportCode.INVALID_ARTIFACT)
        identity = row["artifact_id"]
        _require(type(identity) is str and identity in allowed and identity not in seen, TransportCode.INVALID_ARTIFACT)
        slot = allowed[identity]
        _require(type(row["filename"]) is str and row["filename"] == slot.filename
            and type(row["kind"]) is str and row["kind"] == "regular", TransportCode.INVALID_ARTIFACT)
        size = row["byte_count"]
        _require(_integer(size, 0, MAX_ARTIFACT_BYTES) and size <= MAX_OUTPUT_BYTES - total, TransportCode.INVALID_LENGTH)
        _require(_sha256(row["sha256"]), TransportCode.DIGEST_MISMATCH)
        total += size
        seen.add(identity)
        claims.append(ArtifactClaim(identity, slot.filename, size, row["sha256"]))
    return OutputClaims(expected.job_id, tuple(claims), total)
