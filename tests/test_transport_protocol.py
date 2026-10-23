"""Adversarial pure metadata/framing tests; no transport, parsing or execution."""

from dataclasses import FrozenInstanceError, replace
import hashlib
import json
import socket
import subprocess

import pytest

from runner import transport_protocol as protocol
from runner.policy import FixtureRequest, SandboxPolicy


PRIVATE = "synthetic-private-value-never-log"


@pytest.fixture(autouse=True)
def no_external_io(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Pure validation attempted external I/O")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


@pytest.fixture
def manifest():
    return protocol.InputManifest.for_payload(protocol.JobBinding("session_a", "run_a", 1), b"synthetic data\n")


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode()


def changed_header(frame, field, value):
    fields = list(protocol.FRAME_HEADER.unpack(frame[:protocol.FRAME_HEADER.size]))
    fields[field] = value
    return protocol.FRAME_HEADER.pack(*fields) + frame[protocol.FRAME_HEADER.size:]


def wire(manifest, payload):
    return [protocol.encode_frame(manifest, index, payload[offset:offset + protocol.MAX_DATA_BYTES])
        for index, offset in enumerate(range(0, len(payload), protocol.MAX_DATA_BYTES))]


def test_server_identity_and_manifest_round_trip_do_not_grant_authority(manifest):
    other = protocol.JobBinding("session_a", "run_a", 1)
    assert other.job_id != manifest.binding.job_id and len(other.job_id) == 32
    assert protocol.validate_manifest(manifest.to_bytes(), manifest) is manifest
    assert protocol.FIXTURE_ID == FixtureRequest("smoke-v1").fixture_id
    assert not SandboxPolicy().execution_enabled
    with pytest.raises(TypeError):
        protocol.JobBinding("session_a", "run_a", 1, job_id="caller")
    with pytest.raises(ValueError):
        replace(manifest.binding, job_id="caller")
    with pytest.raises(FrozenInstanceError):
        manifest.binding.run_id = "other"


@pytest.mark.parametrize("value", [True, False, 0, -1, 2**63, 1.0, "1", None])
def test_invalid_lease_epoch_types_and_bounds(value):
    with pytest.raises(protocol.TransportError):
        protocol.JobBinding("session", "run", value)


@pytest.mark.parametrize("value", [None, [], "", "a" * 129, "../other", "/absolute", "C:\\private", "space id", "é", "line\n"])
def test_identifier_bounds_and_canonical_encoding(value):
    with pytest.raises(protocol.TransportError):
        protocol.JobBinding(value, "run", 1)


@pytest.mark.parametrize("key", list(protocol.InputManifest.for_payload(protocol.JobBinding("s", "r", 1), b"x").fields()))
def test_every_manifest_field_is_mandatory(manifest, key):
    body = manifest.fields()
    del body[key]
    with pytest.raises(protocol.TransportError):
        protocol.validate_manifest(encoded(body), manifest)


@pytest.mark.parametrize("key,value", [
    ("image", "caller:latest"), ("command", ["sh"]), ("host_path", "/etc/shadow"),
    ("mounts", ["/:/host"]), ("privileged", True), ("policy", {}), ("success", True),
])
def test_unknown_authority_or_runtime_fields_rejected(manifest, key, value):
    body = manifest.fields() | {key: value}
    with pytest.raises(protocol.TransportError):
        protocol.validate_manifest(encoded(body), manifest)


@pytest.mark.parametrize("key,value", [
    ("protocol_version", 2), ("protocol_version", True), ("fixture_id", "dataset-v1"),
    ("job_id", "f" * 32), ("session_id", "other"), ("run_id", "other"),
    ("lease_epoch", True), ("lease_epoch", 2), ("payload_length", True),
    ("payload_length", -1), ("payload_length", 0), ("payload_length", protocol.MAX_PAYLOAD_BYTES + 1),
    ("payload_length", 1), ("sha256", "f" * 64), ("sha256", "A" * 64),
    ("metadata", {"purpose": PRIVATE}), ("metadata", {"purpose": "synthetic-transport-check", "path": PRIVATE}),
])
def test_modified_claims_cannot_replace_expected_server_manifest(manifest, key, value, caplog):
    body = manifest.fields()
    body[key] = value
    with pytest.raises(protocol.TransportError) as error:
        protocol.validate_manifest(encoded(body), manifest)
    assert PRIVATE not in str(error.value) + caplog.text


@pytest.mark.parametrize("data", [
    b"", b"\xff", b"[]", b"null", b"{} trailing", b'{"x":NaN}', b'{"x":Infinity}',
    b'{"x":1.0}', b'{"x":1,"x":2}', b'{"metadata":{"x":1,"x":2}}',
    b'{"x":99999999999999999999999999999999}', b"[" * 1500 + b"]" * 1500,
    b"x" * (protocol.MAX_MANIFEST_BYTES + 1),
], ids=["empty", "utf8", "list", "null", "trailing", "nan", "infinity", "float", "duplicate", "nested-duplicate", "big-int", "depth", "size"])
def test_malformed_bounded_json_is_rejected(manifest, data):
    with pytest.raises(protocol.TransportError):
        protocol.validate_manifest(data, manifest)


@pytest.mark.parametrize("length", [1, protocol.MAX_DATA_BYTES - 1, protocol.MAX_DATA_BYTES,
    protocol.MAX_DATA_BYTES + 1, protocol.MAX_PAYLOAD_BYTES])
def test_frame_boundaries_and_streaming_digest(length):
    payload = b"x" * length
    manifest = protocol.InputManifest.for_payload(protocol.JobBinding("s", "r", 1), payload)
    validator = protocol.FrameValidator(manifest)
    for frame in wire(manifest, payload):
        for offset in range(0, len(frame), 97):
            validator.feed(frame[offset:offset + 97])
            assert validator.buffered_bytes <= protocol.FRAME_HEADER.size
    evidence = validator.finish()
    assert evidence.received_bytes == length and evidence.sha256 == hashlib.sha256(payload).hexdigest()
    assert not evidence.execution_enabled
    with pytest.raises(protocol.TransportError, match="CLOSED"):
        validator.feed(b"x")


def test_every_split_and_single_byte_fragmentation_preserve_framing(manifest):
    frame = protocol.encode_frame(manifest, 0, b"synthetic data\n")
    for split in range(1, len(frame)):
        validator = protocol.FrameValidator(manifest)
        validator.feed(frame[:split])
        validator.feed(frame[split:])
        assert validator.finish().received_bytes == manifest.payload_length
    validator = protocol.FrameValidator(manifest)
    for value in frame:
        validator.feed(bytes([value]))
    validator.finish()


@pytest.mark.parametrize("field,value", [(0, b"BAD!"), (1, 2), (2, b"f" * 16), (3, b"f" * 32),
    (4, 1), (5, 0), (5, protocol.MAX_DATA_BYTES + 1), (5, 2**32 - 1)])
def test_bad_headers_fail_before_payload_is_accepted_and_poison_instance(manifest, field, value):
    validator = protocol.FrameValidator(manifest)
    frame = protocol.encode_frame(manifest, 0, b"synthetic data\n")
    with pytest.raises(protocol.TransportError) as first:
        validator.feed(changed_header(frame, field, value))
    assert validator.buffered_bytes == 0
    with pytest.raises(protocol.TransportError) as second:
        validator.feed(frame)
    assert second.value.code == first.value.code
    with pytest.raises(protocol.TransportError):
        validator.finish()


@pytest.mark.parametrize("cut", [0, 1, protocol.FRAME_HEADER.size - 1, protocol.FRAME_HEADER.size, -1])
def test_missing_header_or_payload_is_truncated_at_eof(manifest, cut):
    validator = protocol.FrameValidator(manifest)
    frame = protocol.encode_frame(manifest, 0, b"synthetic data\n")
    if frame[:cut]:
        validator.feed(frame[:cut])
    with pytest.raises(protocol.TransportError, match="TRUNCATED"):
        validator.finish()


def test_reordered_duplicate_and_trailing_frames_rejected():
    payload = b"x" * (protocol.MAX_DATA_BYTES + 1)
    manifest = protocol.InputManifest.for_payload(protocol.JobBinding("s", "r", 1), payload)
    first, second = wire(manifest, payload)
    for frames in ((second,), (first, first), (first, second, second), (first, second, b"x")):
        validator = protocol.FrameValidator(manifest)
        with pytest.raises(protocol.TransportError):
            for frame in frames:
                validator.feed(frame)


def test_mutated_payload_needs_independently_matching_digest(manifest):
    validator = protocol.FrameValidator(manifest)
    frame = protocol.encode_frame(manifest, 0, b"synthetic data\n")
    validator.feed(frame[:-1] + b"!")
    with pytest.raises(protocol.TransportError, match="DIGEST_MISMATCH"):
        validator.finish()


@pytest.mark.parametrize("chunk", [None, "bytes", bytearray(b"x"), b"", b"x" * (protocol.MAX_FRAME_BYTES + 1)],
    ids=["none", "str", "mutable", "empty", "oversized"])
def test_bounded_immutable_feed_inputs_only(manifest, chunk):
    with pytest.raises(protocol.TransportError):
        protocol.FrameValidator(manifest).feed(chunk)


def output_body(binding, slots, sizes=None):
    sizes = sizes if sizes is not None else [1] * len(slots)
    return binding.fields() | {"artifacts": [{"artifact_id": slot.artifact_id, "filename": slot.filename,
        "kind": "regular", "byte_count": size, "sha256": "a" * 64} for slot, size in zip(slots, sizes)]}


@pytest.mark.parametrize("count", [0, 1, 10])
def test_output_slots_are_server_owned_and_claims_remain_quarantined(manifest, count):
    slots = tuple(protocol.ArtifactSlot(manifest.binding, "csv") for _ in range(count))
    result = protocol.validate_output_manifest(encoded(output_body(manifest.binding, slots)), manifest.binding, slots)
    assert result.status == "QUARANTINED" and not result.publication_allowed
    assert all(not claim.content_verified and claim.status == "QUARANTINED" for claim in result.artifacts)
    with pytest.raises(FrozenInstanceError):
        result.publication_allowed = True
    with pytest.raises(TypeError):
        protocol.ArtifactSlot(manifest.binding, "csv", artifact_id="caller")


@pytest.mark.parametrize("filename", ["../outside.csv", "/etc/passwd", "C:\\private.csv", "\\\\host\\data",
    "sub/file.csv", "a:stream", "é.csv", "A.csv", "file.csv.", "file.csv ", "./file.csv", "file\x00.csv"])
def test_artifact_paths_must_exactly_match_canonical_issued_name(manifest, filename):
    slot = protocol.ArtifactSlot(manifest.binding, "csv")
    body = output_body(manifest.binding, (slot,))
    body["artifacts"][0]["filename"] = filename
    with pytest.raises(protocol.TransportError):
        protocol.validate_output_manifest(encoded(body), manifest.binding, (slot,))


@pytest.mark.parametrize("key,value", [("kind", "symlink"), ("kind", "hardlink"), ("kind", "fifo"),
    ("kind", "directory"), ("kind", "device"), ("kind", "socket"), ("link_target", "/private"),
    ("status", "VALIDATED"), ("artifact_id", "f" * 32), ("sha256", "invalid"),
    ("byte_count", True), ("byte_count", -1), ("byte_count", protocol.MAX_ARTIFACT_BYTES + 1)])
def test_unsafe_artifact_declarations_rejected(manifest, key, value):
    slot = protocol.ArtifactSlot(manifest.binding, "csv")
    body = output_body(manifest.binding, (slot,))
    body["artifacts"][0][key] = value
    with pytest.raises(protocol.TransportError):
        protocol.validate_output_manifest(encoded(body), manifest.binding, (slot,))


def test_output_count_and_combined_byte_limits_are_independent(manifest):
    slots = tuple(protocol.ArtifactSlot(manifest.binding, "json") for _ in range(3))
    at_limit = output_body(manifest.binding, slots, [protocol.MAX_ARTIFACT_BYTES] * 2 + [0])
    result = protocol.validate_output_manifest(encoded(at_limit), manifest.binding, slots)
    assert result.total_declared_bytes == protocol.MAX_OUTPUT_BYTES
    at_limit["artifacts"][-1]["byte_count"] = 1
    with pytest.raises(protocol.TransportError):
        protocol.validate_output_manifest(encoded(at_limit), manifest.binding, slots)
    eleven = tuple(protocol.ArtifactSlot(manifest.binding, "json") for _ in range(11))
    with pytest.raises(protocol.TransportError):
        protocol.validate_output_manifest(encoded(output_body(manifest.binding, eleven)), manifest.binding, eleven)


def test_duplicate_missing_and_foreign_artifact_slots_rejected(manifest):
    slots = tuple(protocol.ArtifactSlot(manifest.binding, "png") for _ in range(2))
    body = output_body(manifest.binding, slots)
    body["artifacts"][1] = body["artifacts"][0].copy()
    with pytest.raises(protocol.TransportError):
        protocol.validate_output_manifest(encoded(body), manifest.binding, slots)
    body = output_body(manifest.binding, slots)
    body["artifacts"].pop()
    with pytest.raises(protocol.TransportError):
        protocol.validate_output_manifest(encoded(body), manifest.binding, slots)
    foreign = protocol.ArtifactSlot(protocol.JobBinding("other", "run", 1), "png")
    with pytest.raises(protocol.TransportError):
        protocol.validate_output_manifest(encoded(output_body(manifest.binding, (foreign,))), manifest.binding, (foreign,))


@pytest.mark.parametrize("file_type", ["py", "html", "svg", "xlsx", "CSV", "../csv", None])
def test_only_inert_output_slot_types_are_allowed(manifest, file_type):
    with pytest.raises(protocol.TransportError):
        protocol.ArtifactSlot(manifest.binding, file_type)


@pytest.mark.parametrize("payload", [b"", b"x" * (protocol.MAX_PAYLOAD_BYTES + 1), bytearray(b"x"), "x"],
    ids=["empty", "oversized", "mutable", "string"])
def test_input_factory_does_not_accept_unbounded_or_mutable_payloads(manifest, payload):
    with pytest.raises(protocol.TransportError):
        protocol.InputManifest.for_payload(manifest.binding, payload)


@pytest.mark.parametrize("sequence", [True, -1, 2**32, "0"])
def test_encoder_cannot_coerce_sequence_fields(manifest, sequence):
    with pytest.raises(protocol.TransportError):
        protocol.encode_frame(manifest, sequence, b"synthetic data\n")


@pytest.mark.parametrize("field,value", [("job_id", "f" * 32), ("session_id", "other"),
    ("run_id", "other"), ("lease_epoch", 2), ("protocol_version", True), ("fixture_id", "other")])
def test_output_claims_cannot_change_job_owner_or_protocol(manifest, field, value):
    body = output_body(manifest.binding, ())
    body[field] = value
    with pytest.raises(protocol.TransportError):
        protocol.validate_output_manifest(encoded(body), manifest.binding, ())


def test_output_missing_fields_duplicate_json_and_size_limits(manifest):
    slot = protocol.ArtifactSlot(manifest.binding, "csv")
    for field in ("artifact_id", "filename", "kind", "byte_count", "sha256"):
        body = output_body(manifest.binding, (slot,))
        del body["artifacts"][0][field]
        with pytest.raises(protocol.TransportError):
            protocol.validate_output_manifest(encoded(body), manifest.binding, (slot,))
    for data in (b'{"artifacts":[],"artifacts":[]}', b"x" * (protocol.MAX_OUTPUT_MANIFEST_BYTES + 1)):
        with pytest.raises(protocol.TransportError):
            protocol.validate_output_manifest(data, manifest.binding, (slot,))
