"""Strict job envelopes; IDs/hashes alone do not prove durable authorization."""

import json
from uuid import uuid4

import pytest

from ingestion.parser_jobs import (
    MAX_JOB_BYTES, MAX_REPLY_BYTES, ParserJob, WorkerCode, WorkerError,
    validate_job, validate_reply,
)
from ingestion_fixtures import request, result_fields


def job():
    return ParserJob.for_request(request(b"name\nsynthetic\n"), run_id=uuid4().hex, lease_epoch=1)


def reply_fields(expected):
    return dict(protocol_version=1, job_id=expected.job_id, run_id=expected.run_id,
        lease_epoch=expected.lease_epoch, status="PROFILED_SYNTHETIC", result=result_fields(expected.request))


def test_allowlist_and_generated_binding():
    expected = job()
    assert validate_job(expected.model_dump_json().encode(), expected) == expected
    assert expected.operation == "PARSE_CSV"
    other = ParserJob.for_request(request(b"synthetic", "xlsx"), run_id=uuid4().hex, lease_epoch=2)
    assert other.operation == "PARSE_XLSX" and other.job_id != expected.job_id
    assert validate_reply(json.dumps(reply_fields(expected)).encode(), expected).result is not None


@pytest.mark.parametrize("change", [{"operation": "EXEC"}, {"operation": "PARSE_XLSX"},
    {"operation": "os.system"}, {"command": "python -c evil"}, {"path": "/etc/passwd"},
    {"url": "https://example.invalid"}, {"image": "attacker:latest"}, {"mounts": []},
    {"credentials": "private"}, {"protocol_version": True}, {"protocol_version": 2},
    {"lease_epoch": True}, {"lease_epoch": 0}, {"lease_epoch": "1"}])
def test_unsafe_or_unknown_job_fields_rejected(change):
    expected = job()
    with pytest.raises(WorkerError) as error:
        validate_job(json.dumps({**expected.model_dump(mode="json"), **change}).encode(), expected)
    assert error.value.code is WorkerCode.INVALID_JOB


@pytest.mark.parametrize("field", ["job_id", "run_id", "lease_epoch"])
def test_foreign_or_stale_job_binding_rejected(field):
    expected = job()
    fields = expected.model_dump(mode="json")
    fields[field] = 2 if field == "lease_epoch" else uuid4().hex
    with pytest.raises(WorkerError) as error:
        validate_job(json.dumps(fields).encode(), expected)
    assert error.value.code is WorkerCode.BINDING_MISMATCH


@pytest.mark.parametrize("field", ["dataset_id", "session_id", "object_id"])
def test_nested_ownership_mismatch_rejected(field):
    expected = job()
    fields = expected.model_dump(mode="json")
    fields["request"][field] = uuid4().hex
    with pytest.raises(WorkerError) as error:
        validate_job(json.dumps(fields).encode(), expected)
    assert error.value.code is WorkerCode.BINDING_MISMATCH


def test_dataset_limit_is_not_synthetic_frame_limit():
    from ingestion.contracts import MAX_SOURCE_BYTES
    from runner.transport_protocol import MAX_PAYLOAD_BYTES
    expected = job()
    fields = expected.model_dump(mode="json")
    fields["request"]["metadata"]["byte_count"] = MAX_SOURCE_BYTES
    permitted = ParserJob.model_validate_json(json.dumps(fields))
    assert permitted.request.metadata.byte_count == 20 * 1024**2 > MAX_PAYLOAD_BYTES
    fields["request"]["metadata"]["byte_count"] += 1
    with pytest.raises(WorkerError):
        validate_job(json.dumps(fields).encode(), expected)


@pytest.mark.parametrize("value", [b"{}", b'[]', b'\xff', b'{"a":1,"a":2}', b'{"a":NaN}', b"x" * (MAX_JOB_BYTES + 1)],
    ids=lambda _: "bounded-fixture")
def test_malformed_job_json(value):
    with pytest.raises(WorkerError):
        validate_job(value, job())


@pytest.mark.parametrize("change", [{"status": "READY"}, {"cleanup_verified": True}, {"executable": "python"},
    {"protocol_version": True}, {"lease_epoch": True}, {"result": None}])
def test_unsafe_worker_output_rejected(change):
    expected = job()
    with pytest.raises(WorkerError):
        validate_reply(json.dumps({**reply_fields(expected), **change}).encode(), expected)


def test_reply_profile_and_envelope_bindings_checked():
    expected = job()
    fields = reply_fields(expected)
    fields["result"]["source_sha256"] = "f" * 64
    with pytest.raises(WorkerError) as error:
        validate_reply(json.dumps(fields).encode(), expected)
    assert error.value.code is WorkerCode.INVALID_REPLY
    fields = reply_fields(expected)
    fields["job_id"] = uuid4().hex
    with pytest.raises(WorkerError) as error:
        validate_reply(json.dumps(fields).encode(), expected)
    assert error.value.code is WorkerCode.BINDING_MISMATCH
    with pytest.raises(WorkerError):
        validate_reply(b"x" * (MAX_REPLY_BYTES + 1), expected)
