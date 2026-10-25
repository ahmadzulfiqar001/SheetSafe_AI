"""Fake I/O and actual synthetic parser fixtures only; no subprocess/daemon."""

import json
from uuid import uuid4

import pytest

from ingestion.parser_jobs import ParserJob, SOURCE_CHUNK_BYTES, validate_reply
from ingestion_fixtures import request, xlsx
from parser_worker import entrypoint as worker


class FakeTransport:
    def __init__(self, job, source):
        self.job = job.model_dump_json().encode()
        self.chunks = [source[i:i+SOURCE_CHUNK_BYTES] for i in range(0, len(source), SOURCE_CHUNK_BYTES)] + [None]
        self.job_reads, self.reads, self.closes, self.sent = 0, 0, 0, []
        self.receive_error = self.send_error = self.close_error = None

    def receive_job(self, *, max_bytes, timeout):
        self.job_reads += 1
        assert max_bytes == 8192 and timeout == 1.0
        if self.receive_error:
            raise self.receive_error
        return self.job

    def receive_source(self, *, max_bytes, timeout):
        self.reads += 1
        assert max_bytes == SOURCE_CHUNK_BYTES and timeout == 1.0
        return self.chunks.pop(0)

    def send_reply(self, encoded, *, timeout):
        assert timeout == 1.0
        self.sent.append(encoded)
        if self.send_error:
            raise self.send_error

    def close(self):
        self.closes += 1
        if self.close_error:
            raise self.close_error


def setup_job(file_type="csv"):
    source = b"name,value\nsynthetic,12\n" if file_type == "csv" else xlsx([["name", "value"], ["synthetic", 12]])
    job = ParserJob.for_request(request(source, file_type), run_id=uuid4().hex, lease_epoch=1)
    return job, source, FakeTransport(job, source)


def run(job, transport, **kwargs):
    return worker.run_fixture_worker(job, transport, lease_is_current=lambda _: True, **kwargs)


@pytest.mark.parametrize("file_type", ["csv", "xlsx"])
def test_fixed_operations_with_synthetic_source_and_no_runtime_claim(file_type):
    job, _, transport = setup_job(file_type)
    receipt = run(job, transport)
    assert receipt.delivery == "RETURNED" and receipt.stream_close_returned and receipt.error is None
    reply = validate_reply(receipt.reply, job)
    assert reply.status == "PROFILED_SYNTHETIC" and reply.result.profile.preview == (("synthetic", "12"),)
    assert transport.closes == 1 and len(transport.sent) == 1
    assert not receipt.cleanup_verified and not receipt.runtime_verified and not receipt.publication_allowed


@pytest.mark.parametrize("change", [{"path": "/etc/passwd"}, {"operation": "RUN_PYTHON"},
    {"command": "sh -c evil"}, {"docker_flags": ["--privileged"]}, {"url": "https://example.invalid"}])
def test_unsafe_worker_metadata_rejected_before_source_reads(change):
    job, _, transport = setup_job()
    transport.job = json.dumps({**job.model_dump(mode="json"), **change}).encode()
    reply = validate_reply(run(job, transport).reply, job)
    assert reply.failure.code.value == "INVALID_JOB" and transport.reads == 0


@pytest.mark.parametrize("field", ["job_id", "run_id", "session_id"])
def test_wrong_context_never_reads_source(field):
    job, _, transport = setup_job()
    raw = job.model_dump(mode="json")
    if field == "session_id":
        raw["request"][field] = uuid4().hex
    else:
        raw[field] = uuid4().hex
    transport.job = json.dumps(raw).encode()
    assert validate_reply(run(job, transport).reply, job).failure.code.value == "BINDING_MISMATCH"
    assert transport.reads == 0


@pytest.mark.parametrize("chunks", [[b"name,value\nwrong,12\n", None], [b"x" * 100, None],
    [b"x" * (SOURCE_CHUNK_BYTES + 1), None], ["/host/path", None], [b"", None], [None]],
    ids=lambda _: "synthetic-chunks")
def test_bad_truncated_oversized_or_nonbyte_source(chunks):
    job, _, transport = setup_job()
    transport.chunks = chunks
    reply = validate_reply(run(job, transport).reply, job)
    assert reply.status == "FAILED" and reply.result is None


@pytest.mark.parametrize("kind,code", [("crash", "WORKER_FAILED"), ("timeout", "TIMED_OUT"),
    ("interrupt", "INTERRUPTED"), ("bad_result", "INVALID_REPLY")])
def test_worker_failure_returns_only_sanitized_terminal_metadata(monkeypatch, kind, code):
    job, _, transport = setup_job()
    original = worker._profile
    def failed(*args):
        if kind == "bad_result":
            result = original(*args)
            return result.model_copy(update={"dataset_id": uuid4().hex})
        error = {"crash": RuntimeError, "timeout": TimeoutError, "interrupt": InterruptedError}[kind]
        raise error("secret spreadsheet cell and credentials")
    monkeypatch.setattr(worker, "_profile", failed)
    receipt = run(job, transport)
    reply = validate_reply(receipt.reply, job)
    assert reply.failure.code.value == code and reply.result is None
    assert b"secret" not in receipt.reply and transport.closes == 1


def test_cancel_stale_and_mid_parse_revocation_fail_closed(monkeypatch):
    job, _, transport = setup_job()
    receipt = worker.run_fixture_worker(job, transport, lease_is_current=lambda _: False)
    assert validate_reply(receipt.reply, job).failure.code.value == "STALE_LEASE"
    assert transport.job_reads == transport.reads == 0
    transport = setup_job()[2]
    receipt = run(job, transport, cancelled=lambda: True)
    assert validate_reply(receipt.reply, job).status == "CANCELLED" and transport.reads == 0
    job, _, transport = setup_job()
    current = [True]
    original = worker._profile
    def revoked(*args):
        result = original(*args)
        current[0] = False
        return result
    monkeypatch.setattr(worker, "_profile", revoked)
    receipt = worker.run_fixture_worker(job, transport, lease_is_current=lambda _: current[0])
    assert validate_reply(receipt.reply, job).failure.code.value == "STALE_LEASE"


def test_transport_timeout_and_ambiguous_send_are_not_retried():
    job, _, transport = setup_job()
    transport.receive_error = TimeoutError("sensitive host path")
    assert validate_reply(run(job, transport).reply, job).status == "TIMED_OUT"
    job, _, transport = setup_job()
    transport.send_error = OSError("response lost after delivery")
    receipt = run(job, transport)
    assert receipt.delivery == "UNCERTAIN" and receipt.error.value == "TRANSPORT_FAILED"
    assert len(transport.sent) == 1 and transport.closes == 1 and not receipt.publication_allowed
    job, _, transport = setup_job()
    transport.close_error = OSError("close failed")
    receipt = run(job, transport)
    assert not receipt.stream_close_returned and receipt.error.value == "TRANSPORT_FAILED"


def test_elapsed_budget_after_io_never_invokes_parser(monkeypatch):
    job, _, transport = setup_job()
    now = [0.0]
    original = transport.receive_source
    def delayed(**kwargs):
        result = original(**kwargs)
        now[0] = 21.0
        return result
    def forbidden(*args):
        raise AssertionError("Expired work must not reach the parser")
    monkeypatch.setattr(transport, "receive_source", delayed)
    monkeypatch.setattr(worker, "_profile", forbidden)
    receipt = run(job, transport, clock=lambda: now[0])
    assert validate_reply(receipt.reply, job).status == "TIMED_OUT" and transport.closes == 1


def test_bounded_source_read_count_rejects_nonterminating_delivery():
    source = b"name\n" + b"x" * 10000
    job = ParserJob.for_request(request(source), run_id=uuid4().hex, lease_epoch=1)
    transport = FakeTransport(job, source)
    transport.chunks = [b"x"] * 10000  # Never delivers EOF before the read budget.
    receipt = run(job, transport)
    assert transport.reads == 4096 and transport.closes == 1
    assert validate_reply(receipt.reply, job).failure.code.value == "TRANSPORT_FAILED"


@pytest.mark.parametrize("args", [["PARSE_CSV"], ["-c", "evil"], ["/etc/passwd"], ["--image=attacker"], "PARSE_XLSX"])
def test_cli_rejects_all_caller_arguments(args, capsys):
    assert worker.main(args) == 2
    assert capsys.readouterr().err == "parser_arguments_rejected\n"


def test_production_entrypoint_has_no_receiver_or_success(capsys):
    assert worker.main([]) == 78
    assert capsys.readouterr().err == "parser_transport_unavailable\n"
