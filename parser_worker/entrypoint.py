"""Fixed parser operations, fake transport tests only. Production main is CLOSED.

No stdin/file/socket/archive adapter or backend imports. Callback lease checks
are a synthetic harness contract, not authenticated guest-to-control-plane RPC.
OS preemption, dispatch fencing and teardown remain the future broker's duties.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
import sys
import time
from typing import Literal, Protocol

from ingestion.contracts import IngestionCode, IngestionError, MAX_SOURCE_BYTES
from ingestion.parser_jobs import (
    MAX_JOB_BYTES, ParserJob, SOURCE_CHUNK_BYTES, WorkerCode, WorkerError, WorkerFailure,
    WorkerReply, validate_job, validate_reply,
)
from parser_worker.common import ParseControl, verify_source


IO_SECONDS = 1.0
MAX_SOURCE_READS = 4096


class ParserTransport(Protocol):
    """Future reviewed transport must bound/preempt I/O; no implementation here."""

    def receive_job(self, *, max_bytes: int, timeout: float) -> bytes: ...
    def receive_source(self, *, max_bytes: int, timeout: float) -> bytes | None: ...
    def send_reply(self, encoded: bytes, *, timeout: float) -> None: ...
    def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class FixtureWorkerReceipt:
    reply: bytes | None = field(repr=False)
    delivery: Literal["NOT_ATTEMPTED", "RETURNED", "UNCERTAIN"]
    stream_close_returned: bool
    error: WorkerCode | None
    runtime_verified: bool = field(default=False, init=False)
    cleanup_verified: bool = field(default=False, init=False)
    publication_allowed: bool = field(default=False, init=False)


def _profile(job: ParserJob, source: bytes, control: ParseControl):
    # Fixed imports, never an import/module/callable name selected by a request.
    if job.operation == "PARSE_CSV":
        from parser_worker.csv_parser import profile_csv_fixture
        return profile_csv_fixture(source, job.request, control=control)
    if job.operation == "PARSE_XLSX":
        from parser_worker.xlsx_parser import profile_xlsx_fixture
        return profile_xlsx_fixture(source, job.request, control=control)
    raise WorkerError(WorkerCode.INVALID_JOB)


def _failure(job: ParserJob, code: WorkerCode | IngestionCode) -> WorkerReply:
    state = code.value if code.value in {"CANCELLED", "TIMED_OUT", "INTERRUPTED"} else "FAILED"
    return WorkerReply(job_id=job.job_id, run_id=job.run_id, lease_epoch=job.lease_epoch,
        status=state, failure=WorkerFailure(state=state, code=code))


def run_fixture_worker(expected: ParserJob, transport: ParserTransport, *,
        lease_is_current: Callable[[ParserJob], bool], cancelled: Callable[[], bool] = lambda: False,
        clock: Callable[[], float] = time.monotonic) -> FixtureWorkerReceipt:
    """One synthetic job, no retries or persistence. Does not authorize real I/O.

    Expected context and callbacks must be trusted. Their eventual production
    authentication/liveness is not supplied by a matching manifest or this fake.
    Native crashes/unresponsive calls need external supervision, not this catch.
    """
    reply, delivery, closed, error = None, "NOT_ATTEMPTED", False, None
    try:
        if type(expected) is not ParserJob:
            raise WorkerError(WorkerCode.INVALID_JOB)
        validate_job(expected.model_dump_json().encode("utf-8"), expected)
        def authorized_cancel():
            if lease_is_current(expected) is not True:
                raise WorkerError(WorkerCode.STALE_LEASE)
            return cancelled()
        try:
            control = ParseControl(clock=clock, cancelled=authorized_cancel)
            control.check()
            incoming = transport.receive_job(max_bytes=MAX_JOB_BYTES, timeout=IO_SECONDS)
            control.check()
            job = validate_job(incoming, expected)
            source = bytearray()
            for _ in range(MAX_SOURCE_READS):
                control.check()
                chunk = transport.receive_source(max_bytes=SOURCE_CHUNK_BYTES, timeout=IO_SECONDS)
                control.check()
                if chunk is None:
                    break
                if type(chunk) is not bytes or not 0 < len(chunk) <= SOURCE_CHUNK_BYTES:
                    raise WorkerError(WorkerCode.TRANSPORT_FAILED)
                if len(source) + len(chunk) > min(MAX_SOURCE_BYTES, job.request.metadata.byte_count):
                    raise IngestionError(IngestionCode.SOURCE_INTEGRITY)
                source.extend(chunk)
            else:
                raise WorkerError(WorkerCode.TRANSPORT_FAILED)
            payload = bytes(source)
            verify_source(payload, job.request, control)
            control.check()
            result = _profile(job, payload, control)
            control.check()
            reply = WorkerReply(job_id=job.job_id, run_id=job.run_id, lease_epoch=job.lease_epoch,
                status=result.state, result=result)
            validate_reply(reply.model_dump_json().encode("utf-8"), expected)
            control.check()
        except (WorkerError, IngestionError) as failure:
            reply = _failure(expected, failure.code)
        except TimeoutError:
            reply = _failure(expected, WorkerCode.TIMED_OUT)
        except InterruptedError:
            reply = _failure(expected, WorkerCode.INTERRUPTED)
        except Exception:
            reply = _failure(expected, WorkerCode.WORKER_FAILED)
        encoded = reply.model_dump_json().encode("utf-8")
        validate_reply(encoded, expected)
        # Failed send may have delivered bytes. Never resend or claim absence.
        delivery = "UNCERTAIN"
        transport.send_reply(encoded, timeout=IO_SECONDS)
        delivery = "RETURNED"
    except WorkerError as failure:
        error = failure.code
    except Exception:
        error = WorkerCode.TRANSPORT_FAILED
    finally:
        try:
            transport.close()
            closed = True
        except Exception:
            error = WorkerCode.TRANSPORT_FAILED
    return FixtureWorkerReceipt(reply.model_dump_json().encode("utf-8") if reply else None,
        delivery, closed, error)


def main(arguments: list[str]) -> int:
    if type(arguments) is not list or arguments:
        print("parser_arguments_rejected", file=sys.stderr)
        return 2
    # No default receiver, environment flag, host path or stdin fallback.
    print("parser_transport_unavailable", file=sys.stderr)
    return 78


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
