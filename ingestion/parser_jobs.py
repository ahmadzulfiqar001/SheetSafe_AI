"""Versioned, transport-neutral parser job contracts. No authentication or I/O.

Expected jobs come from trusted control-plane state; matching JSON/IDs never
proves current session authorization, a DB lease, runtime isolation or teardown.
"""

from enum import StrEnum
import json
from typing import Literal
from uuid import uuid4

from pydantic import Field, field_validator, model_validator

from ingestion.contracts import (
    Contract, Identifier, IngestionCode, IngestionRequest, MAX_PROFILE_BYTES,
    ParserResult, validate_profile_result,
)


MAX_JOB_BYTES = 8192
MAX_REPLY_BYTES = MAX_PROFILE_BYTES + 4096
SOURCE_CHUNK_BYTES = 64 * 1024


class WorkerCode(StrEnum):
    INVALID_JOB = "INVALID_JOB"
    BINDING_MISMATCH = "BINDING_MISMATCH"
    STALE_LEASE = "STALE_LEASE"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"
    INTERRUPTED = "INTERRUPTED"
    WORKER_FAILED = "WORKER_FAILED"
    TRANSPORT_FAILED = "TRANSPORT_FAILED"
    INVALID_REPLY = "INVALID_REPLY"


class WorkerError(ValueError):
    def __init__(self, code: WorkerCode):
        self.code = code
        super().__init__(f"Parser worker failed: {code.value}.")


class ParserJob(Contract):
    protocol_version: Literal[1] = 1
    job_id: Identifier
    run_id: Identifier
    lease_epoch: int = Field(ge=1, le=2**63 - 1)
    operation: Literal["PARSE_CSV", "PARSE_XLSX"]
    request: IngestionRequest = Field(repr=False)

    @field_validator("protocol_version", mode="before")
    @classmethod
    def strict_version(cls, value):
        if type(value) is not int:
            raise ValueError("Invalid protocol")
        return value

    @model_validator(mode="after")
    def consistent(self):
        if self.operation != {"csv": "PARSE_CSV", "xlsx": "PARSE_XLSX"}[self.request.metadata.file_type]:
            raise ValueError("Operation and format differ")
        return self

    @classmethod
    def for_request(cls, request: IngestionRequest, *, run_id: str, lease_epoch: int):
        """Trusted constructor generates job ID; caller must first authorize DB context."""
        return cls(job_id=uuid4().hex, run_id=run_id, lease_epoch=lease_epoch,
            operation="PARSE_CSV" if request.metadata.file_type == "csv" else "PARSE_XLSX", request=request)


class WorkerFailure(Contract):
    state: Literal["FAILED", "CANCELLED", "TIMED_OUT", "INTERRUPTED"]
    code: WorkerCode | IngestionCode

    @model_validator(mode="after")
    def consistent(self):
        expected = self.code.value if self.code.value in {"CANCELLED", "TIMED_OUT", "INTERRUPTED"} else "FAILED"
        if self.state != expected:
            raise ValueError("Invalid failure state")
        return self


class WorkerReply(Contract):
    protocol_version: Literal[1] = 1
    job_id: Identifier
    run_id: Identifier
    lease_epoch: int = Field(ge=1, le=2**63 - 1)
    status: Literal["PROFILED_SYNTHETIC", "NEEDS_CLARIFICATION", "FAILED", "CANCELLED", "TIMED_OUT", "INTERRUPTED"]
    result: ParserResult | None = Field(default=None, repr=False)
    failure: WorkerFailure | None = None

    @field_validator("protocol_version", mode="before")
    @classmethod
    def strict_version(cls, value):
        if type(value) is not int:
            raise ValueError("Invalid protocol")
        return value

    @model_validator(mode="after")
    def consistent(self):
        success = self.status in {"PROFILED_SYNTHETIC", "NEEDS_CLARIFICATION"}
        if success:
            if self.result is None or self.failure is not None or self.result.state != self.status:
                raise ValueError("Invalid result state")
        elif self.result is not None or self.failure is None or self.status != self.failure.state:
            raise ValueError("Invalid failure state")
        return self


def _decode(encoded: object, model: type[Contract], maximum: int, code: WorkerCode):
    try:
        if type(encoded) is not bytes or not 0 < len(encoded) <= maximum:
            raise ValueError()
        def unique(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ValueError()
                result[key] = value
            return result
        def invalid(_):
            raise ValueError()
        json.loads(encoded, object_pairs_hook=unique, parse_constant=invalid)
        return model.model_validate_json(encoded)
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise WorkerError(code) from None


def validate_job(encoded: bytes, expected: ParserJob) -> ParserJob:
    job = _decode(encoded, ParserJob, MAX_JOB_BYTES, WorkerCode.INVALID_JOB)
    if type(expected) is not ParserJob or job != expected:
        raise WorkerError(WorkerCode.BINDING_MISMATCH)
    return job


def validate_reply(encoded: bytes, expected: ParserJob) -> WorkerReply:
    if type(expected) is not ParserJob:
        raise WorkerError(WorkerCode.BINDING_MISMATCH)
    reply = _decode(encoded, WorkerReply, MAX_REPLY_BYTES, WorkerCode.INVALID_REPLY)
    if (reply.job_id != expected.job_id or reply.run_id != expected.run_id
            or reply.lease_epoch != expected.lease_epoch):
        raise WorkerError(WorkerCode.BINDING_MISMATCH)
    if reply.result is not None:
        try:
            validate_profile_result(reply.result.model_dump_json().encode("utf-8"), expected.request)
        except ValueError:
            raise WorkerError(WorkerCode.INVALID_REPLY) from None
    return reply
