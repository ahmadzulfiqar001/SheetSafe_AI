"""Internal synthetic metadata only. Never imports or invokes format parsers.

Reuse existing ownership/storage/dataset rows. No upload route, byte parsing,
worker dispatch, READY transition or publication is implemented in this step.
"""

from contextlib import contextmanager
import hashlib
import re
import sqlite3
from uuid import uuid4

from backend.security.authorization import owned_dataset
from backend.security.sessions import SessionError, SessionPrincipal, require_active_session
from backend.storage.database import Database, DatabaseVersionError
from ingestion.contracts import (
    IngestionCode, IngestionError, IngestionRequest, ParserResult,
    metadata_from_mapping, validate_profile_result,
)


@contextmanager
def _safe_storage():
    try:
        yield
    except (sqlite3.Error, OSError, DatabaseVersionError):
        raise IngestionError(IngestionCode.STORAGE_UNAVAILABLE) from None


def _source(connection, principal, object_id, metadata):
    require_active_session(connection, principal)
    if type(object_id) is not str or re.fullmatch(r"[0-9a-f]{32}", object_id) is None:
        raise SessionError(404)
    record = connection.execute(
        "SELECT * FROM storage_objects WHERE object_id=? AND session_id=? AND category='original' AND state='SEALED'",
        (object_id, principal.session_id),
    ).fetchone()
    if record is None:
        raise SessionError(404)
    if (record["byte_count"] != metadata.byte_count or record["sha256"] != metadata.sha256
            or record["file_type"] != metadata.file_type):
        raise IngestionError(IngestionCode.SOURCE_INTEGRITY)


def prepare_synthetic_request(database: Database, principal: SessionPrincipal,
        object_id: str, metadata: object) -> IngestionRequest:
    """Reserve PENDING metadata for an existing synthetic original, idempotently.

    Caller fields cannot set dataset/session IDs or state. This does not read
    bytes or certify their contents; PrivateStorage and the parser verify bytes.
    """
    declared = metadata_from_mapping(metadata)
    settings = declared.model_dump_json()
    with _safe_storage(), database.transaction() as connection:
        _source(connection, principal, object_id, declared)
        fingerprint = hashlib.sha256((object_id + settings).encode("utf-8")).hexdigest()
        key = "synthetic-ingestion:" + object_id
        existing = connection.execute("SELECT * FROM datasets WHERE session_id=? AND idempotency_key=?",
            (principal.session_id, key)).fetchone()
        if existing is not None:
            owned_dataset(connection, principal, existing["dataset_id"])
            if (existing["request_sha256"] != fingerprint or existing["storage_ref"] != object_id
                    or existing["source_sha256"] != declared.sha256 or existing["byte_count"] != declared.byte_count
                    or existing["file_type"] != declared.file_type):
                raise IngestionError(IngestionCode.STATE_CONFLICT)
            dataset_id = existing["dataset_id"]
            version = connection.execute("SELECT state, parsing_settings_json FROM dataset_versions WHERE dataset_id=? AND version=1",
                (dataset_id,)).fetchone()
            if version is None or version["state"] != "PENDING" or version["parsing_settings_json"] != settings:
                raise IngestionError(IngestionCode.STATE_CONFLICT)
        else:
            dataset_id = uuid4().hex
            connection.execute("""INSERT INTO datasets(dataset_id,session_id,source_sha256,storage_ref,
                file_type,byte_count,idempotency_key,request_sha256,created_at) VALUES (?,?,?,?,?,?,?,?,?)""",
                (dataset_id, principal.session_id, declared.sha256, object_id, declared.file_type,
                    declared.byte_count, key, fingerprint, database.now()))
            connection.execute("""INSERT INTO dataset_versions(dataset_id,version,session_id,parsing_settings_json,created_at)
                VALUES (?,1,?,?,?)""", (dataset_id, principal.session_id, settings, database.now()))
            database.append_audit_event(connection, session_pseudonym=principal.audit_pseudonym,
                event_type="DATASET_CREATED", build_version="0.1.0", timestamp=database.now(),
                details={"byte_count": declared.byte_count, "source_sha256": declared.sha256})
        return IngestionRequest(dataset_id=dataset_id, session_id=principal.session_id, object_id=object_id, metadata=declared)


def check_synthetic_result(database: Database, principal: SessionPrincipal,
        request: IngestionRequest, encoded: bytes) -> ParserResult:
    """Recheck owner/state before and after bounded output validation; never READY.

    Structural validity cannot attest sandbox enforcement, source semantics,
    cleanup or independent numerical validation. Nothing is published/persisted.
    """
    def authorized():
        with _safe_storage(), database.connection() as connection:
            record = owned_dataset(connection, principal, request.dataset_id)
            if (request.session_id != principal.session_id or record["storage_ref"] != request.object_id
                    or record["source_sha256"] != request.metadata.sha256
                    or record["byte_count"] != request.metadata.byte_count or record["file_type"] != request.metadata.file_type):
                raise IngestionError(IngestionCode.SOURCE_INTEGRITY)
            _source(connection, principal, request.object_id, request.metadata)
            version = connection.execute("SELECT state,parsing_settings_json FROM dataset_versions WHERE dataset_id=? AND version=1",
                (request.dataset_id,)).fetchone()
            if (version is None or version["state"] != "PENDING"
                    or version["parsing_settings_json"] != request.metadata.model_dump_json()):
                raise IngestionError(IngestionCode.STATE_CONFLICT)
    authorized()
    result = validate_profile_result(encoded, request)
    authorized()
    return result
