"""Synthetic-only private byte storage and verified lifecycle cleanup.

No public upload/download routes, parsing, execution or validator are added here.
Every write is durably reserved before I/O; a sealed DB row is its commit marker.
The namespace lock spans I/O, while session revocation needs only a short SQLite
transaction. A revoked writer cannot seal or publish its bytes.
"""

import asyncio
from collections.abc import Iterable
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import os
import re
import sqlite3
from threading import Event
import time
from uuid import uuid4

from backend.config import Settings
from backend.security.authorization import owned_run
from backend.security.lifecycle import CleanupContext, CleanupVerification, RetryableCleanupError
from backend.security.sessions import SessionError, SessionPrincipal, require_active_session
from backend.storage.database import Database
from backend.storage.filesystem import UnsafeStorage, directory, namespace_lock


MIB = 1024 * 1024
INPUT_LIMIT = 20 * MIB
PARSED_LIMIT = 100 * MIB
ARTIFACT_LIMIT = 10 * MIB
ARTIFACT_TOTAL = 20 * MIB
ARTIFACT_COUNT = 10
LOG_LIMIT = 64 * 1024
CHUNK_SIZE = 64 * 1024
CATEGORIES = frozenset({"original", "version", "candidate", "temporary", "quarantine", "validated"})
TYPES = {
    "original": frozenset({"csv", "xlsx"}), "version": frozenset({"csv", "json"}),
    "candidate": frozenset({"py"}),
    "temporary": frozenset({"csv", "png", "json", "txt"}),
    "quarantine": frozenset({"csv", "png", "json", "txt", "py"}),
    "validated": frozenset({"csv", "png", "json", "txt", "py"}),
}


@dataclass(frozen=True)
class StoredFile:
    object_id: str
    category: str
    file_type: str
    byte_count: int
    sha256: str


def _id(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{32}", value):
        raise SessionError(404)
    return value


@contextmanager
def _safe_errors():
    try:
        yield
    except (OSError, sqlite3.Error, UnsafeStorage):
        raise SessionError(503) from None


class PrivateStorage:
    def __init__(self, database: Database, settings: Settings):
        self.database, self.root = database, settings.storage_path

    def initialize(self) -> None:
        """Bind an empty dedicated directory to this DB, never adopt user files."""
        with _safe_errors(), directory(self.root.parent) as parent:
            with self.database.transaction() as connection:
                identity = connection.execute("SELECT root_id FROM storage_identity WHERE singleton=1").fetchone()
                if identity is None:
                    with parent.child(self.root.name, create=True) as root:
                        if root.names():
                            raise UnsafeStorage()
                        root_id = uuid4().hex
                        with root.open(".sheetsafe-root", create=True) as stream:
                            stream.write(root_id.encode("ascii"))
                            stream.flush()
                            os.fsync(stream.fileno())
                        root.sync()
                        connection.execute("INSERT INTO storage_identity VALUES (1, ?)", (root_id,))
        self.check_ready()

    @contextmanager
    def _root(self):
        with self.database.connection() as connection:
            identity = connection.execute("SELECT root_id FROM storage_identity WHERE singleton=1").fetchone()
        if identity is None:
            raise UnsafeStorage()
        with directory(self.root) as root:
            with root.open(".sheetsafe-root") as stream:
                if stream.read(33) != identity[0].encode("ascii"):
                    raise UnsafeStorage()
            yield root

    def check_ready(self) -> None:
        with _safe_errors(), self._root() as root, self.database.connection() as connection:
            namespaces = {row[0] for row in connection.execute("SELECT namespace_id FROM storage_namespaces")}
            if root.names() - namespaces - {".sheetsafe-root"}:
                raise UnsafeStorage()

    def _namespace(self, connection, principal: SessionPrincipal) -> str:
        require_active_session(connection, principal)
        row = connection.execute("SELECT * FROM storage_namespaces WHERE session_id=?", (principal.session_id,)).fetchone()
        if row is None:
            namespace = uuid4().hex
            connection.execute("INSERT INTO storage_namespaces(session_id, namespace_id) VALUES (?, ?)",
                               (principal.session_id, namespace))
            return namespace
        if row["cleaned_at"] is not None:
            raise SessionError(401)
        return _id(row["namespace_id"])

    @staticmethod
    def _limit(category: str, file_type: str) -> int:
        if category == "original":
            return INPUT_LIMIT
        if category == "version":
            return PARSED_LIMIT
        if category == "temporary" and file_type == "txt":
            return LOG_LIMIT
        return ARTIFACT_LIMIT

    def store(
        self, principal: SessionPrincipal, *, category: str, file_type: str,
        chunks: Iterable[bytes], byte_count: int, run_id: str | None = None, candidate_version: int = 0,
    ) -> StoredFile:
        """Trusted synthetic ingestion boundary; no caller-selected paths or IDs.

        Chunks must be at most 64 KiB and finish within the I/O budget. Detailed
        format/CSV/XLSX safety validation belongs to future isolated ingestion.
        """
        if category not in CATEGORIES or file_type not in TYPES[category]:
            raise SessionError(415)
        if category == "validated":
            raise SessionError(409)  # No independently verified publication capability yet.
        if type(byte_count) is not int or not 0 < byte_count <= self._limit(category, file_type):
            raise SessionError(413)
        is_input = category in {"original", "version"}
        if (is_input and (run_id is not None or candidate_version != 0)) or (
            not is_input and (not run_id or type(candidate_version) is not int or not 1 <= candidate_version <= 3)
        ):
            raise SessionError(400)
        object_id = uuid4().hex
        with _safe_errors():
            # Reserve the namespace before creating files, so crashes are discoverable.
            with self.database.transaction() as connection:
                namespace = self._namespace(connection, principal)
            with self.database.transaction() as connection:
                require_active_session(connection, principal)
                with self._root() as root, root.child(namespace, create=True):
                    pass
            with self._root() as root, root.child(namespace) as folder, namespace_lock(folder):
                with self.database.transaction() as connection:
                    require_active_session(connection, principal)
                    if not is_input:
                        owned_run(connection, principal, run_id)
                    if category == "original" and connection.execute(
                        "SELECT 1 FROM storage_objects WHERE session_id=? AND category='original'", (principal.session_id,)
                    ).fetchone():
                        raise SessionError(409)
                    if category == "candidate" and connection.execute(
                        "SELECT 1 FROM storage_objects WHERE run_id=? AND candidate_version=? AND category='candidate'",
                        (run_id, candidate_version),
                    ).fetchone():
                        raise SessionError(409)
                    # Candidate source is separate from collected execution artifacts.
                    if category in {"temporary", "quarantine"}:
                        usage = connection.execute(
                            """SELECT count(*), coalesce(sum(byte_count),0) FROM storage_objects
                                WHERE run_id=? AND candidate_version=? AND category IN ('temporary','quarantine','validated')""",
                            (run_id, candidate_version),
                        ).fetchone()
                        if usage[0] >= ARTIFACT_COUNT or usage[1] + byte_count > ARTIFACT_TOTAL:
                            raise SessionError(413)
                    connection.execute(
                        """INSERT INTO storage_objects(object_id,session_id,category,file_type,run_id,
                            candidate_version,byte_count,created_at) VALUES (?,?,?,?,?,?,?,?)""",
                        (object_id, principal.session_id, category, file_type, run_id,
                         candidate_version, byte_count, self.database.now()),
                    )
                    self.database.append_audit_event(
                        connection, session_pseudonym=principal.audit_pseudonym, event_type="STORAGE_STAGED",
                        build_version="0.1.0", run_id=run_id, details={"byte_count": byte_count},
                    )
                # Keep a durable STAGING record even on exceptions. Never silently
                # forget files if immediate unlink or a later DB transaction fails.
                with folder.child(category, create=True) as bucket:
                    digest, written, stop_at = hashlib.sha256(), 0, time.monotonic() + 10
                    with bucket.open(object_id + ".part", create=True) as stream:
                        for chunk in chunks:
                            if time.monotonic() >= stop_at:
                                raise SessionError(503)
                            if not isinstance(chunk, bytes) or len(chunk) > CHUNK_SIZE:
                                raise SessionError(400)
                            written += len(chunk)
                            if written > byte_count:
                                raise SessionError(413)
                            stream.write(chunk)
                            digest.update(chunk)
                        if written != byte_count:
                            raise SessionError(400)
                        stream.flush()
                        os.fsync(stream.fileno())
                    with self.database.transaction() as connection:
                        require_active_session(connection, principal)
                        bucket.rename_new(object_id + ".part", object_id + "." + file_type)
                        connection.execute("UPDATE storage_objects SET state='SEALED', sha256=? WHERE object_id=?",
                                           (digest.hexdigest(), object_id))
                        self.database.append_audit_event(
                            connection, session_pseudonym=principal.audit_pseudonym, event_type="STORAGE_SEALED",
                            build_version="0.1.0", run_id=run_id,
                            details={"byte_count": written, "artifact_sha256": digest.hexdigest()},
                        )
                return StoredFile(object_id, category, file_type, written, digest.hexdigest())

    def read(self, principal: SessionPrincipal, object_id: str) -> bytes:
        """Bounded owner-only internal reads; quarantined bytes have no public route."""
        object_id = _id(object_id)
        with _safe_errors(), self.database.connection() as connection:
            require_active_session(connection, principal)
            row = connection.execute(
                """SELECT o.*, n.namespace_id FROM storage_objects o JOIN storage_namespaces n USING(session_id)
                    WHERE object_id=? AND o.session_id=? AND state='SEALED'""", (object_id, principal.session_id),
            ).fetchone()
        if row is None:
            raise SessionError(404)
        with _safe_errors(), self._root() as root, root.child(_id(row["namespace_id"])) as folder, namespace_lock(folder):
            # Recheck after acquiring the filesystem lock, not just on an old snapshot.
            with self.database.connection() as connection:
                require_active_session(connection, principal)
            with folder.child(row["category"]) as bucket, bucket.open(object_id + "." + row["file_type"]) as stream:
                data = stream.read(min(row["byte_count"], self._limit(row["category"], row["file_type"])) + 1)
            if len(data) != row["byte_count"] or hashlib.sha256(data).hexdigest() != row["sha256"]:
                raise SessionError(503)
            with self.database.connection() as connection:
                require_active_session(connection, principal)
            return data

    def publish(self, principal: SessionPrincipal, object_id: str) -> None:
        """Fail closed until independent validation and runner receipts are wired."""
        _id(object_id)
        with self.database.connection() as connection:
            require_active_session(connection, principal)
        raise SessionError(409)

    async def remove_and_verify(self, context: CleanupContext) -> CleanupVerification:
        # Cancellation must not leave an unobserved deletion thread behind.
        stop = Event()
        task = asyncio.create_task(asyncio.to_thread(self._cleanup, context, stop))
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            stop.set()
            try:
                await asyncio.shield(task)
            except Exception:
                pass
            raise

    def _cleanup(self, context: CleanupContext, stop: Event) -> CleanupVerification:
        def budget() -> None:
            if stop.is_set() or time.monotonic() >= stop_at or self.database.now() >= context.deadline_at:
                raise RetryableCleanupError() from None

        stop_at, removed = time.monotonic() + 1, 0
        try:
            with self.database.connection() as connection:
                job = connection.execute(
                    """SELECT 1 FROM cleanup_requests c JOIN sessions s USING(session_id)
                        WHERE c.request_id=? AND c.session_id=? AND c.state='RUNNING'
                        AND s.revoked_at IS NOT NULL AND s.deletion_requested_at IS NOT NULL""",
                    (context.request_id, context.session_id),
                ).fetchone()
                if job is None:
                    raise UnsafeStorage()
                ns = connection.execute("SELECT * FROM storage_namespaces WHERE session_id=?", (context.session_id,)).fetchone()
                rows = connection.execute("SELECT * FROM storage_objects WHERE session_id=?", (context.session_id,)).fetchall()
                # Legacy references must map to our registry. Absence is not evidence.
                unresolved = connection.execute(
                    """SELECT 1 FROM datasets d WHERE d.session_id=? AND NOT EXISTS(
                        SELECT 1 FROM storage_objects o WHERE o.object_id=d.storage_ref AND o.session_id=d.session_id)
                        UNION ALL SELECT 1 FROM attempts a JOIN runs r USING(run_id)
                        WHERE r.session_id=? AND NOT EXISTS(SELECT 1 FROM storage_objects o
                            WHERE o.object_id=a.code_ref AND o.session_id=r.session_id) LIMIT 1""",
                    (context.session_id, context.session_id),
                ).fetchone()
                if unresolved:
                    raise UnsafeStorage()
            budget()
            with self._root() as root:
                if ns is not None:
                    namespace = _id(ns["namespace_id"])
                    if namespace in root.names():
                        with root.child(namespace) as folder, namespace_lock(folder):
                            if folder.names() - CATEGORIES - {".lock"}:
                                raise UnsafeStorage()
                            for category in sorted(CATEGORIES):
                                budget()
                                if category not in folder.names():
                                    continue
                                with folder.child(category) as bucket:
                                    expected = set()
                                    for row in rows:
                                        if row["category"] == category:
                                            expected.update({_id(row["object_id"]) + ".part", row["object_id"] + "." + row["file_type"]})
                                    names = bucket.names()
                                    if names - expected:
                                        raise UnsafeStorage()
                                    for name in sorted(names):
                                        budget()
                                        if removed >= 64:
                                            raise RetryableCleanupError()
                                        bucket.unlink(name)
                                        removed += 1
                                    if bucket.names():
                                        raise UnsafeStorage()
                                folder.rmdir(category)
                        # Access is already revoked; no new storage caller may acquire
                        # this namespace or create files while we finish removing it.
                        with root.child(namespace) as folder:
                            if folder.names() != {".lock"}:
                                raise UnsafeStorage()
                            folder.unlink(".lock")
                        root.rmdir(namespace)
                    if namespace in root.names():
                        raise UnsafeStorage()
            budget()
            with self.database.transaction() as connection:
                # Keep the registry until the coordinator atomically purges all
                # session metadata. A failed purge must retain reference mappings
                # for idempotent verification on the next claim/restart.
                connection.execute("UPDATE storage_namespaces SET cleaned_at=? WHERE session_id=?",
                                   (self.database.now(), context.session_id))
            return CleanupVerification(context.session_id, True)
        except (PermissionError, BlockingIOError, TimeoutError):
            raise RetryableCleanupError() from None
        except (OSError, sqlite3.Error):
            raise RetryableCleanupError() from None
        except (UnsafeStorage, SessionError):
            raise UnsafeStorage() from None
