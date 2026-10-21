"""Opaque sessions, atomic revocation and durable creation admission limits.

Only high-entropy credential hashes are persisted. Raw credentials and derived
CSRF tokens are never written to SQLite, audit events or application logs.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import hmac
import ipaddress
import re
import secrets
import sqlite3
import time
from uuid import uuid4

from backend.config import Settings
from backend.security.lifecycle import LifecycleCoordinator
from backend.storage.database import Database, DatabaseVersionError


class SessionError(Exception):
    """Reviewed public status without sensitive exception text."""

    def __init__(self, status_code: int, *, retry_after: int | None = None) -> None:
        super().__init__()
        self.status_code = status_code
        self.retry_after = retry_after


@dataclass(frozen=True)
class SessionPrincipal:
    session_id: str
    audit_pseudonym: str
    expires_at: int
    auth_token_hash: str = field(repr=False)
    csrf_token: str = field(repr=False)


@dataclass(frozen=True)
class IssuedSession:
    principal: SessionPrincipal
    credential: str = field(repr=False)


def credential_hash(credential: str) -> str:
    """SHA-256 is suitable here for uniformly random 256-bit bearer credentials."""
    return hashlib.sha256(credential.encode("ascii")).hexdigest()


def csrf_token_for(credential: str) -> str:
    """Bind CSRF proof to this session without a separate server secret or DB value."""
    return hmac.new(credential.encode("ascii"), b"sheetsafe-csrf-v1", hashlib.sha256).hexdigest()


def utc_now() -> int:
    return int(time.time())


def require_active_session(connection: sqlite3.Connection, principal: SessionPrincipal) -> None:
    """Recheck within each future mutation transaction to close revocation races."""
    found = connection.execute(
        """SELECT 1 FROM sessions WHERE session_id=? AND auth_token_hash=?
            AND revoked_at IS NULL AND deletion_requested_at IS NULL
            AND mode='synthetic' AND expires_at>?""",
        (principal.session_id, principal.auth_token_hash, utc_now()),
    ).fetchone()
    if found is None:
        raise SessionError(401)


class SessionService:
    def __init__(self, database: Database, settings: Settings, lifecycle: LifecycleCoordinator | None = None) -> None:
        self.database = database
        self.settings = settings
        self.lifecycle = lifecycle if lifecycle is not None else LifecycleCoordinator(database, settings)

    @contextmanager
    def _scope(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        try:
            manager = self.database.transaction() if write else self.database.connection()
            with manager as connection:
                yield connection
        except (sqlite3.Error, OSError, DatabaseVersionError):
            raise SessionError(503) from None

    @staticmethod
    def _authenticate(connection: sqlite3.Connection, credential: str) -> SessionPrincipal:
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", credential):
            raise SessionError(401)
        token_hash = credential_hash(credential)
        row = connection.execute(
            """SELECT session_id, audit_pseudonym, expires_at FROM sessions
                WHERE auth_token_hash=? AND revoked_at IS NULL AND deletion_requested_at IS NULL
                AND mode='synthetic' AND expires_at>?""",
            (token_hash, utc_now()),
        ).fetchone()
        if row is None:
            raise SessionError(401)
        return SessionPrincipal(row["session_id"], row["audit_pseudonym"], row["expires_at"],
                                token_hash, csrf_token_for(credential))

    def authenticate(self, credential: str) -> SessionPrincipal:
        with self._scope() as connection:
            return self._authenticate(connection, credential)

    def _admit(self, connection: sqlite3.Connection, client_ip: str, now: int) -> None:
        if self.lifecycle.admissions_paused(connection):
            raise SessionError(503)
        try:
            canonical_ip = str(ipaddress.ip_address(client_ip))
        except ValueError:
            raise SessionError(400) from None
        window = now - now % 60
        retry_after = 60 - now % 60
        connection.execute("DELETE FROM session_creation_limits WHERE window_start < ?", (window,))
        buckets = (
            ("global", "0" * 64, self.settings.session_creations_global_per_minute),
            ("ip", hashlib.sha256(canonical_ip.encode("ascii")).hexdigest(),
             self.settings.session_creations_per_ip_per_minute),
        )
        # All checks precede inserts: distinct attacking IPs cannot grow the table
        # once the global cap is reached. The writer transaction serializes workers.
        for scope, key_hash, limit in buckets:
            row = connection.execute(
                "SELECT request_count FROM session_creation_limits WHERE scope=? AND key_hash=? AND window_start=?",
                (scope, key_hash, window),
            ).fetchone()
            if row is not None and row[0] >= limit:
                raise SessionError(429, retry_after=retry_after)
        if connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] >= self.settings.max_session_records:
            # Fail closed until a later lifecycle coordinator safely purges records.
            # Never delete metadata that might still coordinate files/running work.
            raise SessionError(429, retry_after=60)
        for scope, key_hash, _ in buckets:
            connection.execute(
                """INSERT INTO session_creation_limits(scope, key_hash, window_start, request_count)
                    VALUES (?, ?, ?, 1) ON CONFLICT(scope, key_hash) DO UPDATE SET
                    request_count=CASE WHEN window_start=excluded.window_start
                        THEN request_count+1 ELSE 1 END, window_start=excluded.window_start""",
                (scope, key_hash, window),
            )

    def create(self, client_ip: str) -> IssuedSession:
        credential = secrets.token_urlsafe(32)
        session_id, pseudonym = uuid4().hex, uuid4().hex
        with self._scope(write=True) as connection:
            now = utc_now()
            self._admit(connection, client_ip, now)
            expires_at = now + self.settings.session_lifetime_seconds
            connection.execute(
                """INSERT INTO sessions(session_id, auth_token_hash, audit_pseudonym, mode,
                    created_at, expires_at) VALUES (?, ?, ?, 'synthetic', ?, ?)""",
                (session_id, credential_hash(credential), pseudonym, now, expires_at),
            )
            self.database.append_audit_event(
                connection, session_pseudonym=pseudonym, event_type="SESSION_CREATED", build_version="0.1.0",
            )
        principal = SessionPrincipal(session_id, pseudonym, expires_at,
                                     credential_hash(credential), csrf_token_for(credential))
        return IssuedSession(principal, credential)

    def revoke(self, credential: str, session_id: str) -> str:
        with self._scope(write=True) as connection:
            principal = self._authenticate(connection, credential)
            if principal.session_id != session_id:
                raise SessionError(404)
            return self.lifecycle.request_cleanup(connection, session_id, reason="MANUAL", now=utc_now())
