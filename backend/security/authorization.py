"""Ownership guards consume trusted DB metadata, never a caller-supplied owner.

Call these inside the same transaction as future reads/mutations. Artifact owners
must come from trusted artifact/run metadata; event streams must filter by the
principal's audit pseudonym as well as validating the parent run's ownership.
"""

import sqlite3

from backend.security.sessions import SessionError, SessionPrincipal, require_active_session


def require_owner(
    connection: sqlite3.Connection, principal: SessionPrincipal, owner_session_id: str,
) -> None:
    """Reusable guard for datasets, runs, events and future artifact metadata."""
    require_active_session(connection, principal)
    if owner_session_id != principal.session_id:
        raise SessionError(404)


def owned_dataset(connection: sqlite3.Connection, principal: SessionPrincipal, dataset_id: str) -> sqlite3.Row:
    require_active_session(connection, principal)
    row = connection.execute(
        "SELECT * FROM datasets WHERE dataset_id=? AND session_id=?", (dataset_id, principal.session_id),
    ).fetchone()
    if row is None:
        raise SessionError(404)
    return row


def owned_run(connection: sqlite3.Connection, principal: SessionPrincipal, run_id: str) -> sqlite3.Row:
    require_active_session(connection, principal)
    row = connection.execute(
        "SELECT * FROM runs WHERE run_id=? AND session_id=?", (run_id, principal.session_id),
    ).fetchone()
    if row is None:
        raise SessionError(404)
    return row


def owned_audit_event(
    connection: sqlite3.Connection, principal: SessionPrincipal, event_id: str,
) -> sqlite3.Row:
    require_active_session(connection, principal)
    row = connection.execute(
        "SELECT * FROM audit_events WHERE event_id=? AND session_pseudonym=?",
        (event_id, principal.audit_pseudonym),
    ).fetchone()
    if row is None:
        raise SessionError(404)
    if row["run_id"] is not None:
        owned_run(connection, principal, row["run_id"])
    return row
