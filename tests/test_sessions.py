"""Real session credentials, cookies, ownership, CSRF and durable admission tests."""

from concurrent.futures import ThreadPoolExecutor
from http.cookies import SimpleCookie
from pathlib import Path
import secrets
import sqlite3
from time import time
from typing import Annotated

from fastapi import Depends, Request
from fastapi.testclient import TestClient
import pytest

from backend.api.dependencies import authenticated_session
from backend.config import Settings
from backend.main import create_app
from backend.security.authorization import owned_audit_event, owned_dataset, owned_run, require_owner
from backend.security.sessions import SessionError, SessionPrincipal, SessionService, credential_hash
from backend.storage.database import Database
from backend.storage.schema import APPLICATION_ID, MIGRATIONS, SCHEMA_VERSION


ORIGIN = "https://testserver"
BOOTSTRAP = {"Origin": ORIGIN, "X-SheetSafe-Request": "1"}


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(_env_file=None, environment="test", database_path=tmp_path / "sessions.sqlite3",
                    allowed_origins=(ORIGIN,), database_busy_timeout_ms=2000)


def application_with_probe(settings: Settings):
    application = create_app(settings)

    @application.get("/_test/me")
    def me(principal: Annotated[SessionPrincipal, Depends(authenticated_session)]):
        return {"session_id": principal.session_id, "expires_at": principal.expires_at}

    @application.get("/_test/datasets/{dataset_id}")
    def dataset(
        dataset_id: str, request: Request,
        principal: Annotated[SessionPrincipal, Depends(authenticated_session)],
    ):
        with request.app.state.database.connection() as connection:
            row = owned_dataset(connection, principal, dataset_id)
        return {"dataset_id": row["dataset_id"]}

    return application


@pytest.fixture
def client(settings: Settings):
    with TestClient(application_with_probe(settings), base_url=ORIGIN, client=("127.0.0.1", 50000)) as client:
        yield client


def create(client: TestClient):
    return client.post("/api/v1/sessions", json={}, headers=BOOTSTRAP)


def credential(client: TestClient) -> str:
    return client.cookies.get(client.app.state.settings.session_cookie_name)


def test_creation_stores_hash_only_and_authenticates(client: TestClient) -> None:
    response = create(client)
    assert response.status_code == 201
    data = response.json()
    assert data["mode"] == "synthetic"
    assert data["private_uploads_enabled"] is False
    assert data["lifetime_seconds"] == 3600
    assert response.headers["Cache-Control"] == "no-store"
    token = credential(client)
    assert len(token) == 43
    assert token not in response.text
    assert client.get("/_test/me").json()["session_id"] == data["session_id"]
    database = client.app.state.database
    with database.connection() as connection:
        row = connection.execute("SELECT * FROM sessions").fetchone()
        assert row["auth_token_hash"] == credential_hash(token)
        assert row["expires_at"] - row["created_at"] == 3600
        dump = "\n".join(connection.iterdump())
        assert token not in dump
        assert data["csrf_token"] not in dump
        event = connection.execute("SELECT * FROM audit_events").fetchone()
        assert event["event_type"] == "SESSION_CREATED"
        assert event["details_json"] == "{}"


def test_credentials_are_fresh_and_expiry_does_not_slide(client: TestClient) -> None:
    first = create(client).json()
    token_a = credential(client)
    assert client.get("/_test/me").json()["expires_at"] == first["expires_at"]
    second = create(client).json()
    assert credential(client) != token_a
    assert second["session_id"] != first["session_id"]
    assert second["csrf_token"] != first["csrf_token"]


@pytest.mark.parametrize("token", [None, "", "tampered", "a" * 43, "a" * 1000, "!" * 43])
def test_missing_or_tampered_credentials_are_rejected(client: TestClient, token: str | None) -> None:
    client.cookies.clear()
    headers = {} if token is None else {"Cookie": f"__Host-sheetsafe_session={token}"}
    response = client.get("/_test/me", headers=headers)
    assert response.status_code == 401
    assert response.json()["code"] == "UNAUTHENTICATED"
    assert set(response.json()) == {"code", "message", "retryable", "request_id"}
    if token:
        assert token not in response.text


def test_duplicate_cookies_and_csrf_token_as_credential_are_rejected(client: TestClient) -> None:
    data = create(client).json()
    token = credential(client)
    name = client.app.state.settings.session_cookie_name
    assert client.get("/_test/me", headers={"Cookie": f"{name}={token}; {name}={token}"}).status_code == 401
    assert client.get("/_test/me", headers={"Cookie": f"{name}={data['csrf_token']}"}).status_code == 401


def test_server_expiry_rejects_cookie_even_before_browser_expiry(client: TestClient) -> None:
    data = create(client).json()
    with client.app.state.database.transaction() as connection:
        now = connection.execute("SELECT unixepoch()").fetchone()[0]
        connection.execute(
            "UPDATE sessions SET created_at=?, expires_at=? WHERE session_id=?",
            (now - 3600, now, data["session_id"]),
        )
    assert client.get("/_test/me").status_code == 401
    assert client.delete(f"/api/v1/sessions/{data['session_id']}",
                         headers={"Origin": ORIGIN, "X-CSRF-Token": data["csrf_token"]}).status_code == 401


def seed_owned_run(database: Database, owner: str) -> None:
    with database.transaction() as connection:
        connection.execute(
            """INSERT INTO datasets(dataset_id, session_id, source_sha256, storage_ref,
                file_type, byte_count, idempotency_key, request_sha256) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            ("dataset_a", owner, "a" * 64, "input_a", "csv", 10, "upload_a", "b" * 64),
        )
        connection.execute(
            "INSERT INTO dataset_versions(dataset_id, version, session_id) VALUES (?, 1, ?)",
            ("dataset_a", owner),
        )
        connection.execute(
            """INSERT INTO runs(run_id, session_id, dataset_id, dataset_version, question,
                idempotency_key, request_sha256) VALUES (?, ?, ?, 1, ?, ?, ?)""",
            ("run_a", owner, "dataset_a", "Count rows", "request_a", "c" * 64),
        )


def test_delete_revokes_immediately_and_records_truthful_pending_work(client: TestClient) -> None:
    data = create(client).json()
    token = credential(client)
    database = client.app.state.database
    principal = client.app.state.sessions.authenticate(token)
    seed_owned_run(database, data["session_id"])
    response = client.delete(f"/api/v1/sessions/{data['session_id']}",
                             headers={"Origin": ORIGIN, "X-CSRF-Token": data["csrf_token"]})
    assert response.status_code == 200
    receipt = response.json()
    assert receipt["access_revoked"] is True
    assert receipt["cancellation_status"] == "requested"
    assert receipt["cleanup_status"] == "not_started"
    assert "Max-Age=0" in response.headers["set-cookie"]
    assert token not in response.text
    with database.connection() as connection:
        session = connection.execute("SELECT * FROM sessions").fetchone()
        assert session["revoked_at"] is not None and session["deletion_requested_at"] is not None
        assert connection.execute("SELECT cancel_requested_at FROM runs").fetchone()[0] is not None
        assert connection.execute("SELECT COUNT(*) FROM datasets").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 1
        assert connection.execute("SELECT event_type FROM audit_events WHERE event_id=?",
                                  (receipt["receipt_id"],)).fetchone()[0] == "DELETION_REQUESTED"
        with pytest.raises(SessionError) as error:
            require_owner(connection, principal, principal.session_id)
        assert error.value.status_code == 401
    headers = {"Cookie": f"__Host-sheetsafe_session={token}"}
    assert client.get("/_test/me", headers=headers).status_code == 401
    assert client.delete(f"/api/v1/sessions/{data['session_id']}", headers={
        **headers, "Origin": ORIGIN, "X-CSRF-Token": data["csrf_token"],
    }).status_code == 401


def test_other_session_and_missing_resource_have_same_denial(client: TestClient) -> None:
    first = create(client).json()
    database = client.app.state.database
    token_a = credential(client)
    principal_a = client.app.state.sessions.authenticate(token_a)
    seed_owned_run(database, first["session_id"])
    second = create(client).json()
    principal_b = client.app.state.sessions.authenticate(credential(client))
    assert client.get("/_test/datasets/dataset_a").status_code == 404
    assert client.get("/_test/datasets/missing").status_code == 404
    assert client.delete(f"/api/v1/sessions/{first['session_id']}", headers={
        "Origin": ORIGIN, "X-CSRF-Token": second["csrf_token"],
    }).status_code == 404
    with database.connection() as connection:
        assert owned_dataset(connection, principal_a, "dataset_a")["session_id"] == first["session_id"]
        assert owned_run(connection, principal_a, "run_a")["session_id"] == first["session_id"]
        event_id = connection.execute("SELECT event_id FROM audit_events WHERE session_pseudonym=?",
                                      (principal_a.audit_pseudonym,)).fetchone()[0]
        assert owned_audit_event(connection, principal_a, event_id)["session_pseudonym"] == principal_a.audit_pseudonym
        for check in (
            lambda: owned_run(connection, principal_b, "run_a"),
            lambda: owned_audit_event(connection, principal_b, event_id),
            lambda: require_owner(connection, principal_b, first["session_id"]),
        ):
            with pytest.raises(SessionError) as error:
                check()
            assert error.value.status_code == 404
        assert connection.execute("SELECT revoked_at FROM sessions WHERE session_id=?",
                                  (first["session_id"],)).fetchone()[0] is None


@pytest.mark.parametrize("origin", [None, "null", "https://evil.example", "https://testserver.evil.example", "http://testserver"])
def test_creation_rejects_missing_or_untrusted_origin(client: TestClient, origin: str | None) -> None:
    headers = {"X-SheetSafe-Request": "1"}
    if origin is not None:
        headers["Origin"] = origin
    assert client.post("/api/v1/sessions", json={}, headers=headers).status_code == 403
    with client.app.state.database.connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0


def test_creation_bootstrap_header_and_private_mode_are_rejected(client: TestClient) -> None:
    assert client.post("/api/v1/sessions", json={}, headers={"Origin": ORIGIN}).status_code == 403
    for payload in ({"mode": "private"}, {"mode": "synthetic", "access_code": "synthetic-value"}):
        response = client.post("/api/v1/sessions", json=payload, headers=BOOTSTRAP)
        assert response.status_code == 400
        assert "synthetic-value" not in response.text


@pytest.mark.parametrize("body,media_type,status", [
    (b"x" * 1025, "application/json", 413), (b"not-json", "application/json", 400),
    (b"mode=synthetic", "application/x-www-form-urlencoded", 415),
])
def test_creation_body_limits(client: TestClient, body: bytes, media_type: str, status: int) -> None:
    response = client.post("/api/v1/sessions", content=body,
                           headers={**BOOTSTRAP, "Content-Type": media_type})
    assert response.status_code == status


@pytest.mark.parametrize("origin,csrf", [
    (ORIGIN, None), (ORIGIN, "bad"), (None, "valid"),
    ("https://evil.example", "valid"), ("null", "valid"),
])
def test_delete_csrf_and_origin_checks(client: TestClient, origin, csrf) -> None:
    data = create(client).json()
    headers = {}
    if origin is not None:
        headers["Origin"] = origin
    if csrf is not None:
        headers["X-CSRF-Token"] = data["csrf_token"] if csrf == "valid" else csrf
    response = client.delete(f"/api/v1/sessions/{data['session_id']}", headers=headers)
    assert response.status_code == 403
    assert client.get("/_test/me").status_code == 200


def test_csrf_is_bound_to_session_and_duplicate_headers_fail(client: TestClient) -> None:
    first = create(client).json()
    second = create(client).json()
    url = f"/api/v1/sessions/{second['session_id']}"
    assert client.delete(url, headers={"Origin": ORIGIN, "X-CSRF-Token": first["csrf_token"]}).status_code == 403
    assert client.delete(url, headers=[("Origin", ORIGIN), ("X-CSRF-Token", second["csrf_token"]),
                                       ("X-CSRF-Token", second["csrf_token"])]).status_code == 403
    assert client.delete(url, headers=[("Origin", ORIGIN), ("Origin", ORIGIN),
                                       ("X-CSRF-Token", second["csrf_token"])]).status_code == 403


def test_production_cookie_attributes_and_http_rejection(settings: Settings) -> None:
    production = Settings(_env_file=None, environment="production", database_path=settings.database_path,
                          allowed_origins=(ORIGIN,))
    with TestClient(application_with_probe(production), base_url=ORIGIN, client=("127.0.0.1", 50000)) as client:
        response = create(client)
        assert response.status_code == 201
        cookie = SimpleCookie(response.headers["set-cookie"])["__Host-sheetsafe_session"]
        assert cookie["secure"] and cookie["httponly"]
        assert cookie["samesite"] == "strict" and cookie["path"] == "/"
        assert cookie["domain"] == "" and cookie["max-age"] == "3600"
        assert cookie["expires"]
        assert client.get("http://testserver/_test/me", headers={"X-Forwarded-Proto": "https"}).status_code == 403


def test_explicit_local_http_mode_is_distinct_and_loopback_only(settings: Settings) -> None:
    local = Settings(_env_file=None, environment="development", database_path=settings.database_path,
                     allowed_origins=("http://localhost:8000",), allow_insecure_local_cookies=True)
    application = application_with_probe(local)
    with TestClient(application, base_url="http://localhost:8000", client=("127.0.0.1", 50000)) as client:
        response = client.post("/api/v1/sessions", json={}, headers={
            "Origin": "http://localhost:8000", "X-SheetSafe-Request": "1",
        })
        assert response.status_code == 201
        cookie = SimpleCookie(response.headers["set-cookie"])["sheetsafe_dev_session"]
        assert not cookie["secure"] and cookie["httponly"] and cookie["samesite"] == "strict"
        assert client.get("/_test/me").status_code == 200
    with TestClient(application, base_url="http://localhost:8000", client=("203.0.113.1", 50000)) as remote:
        assert remote.post("/api/v1/sessions", json={}, headers={
            "Origin": "http://localhost:8000", "X-SheetSafe-Request": "1",
        }).status_code == 403


def test_cors_allows_only_configured_origins(client: TestClient) -> None:
    allowed = client.options("/api/v1/sessions", headers={
        "Origin": ORIGIN, "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type,x-sheetsafe-request",
    })
    assert allowed.status_code == 200
    assert allowed.headers["Access-Control-Allow-Origin"] == ORIGIN
    assert allowed.headers["Access-Control-Allow-Credentials"] == "true"
    denied = client.options("/api/v1/sessions", headers={
        "Origin": "https://evil.example", "Access-Control-Request-Method": "POST",
    })
    assert denied.status_code == 400
    assert "Access-Control-Allow-Origin" not in denied.headers
    assert denied.json()["code"] == "INVALID_REQUEST"
    assert denied.json()["request_id"] == denied.headers["X-Request-ID"]
    assert denied.headers["Cache-Control"] == "no-store"


def test_per_ip_limit_persists_after_restart_and_ignores_forwarded_headers(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = int(time())
    monkeypatch.setattr("backend.security.sessions.utc_now", lambda: now)
    limited = Settings(_env_file=None, environment="test", database_path=settings.database_path,
                       allowed_origins=(ORIGIN,), session_creations_per_ip_per_minute=1)
    application = application_with_probe(limited)
    with TestClient(application, base_url=ORIGIN, client=("127.0.0.1", 1)) as client:
        assert create(client).status_code == 201
    with TestClient(application, base_url=ORIGIN, client=("127.0.0.1", 2)) as client:
        response = client.post("/api/v1/sessions", json={}, headers={**BOOTSTRAP, "X-Forwarded-For": "203.0.113.2"})
        assert response.status_code == 429
        assert response.json()["retryable"] is True
        assert 1 <= int(response.headers["Retry-After"]) <= 60


def test_rate_window_resets_and_prunes_old_ip_buckets(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    database = Database(settings)
    database.initialize()
    limited = settings.model_copy(update={"session_creations_per_ip_per_minute": 1})
    service = SessionService(database, limited)
    monkeypatch.setattr("backend.security.sessions.utc_now", lambda: 1800000001)
    service.create("192.0.2.1")
    with pytest.raises(SessionError) as error:
        service.create("192.0.2.1")
    assert error.value.status_code == 429
    monkeypatch.setattr("backend.security.sessions.utc_now", lambda: 1800000061)
    service.create("192.0.2.2")
    with database.connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM session_creation_limits").fetchone()[0] == 2


def test_concurrent_global_admission_is_bounded(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    database = Database(settings)
    database.initialize()
    service = SessionService(database, settings.model_copy(update={"session_creations_global_per_minute": 3}))
    monkeypatch.setattr("backend.security.sessions.utc_now", lambda: 1800000001)

    def attempt(index: int) -> int:
        try:
            service.create(f"192.0.2.{index + 1}")
            return 201
        except SessionError as error:
            return error.status_code

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(attempt, range(8)))
    assert outcomes.count(201) == 3 and outcomes.count(429) == 5
    with database.connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 3
        assert connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 3
        assert connection.execute("SELECT COUNT(*) FROM session_creation_limits").fetchone()[0] == 4


def test_total_record_limit_fails_closed_without_deleting_data(settings: Settings) -> None:
    database = Database(settings)
    database.initialize()
    service = SessionService(database, settings.model_copy(update={"max_session_records": 1}))
    first = service.create("192.0.2.1")
    service.revoke(first.credential, first.principal.session_id)
    with pytest.raises(SessionError) as error:
        service.create("192.0.2.2")
    assert error.value.status_code == 429
    with database.connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1


def test_audit_failure_rolls_back_session_and_admission(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    database = Database(settings)
    database.initialize()

    def fail(*args, **kwargs):
        raise sqlite3.OperationalError("synthetic private detail")

    monkeypatch.setattr(database, "append_audit_event", fail)
    with pytest.raises(SessionError) as error:
        SessionService(database, settings).create("192.0.2.1")
    assert error.value.status_code == 503
    with database.connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM session_creation_limits").fetchone()[0] == 0


def test_cookie_and_csrf_do_not_leak_on_errors(client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    data = create(client).json()
    token = credential(client)
    response = client.delete("/api/v1/sessions/another_session", headers={
        "Origin": ORIGIN, "X-CSRF-Token": data["csrf_token"],
    })
    assert response.status_code == 404
    assert token not in response.text and data["csrf_token"] not in response.text
    assert token not in caplog.text and data["csrf_token"] not in caplog.text


@pytest.mark.parametrize("change", ["deletion", "private"])
def test_pending_deletion_and_private_rows_do_not_authenticate(client: TestClient, change: str) -> None:
    data = create(client).json()
    with client.app.state.database.transaction() as connection:
        if change == "deletion":
            connection.execute("UPDATE sessions SET deletion_requested_at=created_at WHERE session_id=?",
                               (data["session_id"],))
        else:
            connection.execute("UPDATE sessions SET mode='private', consent_at=created_at WHERE session_id=?",
                               (data["session_id"],))
    assert client.get("/_test/me").status_code == 401


def test_revocation_and_cancellation_signal_rollback_if_audit_fails(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = create(client).json()
    token = credential(client)
    database = client.app.state.database
    seed_owned_run(database, data["session_id"])
    original = database.append_audit_event

    def fail_after_first_audit(*args, **kwargs):
        if kwargs["event_type"] == "DELETION_REQUESTED":
            raise sqlite3.OperationalError("synthetic audit failure")
        return original(*args, **kwargs)

    monkeypatch.setattr(database, "append_audit_event", fail_after_first_audit)
    response = client.delete(f"/api/v1/sessions/{data['session_id']}", headers={
        "Origin": ORIGIN, "X-CSRF-Token": data["csrf_token"],
    })
    assert response.status_code == 503
    assert client.app.state.sessions.authenticate(token).session_id == data["session_id"]
    with database.connection() as connection:
        assert connection.execute("SELECT revoked_at FROM sessions").fetchone()[0] is None
        assert connection.execute("SELECT cancel_requested_at FROM runs").fetchone()[0] is None
        assert connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 1


@pytest.mark.parametrize("fail_first", [False, True])
def test_migration_from_v1_preserves_existing_sessions(
    settings: Settings, monkeypatch: pytest.MonkeyPatch, fail_first: bool
) -> None:
    with sqlite3.connect(settings.database_path) as connection:
        for statement in MIGRATIONS[1]:
            connection.execute(statement)
        connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
        connection.execute("PRAGMA user_version=1")
        connection.execute(
            "INSERT INTO sessions(session_id, auth_token_hash, audit_pseudonym) VALUES (?, ?, ?)",
            ("existing_session", credential_hash(secrets.token_urlsafe(32)), "existing_pseudonym"),
        )
    database = Database(settings)
    if fail_first:
        with monkeypatch.context() as patch:
            patch.setitem(MIGRATIONS, 2, (*MIGRATIONS[2], "INVALID MIGRATION SQL"))
            with pytest.raises(sqlite3.OperationalError):
                database.initialize()
        with sqlite3.connect(settings.database_path) as connection:
            assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
            assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1
    database.initialize()
    with database.connection() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        assert connection.execute("SELECT session_id FROM sessions").fetchone()[0] == "existing_session"
        assert connection.execute("SELECT COUNT(*) FROM session_creation_limits").fetchone()[0] == 0
