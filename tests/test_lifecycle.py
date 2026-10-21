"""Exercise real FastAPI lifespans and on-disk database readiness failures."""

from pathlib import Path
import sqlite3

from fastapi.testclient import TestClient
import pytest

from backend.config import Settings
from backend.main import create_app
from backend.storage.database import Database, DatabaseReadinessError
from backend.storage.schema import SCHEMA_VERSION


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None, database_path=tmp_path / "private" / "application.sqlite3",
        database_busy_timeout_ms=100, docs_enabled=False,
    )


def assert_not_ready(response) -> None:
    assert response.status_code == 503
    body = response.json()
    assert set(body) == {"code", "message", "retryable", "request_id"}
    assert body["code"] == "NOT_READY"
    assert body["message"] == "Service is not ready."
    assert body["retryable"] is True
    assert body["request_id"] == response.headers["X-Request-ID"]
    assert response.headers["Cache-Control"] == "no-store"


def test_factory_has_no_file_side_effect_and_startup_initializes_database(settings: Settings) -> None:
    application = create_app(settings)
    assert not settings.database_path.exists()
    assert application.state.database is None
    with TestClient(application) as client:
        assert settings.database_path.is_file()
        database = application.state.database
        assert isinstance(database, Database)
        with database.connection() as connection:
            assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
            assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
            assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        ready = client.get("/api/v1/ready")
        assert ready.status_code == 200
        assert ready.json() == {"status": "ready"}
        assert ready.headers["Cache-Control"] == "no-store"
        assert client.get("/api/v1/health").json() == {"status": "ok"}
    assert application.state.database is None


def test_lifespan_runs_full_integrity_check_before_ready(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = []
    original = Database.check_ready

    def checked(self: Database, *, full_integrity: bool = False) -> None:
        calls.append(full_integrity)
        original(self, full_integrity=full_integrity)

    monkeypatch.setattr(Database, "check_ready", checked)
    with TestClient(create_app(settings)) as client:
        assert calls == [True]
        assert client.get("/api/v1/ready").status_code == 200
        assert calls == [True, False]


def test_readiness_is_unavailable_without_startup(settings: Settings) -> None:
    application = create_app(settings)
    # TestClient without its context deliberately does not run the lifespan.
    client = TestClient(application)
    try:
        assert_not_ready(client.get("/api/v1/ready"))
        assert client.get("/api/v1/health").status_code == 200
        assert not settings.database_path.exists()
    finally:
        client.close()


def test_repeated_lifespans_and_app_recreation_preserve_data(settings: Settings) -> None:
    application = create_app(settings)
    with TestClient(application) as client:
        with application.state.database.transaction() as connection:
            connection.execute(
                "INSERT INTO sessions(session_id, auth_token_hash, audit_pseudonym) VALUES (?, ?, ?)",
                ("session_a", "a" * 64, "pseudonym_a"),
            )
        assert client.get("/api/v1/ready").status_code == 200
    for app in (application, create_app(settings)):
        with TestClient(app) as client:
            assert client.get("/api/v1/ready").status_code == 200
            with app.state.database.connection() as connection:
                assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1
        assert app.state.database is None


@pytest.mark.parametrize("failure", ["corrupt", "directory", "newer"])
def test_real_database_startup_failures_abort_lifespan(settings: Settings, failure: str) -> None:
    path = settings.database_path
    path.parent.mkdir(parents=True)
    if failure == "corrupt":
        path.write_bytes(b"synthetic invalid database")
    elif failure == "directory":
        path.mkdir()
    else:
        Database(settings).initialize()
        with sqlite3.connect(path) as connection:
            connection.execute(f"PRAGMA user_version={SCHEMA_VERSION + 1}")
    application = create_app(settings)
    with pytest.raises(RuntimeError, match="^Database startup checks failed$") as error:
        with TestClient(application):
            pytest.fail("An invalid database must prevent startup")
    assert str(path) not in str(error.value)
    assert application.state.database is None


def test_failed_startup_integrity_check_never_sets_ready(
    settings: Settings, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    private = "synthetic-secret SELECT password FROM credentials C:/private/example.sqlite3"

    def fail_check(self: Database, *, full_integrity: bool = False) -> None:
        assert full_integrity is True
        raise DatabaseReadinessError(private)

    monkeypatch.setattr(Database, "check_ready", fail_check)
    application = create_app(settings)
    with pytest.raises(RuntimeError, match="^Database startup checks failed$"):
        with TestClient(application):
            pytest.fail("Failed startup integrity check must not serve requests")
    assert application.state.database is None
    assert private not in caplog.text


def test_live_database_loss_returns_503_and_recovers(settings: Settings) -> None:
    application = create_app(settings)
    with TestClient(application) as client:
        assert client.get("/api/v1/ready").status_code == 200
        unavailable = settings.database_path.with_suffix(".unavailable")
        settings.database_path.rename(unavailable)
        try:
            assert_not_ready(client.get("/api/v1/ready"))
            assert not settings.database_path.exists()  # A probe never recreates it.
            assert client.get("/api/v1/health").status_code == 200
        finally:
            unavailable.rename(settings.database_path)
        assert client.get("/api/v1/ready").status_code == 200


@pytest.mark.parametrize("failure", ["missing_table", "journal_mode", "schema_version", "foreign_key"])
def test_readiness_rejects_changed_controls_or_schema(settings: Settings, failure: str) -> None:
    application = create_app(settings)
    with TestClient(application) as client:
        with sqlite3.connect(settings.database_path) as connection:
            if failure == "missing_table":
                connection.execute("DROP TABLE attempts")
            elif failure == "journal_mode":
                connection.execute("PRAGMA journal_mode=DELETE")
            elif failure == "schema_version":
                connection.execute(f"PRAGMA user_version={SCHEMA_VERSION + 1}")
            else:
                # This external test connection deliberately bypasses FK enforcement.
                connection.execute(
                    """INSERT INTO datasets(dataset_id, session_id, source_sha256, storage_ref,
                        file_type, byte_count, idempotency_key, request_sha256)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    ("orphan", "missing", "a" * 64, "synthetic_ref", "csv", 1, "key", "b" * 64),
                )
        assert_not_ready(client.get("/api/v1/ready"))
        assert client.get("/api/v1/health").status_code == 200


def test_readiness_exception_details_are_not_exposed(
    settings: Settings, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    private = "synthetic-secret SELECT password FROM credentials C:/private/example.sqlite3"
    application = create_app(settings)
    with TestClient(application) as client:
        def fail() -> None:
            raise sqlite3.OperationalError(private)

        monkeypatch.setattr(application.state.database, "check_ready", fail)
        response = client.get("/api/v1/ready")
        assert_not_ready(response)
        assert private not in response.text
        assert private not in caplog.text
