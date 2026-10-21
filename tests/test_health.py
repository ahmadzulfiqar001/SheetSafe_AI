"""Verify public liveness and the intentionally small HTTP surface."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.config import Settings
from backend.main import create_app


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(_env_file=None, environment="test", docs_enabled=False,
                    database_path=tmp_path / "health.sqlite3")


def test_health_returns_only_liveness(settings: Settings) -> None:
    with TestClient(create_app(settings)) as client:
        response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert response.json() == {"status": "ok"}


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_docs_are_unavailable_when_disabled(path: str, settings: Settings) -> None:
    with TestClient(create_app(settings)) as client:
        assert client.get(path).status_code == 404


def test_docs_can_be_enabled_explicitly(settings: Settings) -> None:
    settings = settings.model_copy(update={"docs_enabled": True})
    application = create_app(settings)
    with TestClient(application) as client:
        assert client.get("/docs").status_code == 200
        assert "/api/v1/health" in client.get("/openapi.json").json()["paths"]
    assert application.debug is False
