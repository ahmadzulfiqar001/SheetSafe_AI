"""Test-only routes exercise safe handlers without adding public functionality."""

from pathlib import Path
import re
import sqlite3

from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import BaseModel
import pytest

from backend.config import Settings
from backend.main import create_app


PRIVATE_DETAIL = "synthetic-secret SELECT password FROM credentials C:/private/example.sqlite3"


class ValidationPayload(BaseModel):
    count: int


@pytest.fixture
def client(tmp_path: Path):
    application = create_app(Settings(
        _env_file=None, database_path=tmp_path / "errors.sqlite3", docs_enabled=False,
    ))

    @application.get("/_test/http/{status_code}")
    def http_error(status_code: int):
        raise HTTPException(status_code, detail=PRIVATE_DETAIL, headers={"X-Internal": PRIVATE_DETAIL})

    @application.post("/_test/validate")
    def validate(payload: ValidationPayload):
        return {"count": payload.count}

    @application.get("/_test/failure/{kind}")
    def unexpected_error(kind: str):
        if kind == "sqlite":
            raise sqlite3.OperationalError(PRIVATE_DETAIL)
        raise RuntimeError(PRIVATE_DETAIL)

    with TestClient(application, raise_server_exceptions=False) as test_client:
        yield test_client


def assert_safe_error(response, status: int, code: str, retryable: bool) -> None:
    assert response.status_code == status
    assert response.headers["content-type"] == "application/json"
    assert response.headers["Cache-Control"] == "no-store"
    body = response.json()
    assert set(body) == {"code", "message", "retryable", "request_id"}
    assert body["code"] == code
    assert body["retryable"] is retryable
    assert re.fullmatch("[0-9a-f]{32}", body["request_id"])
    assert body["request_id"] == response.headers["X-Request-ID"]
    assert PRIVATE_DETAIL not in response.text
    assert "X-Internal" not in response.headers


@pytest.mark.parametrize("status,code,retryable", [
    (400, "INVALID_REQUEST", False), (401, "UNAUTHENTICATED", False),
    (403, "FORBIDDEN", False), (404, "NOT_FOUND", False),
    (405, "METHOD_NOT_ALLOWED", False), (409, "CONFLICT", False),
    (413, "PAYLOAD_TOO_LARGE", False), (415, "UNSUPPORTED_MEDIA_TYPE", False),
    (422, "INVALID_DATA", False), (429, "RATE_LIMITED", True),
    (500, "INTERNAL_ERROR", False), (503, "SERVICE_UNAVAILABLE", True),
    (418, "HTTP_ERROR", False),
])
def test_http_errors_do_not_echo_exception_details(client, status, code, retryable) -> None:
    assert_safe_error(client.get(f"/_test/http/{status}"), status, code, retryable)


def test_routing_errors_and_method_header(client) -> None:
    assert_safe_error(client.get("/missing"), 404, "NOT_FOUND", False)
    response = client.post("/api/v1/health", json={"secret": PRIVATE_DETAIL})
    assert_safe_error(response, 405, "METHOD_NOT_ALLOWED", False)
    assert "GET" in response.headers["Allow"]


@pytest.mark.parametrize("payload", [
    {"count": PRIVATE_DETAIL, "password": PRIVATE_DETAIL}, {}, [],
])
def test_validation_errors_do_not_echo_input(client, payload) -> None:
    assert_safe_error(client.post("/_test/validate", json=payload), 400, "INVALID_REQUEST", False)


def test_malformed_json_is_safe(client) -> None:
    response = client.post("/_test/validate", content=PRIVATE_DETAIL, headers={"Content-Type": "application/json"})
    assert_safe_error(response, 400, "INVALID_REQUEST", False)


@pytest.mark.parametrize("kind", ["runtime", "sqlite"])
def test_unexpected_errors_are_safe(client, kind, caplog: pytest.LogCaptureFixture) -> None:
    response = client.get(f"/_test/failure/{kind}")
    assert_safe_error(response, 500, "INTERNAL_ERROR", False)
    assert PRIVATE_DETAIL not in caplog.text
    assert "Request failed" in caplog.text


def test_request_ids_are_server_generated_and_unique(client) -> None:
    first = client.get("/missing", headers={"X-Request-ID": PRIVATE_DETAIL})
    second = client.get("/missing")
    assert_safe_error(first, 404, "NOT_FOUND", False)
    assert first.json()["request_id"] != second.json()["request_id"]
    health = client.get("/api/v1/health")
    assert re.fullmatch("[0-9a-f]{32}", health.headers["X-Request-ID"])
