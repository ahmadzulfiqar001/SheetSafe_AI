"""Focused tests for Step 11A Streamlit dashboard and typed FastAPI client."""

import ast
from pathlib import Path
from typing import Callable

from fastapi.testclient import TestClient
import httpx
import pytest
from streamlit.testing.v1 import AppTest

from backend.config import Settings
from backend.main import create_app
from frontend.api_client import (
    ActiveSessionView,
    DEFAULT_API_BASE_URL,
    DEFAULT_CLIENT_ORIGIN,
    FrontendClientCode,
    FrontendClientError,
    MAX_API_RESPONSE_BYTES,
    SheetSafeApiClient,
    validate_canonical_origin,
)
from frontend.app import PAGES, SUPPORTED_OPERATIONS


FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"
APP_PATH = FRONTEND_DIR / "app.py"
TEST_ORIGIN = "http://localhost:8501"
HTTPS_API_ORIGIN = "https://testserver"
DEV_API_ORIGIN = "http://127.0.0.1:8000"


@pytest.fixture
def https_backend_client(tmp_path: Path):
    settings = Settings(
        _env_file=None,
        environment="test",
        database_path=tmp_path / "frontend_https.sqlite3",
        storage_root=tmp_path / "storage_https",
        allowed_origins=(TEST_ORIGIN,),
        database_busy_timeout_ms=2000,
    )
    with TestClient(
        create_app(settings),
        base_url=HTTPS_API_ORIGIN,
        client=("127.0.0.1", 50000),
    ) as client:
        yield client


@pytest.fixture
def dev_loopback_backend_client(tmp_path: Path):
    settings = Settings(
        _env_file=None,
        environment="development",
        allow_insecure_local_cookies=True,
        database_path=tmp_path / "frontend_dev.sqlite3",
        storage_root=tmp_path / "storage_dev",
        allowed_origins=(TEST_ORIGIN, "http://127.0.0.1:8501"),
        database_busy_timeout_ms=2000,
    )
    with TestClient(
        create_app(settings),
        base_url=DEV_API_ORIGIN,
        client=("127.0.0.1", 50000),
    ) as client:
        yield client


def _mock_client(handler: Callable[[httpx.Request], httpx.Response]) -> SheetSafeApiClient:
    return SheetSafeApiClient(
        api_base_url=DEV_API_ORIGIN,
        client_origin=TEST_ORIGIN,
        transport=httpx.MockTransport(handler),
    )


def test_frontend_module_boundaries_forbid_backend_internals() -> None:
    forbidden_prefixes = (
        "sqlite3",
        "backend.storage",
        "backend.security",
        "parser_worker",
        "runner",
        "ingestion",
        "docker",
        "openpyxl",
        "pandas",
        "subprocess",
    )
    py_files = sorted(FRONTEND_DIR.glob("*.py"))
    assert len(py_files) >= 3
    for file_path in py_files:
        tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert not alias.name.startswith(forbidden_prefixes), (
                        f"{file_path.name} imported forbidden module {alias.name}"
                    )
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert not node.module.startswith(forbidden_prefixes), (
                    f"{file_path.name} imported from forbidden module {node.module}"
                )


@pytest.mark.parametrize(
    "bad_url",
    [
        "",
        "   ",
        "ftp://127.0.0.1:8000",
        "http://example.com:8000",
        "http://192.168.1.10:8000",
        "https://user:pass@api.example.com",
        "http://127.0.0.1:8000/api/v1",
        "http://127.0.0.1:8000?foo=bar",
        "http://127.0.0.1:8000#frag",
        "http://127.0.0.1:99999",
    ],
)
def test_validate_canonical_origin_rejects_unsafe_urls(bad_url: str) -> None:
    with pytest.raises(FrontendClientError) as exc_info:
        validate_canonical_origin(bad_url)
    assert exc_info.value.code is FrontendClientCode.INVALID_CONFIGURATION


def test_client_rejects_out_of_bounds_timeouts_and_non_v1_paths() -> None:
    with pytest.raises(FrontendClientError) as exc_info:
        SheetSafeApiClient(connect_timeout_seconds=0.01)
    assert exc_info.value.code is FrontendClientCode.INVALID_CONFIGURATION

    with pytest.raises(FrontendClientError) as exc_info_read:
        SheetSafeApiClient(read_timeout_seconds=60.0)
    assert exc_info_read.value.code is FrontendClientCode.INVALID_CONFIGURATION

    client = _mock_client(lambda _req: httpx.Response(200, json={"status": "ok"}))
    with pytest.raises(FrontendClientError) as exc_path:
        client._request_raw("GET", "/internal/admin")
    assert exc_path.value.code is FrontendClientCode.INVALID_CONFIGURATION


def test_live_fastapi_health_and_readiness_integration(
    https_backend_client: TestClient,
) -> None:
    api_client = SheetSafeApiClient(
        api_base_url=HTTPS_API_ORIGIN,
        client_origin=TEST_ORIGIN,
        transport=https_backend_client._transport,
    )
    assert api_client.check_health().status == "ok"
    assert api_client.check_ready().status == "ready"

    snapshot = api_client.probe_backend_status()
    assert snapshot.reachable is True
    assert snapshot.liveness_ok is True
    assert snapshot.readiness_ok is True
    assert snapshot.status_label == "ONLINE & READY"


def test_probe_backend_status_reports_degraded_when_not_ready(tmp_path: Path) -> None:
    settings = Settings(
        _env_file=None,
        environment="test",
        database_path=tmp_path / "degraded.sqlite3",
        storage_root=tmp_path / "storage_degraded",
        allowed_origins=(TEST_ORIGIN,),
    )
    # Create app without running lifespan startup so database/storage are not initialized
    uninitialized_app = create_app(settings)
    raw_test_client = TestClient(uninitialized_app, base_url=HTTPS_API_ORIGIN)
    api_client = SheetSafeApiClient(
        api_base_url=HTTPS_API_ORIGIN,
        client_origin=TEST_ORIGIN,
        transport=raw_test_client._transport,
    )
    snapshot = api_client.probe_backend_status()
    assert snapshot.reachable is True
    assert snapshot.liveness_ok is True
    assert snapshot.readiness_ok is False
    assert snapshot.status_label == "DEGRADED (NOT READY)"


def test_probe_backend_status_reports_offline_when_unreachable() -> None:
    def raise_connect_error(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection refused", request=request)

    api_client = _mock_client(raise_connect_error)
    snapshot = api_client.probe_backend_status()
    assert snapshot.reachable is False
    assert snapshot.liveness_ok is False
    assert snapshot.readiness_ok is False
    assert snapshot.status_label == "OFFLINE"


def test_live_https_session_create_and_revoke_preserves_secret_boundaries(
    https_backend_client: TestClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    api_client = SheetSafeApiClient(
        api_base_url=HTTPS_API_ORIGIN,
        client_origin=TEST_ORIGIN,
        transport=https_backend_client._transport,
    )
    view = api_client.create_synthetic_session()
    assert isinstance(view, ActiveSessionView)
    assert view.mode == "synthetic"
    assert view.private_uploads_enabled is False
    assert view.cookie_name == "__Host-sheetsafe_session"
    assert view.cookie_httponly is True
    assert view.cookie_samesite == "strict"
    assert api_client.active_session == view

    # Verify secrets are sealed and never exposed in repr, view dump, or logs
    sealed = api_client._sealed_session
    assert sealed is not None
    raw_cookie_secret = sealed._cookie_value.get_secret_value()
    raw_csrf_secret = sealed._csrf_token.get_secret_value()
    assert len(raw_cookie_secret) == 43
    assert len(raw_csrf_secret) == 64

    view_json = view.model_dump_json()
    assert raw_cookie_secret not in view_json
    assert raw_csrf_secret not in view_json
    assert raw_cookie_secret not in repr(api_client)
    assert raw_csrf_secret not in repr(api_client)
    assert raw_cookie_secret not in repr(sealed)
    assert raw_csrf_secret not in repr(sealed)
    assert raw_cookie_secret not in caplog.text
    assert raw_csrf_secret not in caplog.text

    # Revoke active session against live FastAPI backend
    receipt = api_client.revoke_active_session()
    assert receipt.session_id == view.session_id
    assert receipt.access_revoked is True
    assert receipt.cancellation_status == "requested"
    assert receipt.cleanup_status == "not_started"
    assert api_client.active_session is None

    # Second revoke fails closed with UNAUTHENTICATED
    with pytest.raises(FrontendClientError) as exc_info:
        api_client.revoke_active_session()
    assert exc_info.value.code is FrontendClientCode.UNAUTHENTICATED


def test_live_dev_loopback_session_lifecycle(
    dev_loopback_backend_client: TestClient,
) -> None:
    api_client = SheetSafeApiClient(
        api_base_url=DEV_API_ORIGIN,
        client_origin=TEST_ORIGIN,
        transport=dev_loopback_backend_client._transport,
    )
    view = api_client.create_synthetic_session()
    assert view.cookie_name == "sheetsafe_dev_session"
    receipt = api_client.revoke_active_session()
    assert receipt.session_id == view.session_id
    assert receipt.access_revoked is True


def test_untrusted_origin_rejected_by_backend_surfaces_forbidden(
    dev_loopback_backend_client: TestClient,
) -> None:
    api_client = SheetSafeApiClient(
        api_base_url=DEV_API_ORIGIN,
        client_origin="https://untrusted.example.com",
        transport=dev_loopback_backend_client._transport,
    )
    with pytest.raises(FrontendClientError) as exc_info:
        api_client.create_synthetic_session()
    assert exc_info.value.code is FrontendClientCode.FORBIDDEN
    assert exc_info.value.status_code == 403


@pytest.mark.parametrize(
    ("status_code", "error_code", "expected_client_code", "retry_after_hdr"),
    [
        (401, "UNAUTHENTICATED", FrontendClientCode.UNAUTHENTICATED, None),
        (403, "FORBIDDEN", FrontendClientCode.FORBIDDEN, None),
        (404, "NOT_FOUND", FrontendClientCode.NOT_FOUND, None),
        (409, "CONFLICT", FrontendClientCode.CONFLICT, None),
        (429, "RATE_LIMITED", FrontendClientCode.RATE_LIMITED, "15"),
        (503, "NOT_READY", FrontendClientCode.NOT_READY, None),
        (500, "INTERNAL_ERROR", FrontendClientCode.SERVICE_UNAVAILABLE, None),
    ],
)
def test_http_error_mapping_and_retry_after_parsing(
    status_code: int,
    error_code: str,
    expected_client_code: FrontendClientCode,
    retry_after_hdr: str | None,
) -> None:
    headers = {"X-Request-ID": "req_test_123"}
    if retry_after_hdr is not None:
        headers["Retry-After"] = retry_after_hdr

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code,
            headers=headers,
            json={
                "code": error_code,
                "message": "Service not ready." if status_code == 503 else "Controlled error.",
                "retryable": status_code in {429, 503},
                "request_id": "req_test_123",
            },
        )

    client = _mock_client(handler)
    with pytest.raises(FrontendClientError) as exc_info:
        client.check_ready()
    err = exc_info.value
    assert err.code is expected_client_code
    assert err.status_code == status_code
    assert err.request_id == "req_test_123"
    assert err.retry_after == (15 if retry_after_hdr else None)


def test_timeout_and_oversized_or_malformed_responses_fail_closed() -> None:
    def timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("Timed out", request=request)

    timeout_client = _mock_client(timeout_handler)
    with pytest.raises(FrontendClientError) as exc_timeout:
        timeout_client.check_health()
    assert exc_timeout.value.code is FrontendClientCode.BACKEND_TIMEOUT
    assert exc_timeout.value.retryable is True

    oversized_client = _mock_client(
        lambda _req: httpx.Response(200, content=b"{" + b"a" * (MAX_API_RESPONSE_BYTES + 10))
    )
    with pytest.raises(FrontendClientError) as exc_size:
        oversized_client.check_health()
    assert exc_size.value.code is FrontendClientCode.MALFORMED_RESPONSE

    dup_key_client = _mock_client(
        lambda _req: httpx.Response(200, content=b'{"status":"ok","status":"ok"}')
    )
    with pytest.raises(FrontendClientError) as exc_dup:
        dup_key_client.check_health()
    assert exc_dup.value.code is FrontendClientCode.MALFORMED_RESPONSE

    nan_client = _mock_client(
        lambda _req: httpx.Response(200, content=b'{"status":NaN}')
    )
    with pytest.raises(FrontendClientError) as exc_nan:
        nan_client.check_health()
    assert exc_nan.value.code is FrontendClientCode.MALFORMED_RESPONSE


def test_session_creation_rejects_missing_or_insecure_cookie() -> None:
    valid_body = {
        "session_id": "a" * 32,
        "expires_at": 1800000000,
        "lifetime_seconds": 3600,
        "mode": "synthetic",
        "private_uploads_enabled": False,
        "csrf_token": "b" * 64,
    }
    # Missing Set-Cookie header
    no_cookie_client = _mock_client(lambda _req: httpx.Response(201, json=valid_body))
    with pytest.raises(FrontendClientError) as exc_missing:
        no_cookie_client.create_synthetic_session()
    assert exc_missing.value.code is FrontendClientCode.MALFORMED_RESPONSE

    # Cookie missing HttpOnly attribute
    insecure_cookie = f"sheetsafe_dev_session={'A' * 43}; Path=/; SameSite=Strict"
    bad_cookie_client = _mock_client(
        lambda _req: httpx.Response(
            201,
            headers={"Set-Cookie": insecure_cookie},
            json=valid_body,
        )
    )
    with pytest.raises(FrontendClientError) as exc_bad_cookie:
        bad_cookie_client.create_synthetic_session()
    assert exc_bad_cookie.value.code is FrontendClientCode.MALFORMED_RESPONSE


def test_gated_actions_fail_closed_without_network_calls() -> None:
    called = False

    def fail_if_called(_request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={"status": "ok"})

    client = _mock_client(fail_if_called)
    with pytest.raises(FrontendClientError) as exc_upload:
        client.submit_dataset_upload(b"col1,col2\n1,2\n")
    assert exc_upload.value.code is FrontendClientCode.FEATURE_DISABLED_BY_GATE

    with pytest.raises(FrontendClientError) as exc_run:
        client.submit_analysis_run(question="What is total revenue?")
    assert exc_run.value.code is FrontendClientCode.FEATURE_DISABLED_BY_GATE
    assert called is False


def test_streamlit_dashboard_renders_all_pages_and_respects_gates(
    dev_loopback_backend_client: TestClient,
) -> None:
    assert PAGES == (
        "Dashboard",
        "My Datasets",
        "AI Analysis",
        "Analysis History",
        "Settings / Privacy",
    )
    assert len(SUPPORTED_OPERATIONS) == 10

    at = AppTest.from_file(str(APP_PATH), default_timeout=15)
    live_client = SheetSafeApiClient(
        api_base_url=DEV_API_ORIGIN,
        client_origin=TEST_ORIGIN,
        transport=dev_loopback_backend_client._transport,
    )
    at.session_state["api_client"] = live_client
    at.session_state["backend_status"] = live_client.probe_backend_status()
    at.run()
    assert not at.exception

    # Verify top metrics reflect live ONLINE & READY FastAPI backend
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["FastAPI Control Plane"] == "Online"
    assert metrics["Active Session"] == "None"
    assert metrics["Dataset Upload Gate"] == "Disabled"
    assert metrics["Vultr AI Execution"] == "Disabled"

    # Click "Start Synthetic Session" on Dashboard
    start_buttons = [b for b in at.button if b.label == "Start Synthetic Session"]
    assert len(start_buttons) == 1
    assert start_buttons[0].disabled is False
    start_buttons[0].click().run()
    assert not at.exception
    assert live_client.active_session is not None
    created_session_id = live_client.active_session.session_id

    # Navigate to "My Datasets" and confirm upload submit button is disabled and 0 user datasets shown
    at.sidebar.radio[0].set_value("My Datasets").run()
    assert not at.exception
    upload_buttons = [
        b for b in at.button if "Submit Dataset for Isolated Profiling" in b.label
    ]
    assert len(upload_buttons) == 1
    assert upload_buttons[0].disabled is True
    assert any("0 user datasets" in info.value for info in at.info)

    # Navigate to "AI Analysis" and confirm sandbox execution button is disabled
    at.sidebar.radio[0].set_value("AI Analysis").run()
    assert not at.exception
    exec_buttons = [
        b for b in at.button if "Execute Generated Python in Sandbox" in b.label
    ]
    assert len(exec_buttons) == 1
    assert exec_buttons[0].disabled is True
    assert any("No active `AIAnalysisPlan`" in info.value for info in at.info)

    # Navigate to "Analysis History" and confirm 0 persisted runs
    at.sidebar.radio[0].set_value("Analysis History").run()
    assert not at.exception
    assert any("0 persisted runs" in info.value for info in at.info)

    # Navigate to "Settings / Privacy" and revoke the active session
    at.sidebar.radio[0].set_value("Settings / Privacy").run()
    assert not at.exception
    revoke_buttons = [
        b for b in at.button if "Revoke Session & Queue Deletion" in b.label
    ]
    assert len(revoke_buttons) == 1
    revoke_buttons[0].click().run()
    assert not at.exception
    assert live_client.active_session is None
    receipt = at.session_state["last_deletion_receipt"]
    assert receipt is not None
    assert receipt.session_id == created_session_id
    assert receipt.access_revoked is True
    assert receipt.cleanup_status == "not_started"
    assert any("not yet complete" in s.value for s in at.success)


def test_streamlit_dashboard_handles_offline_backend_cleanly() -> None:
    def offline_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Backend down", request=request)

    offline_client = _mock_client(offline_handler)
    at = AppTest.from_file(str(APP_PATH), default_timeout=15)
    at.session_state["api_client"] = offline_client
    at.session_state["backend_status"] = offline_client.probe_backend_status()
    at.run()
    assert not at.exception

    metrics = {m.label: m.value for m in at.metric}
    assert metrics["FastAPI Control Plane"] == "Offline"
    start_buttons = [b for b in at.button if b.label == "Start Synthetic Session"]
    assert len(start_buttons) == 1
    assert start_buttons[0].disabled is True

    # Navigate to AI Analysis while backend is offline and confirm planning button is disabled
    at.sidebar.radio[0].set_value("AI Analysis").run()
    assert not at.exception
    plan_buttons = [
        b for b in at.button if "Generate Simulated AI Analysis Plan" in b.label
    ]
    assert len(plan_buttons) == 1
    assert plan_buttons[0].disabled is True
