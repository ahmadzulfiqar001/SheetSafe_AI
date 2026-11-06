"""Focused tests for Step 11A Streamlit dashboard and typed FastAPI client."""

import ast
from pathlib import Path
import sys
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
from frontend.app import (
    PAGES,
    SUPPORTED_OPERATIONS,
    format_analysis_summary_table_rows,
)


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

    with pytest.raises(FrontendClientError) as exc_info_plan_low:
        SheetSafeApiClient(planning_read_timeout_seconds=0.01)
    assert exc_info_plan_low.value.code is FrontendClientCode.INVALID_CONFIGURATION

    with pytest.raises(FrontendClientError) as exc_info_plan_high:
        SheetSafeApiClient(planning_read_timeout_seconds=120.0)
    assert exc_info_plan_high.value.code is FrontendClientCode.INVALID_CONFIGURATION

    client = _mock_client(lambda _req: httpx.Response(200, json={"status": "ok"}))
    assert client.timeout.connect == 2.0
    assert client.timeout.read == 5.0
    assert client.planning_timeout.connect == 2.0
    assert client.planning_timeout.read == 40.0

    with pytest.raises(FrontendClientError) as exc_path:
        client._request_raw("GET", "/internal/admin")
    assert exc_path.value.code is FrontendClientCode.INVALID_CONFIGURATION


def test_ai_planning_request_uses_bounded_40s_timeout_while_standard_requests_preserve_short_timeout() -> None:
    captured_requests: list[dict] = []

    def mock_backend_handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append({
            "path": request.url.path,
            "method": request.method,
            "timeout": request.extensions.get("timeout"),
            "origin": request.headers.get("origin"),
            "csrf": request.headers.get("x-csrf-token"),
            "cookie": request.headers.get("cookie"),
        })

        if request.url.path == "/api/v1/health":
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/api/v1/ready":
            return httpx.Response(200, json={"status": "ready"})
        if request.url.path == "/api/v1/sessions":
            return httpx.Response(
                201,
                headers={"Set-Cookie": "__Host-sheetsafe_session=" + "S" * 43 + "; HttpOnly; SameSite=Strict; Path=/"},
                json={
                    "session_id": "a" * 32,
                    "mode": "synthetic",
                    "expires_at": 1800000000,
                    "lifetime_seconds": 3600,
                    "private_uploads_enabled": False,
                    "csrf_token": "c" * 64,
                },
            )
        if request.url.path == "/api/v1/planning/csv-analytics":
            return httpx.Response(
                200,
                headers={"X-Request-ID": "f" * 32},
                json={
                    "version": 1,
                    "dataset_id": "b" * 32,
                    "session_id": "a" * 32,
                    "filename": "test.csv",
                    "byte_count": 50,
                    "source_sha256": "0" * 64,
                    "schema_sha256": "1" * 64,
                    "delimiter": ",",
                    "row_count": 2,
                    "column_count": 2,
                    "nonempty_cells": 6,
                    "total_missing_cells": 0,
                    "dataset_completeness_pct": 100.0,
                    "is_synthetic_fixture": False,
                    "execution_mode": "DETERMINISTIC_PANDAS_HOST",
                    "ai_code_executed": False,
                    "columns": [
                        {
                            "column_id": "col_001",
                            "name": "region",
                            "inferred_type": "text",
                            "pandas_dtype": "string",
                            "missing_count": 0,
                            "present_count": 2,
                            "completeness_pct": 100.0,
                        },
                        {
                            "column_id": "col_002",
                            "name": "revenue",
                            "inferred_type": "number",
                            "pandas_dtype": "float64",
                            "missing_count": 0,
                            "present_count": 2,
                            "completeness_pct": 100.0,
                        },
                    ],
                    "preview_headers": ["region", "revenue"],
                    "preview_rows": [["North", "100.0"], ["South", "200.0"]],
                    "numeric_summaries": [
                        {
                            "column_id": "col_002",
                            "column_name": "revenue",
                            "pandas_dtype": "float64",
                            "non_null_count": 2,
                            "null_count": 0,
                            "total_sum": 300.0,
                            "mean_value": 150.0,
                            "median_value": 150.0,
                            "std_value": 50.0,
                            "min_value": 100.0,
                            "max_value": 200.0,
                        }
                    ],
                    "chart": {
                        "chart_kind": "BAR",
                        "chart_title": "Total revenue by region",
                        "x_label": "region",
                        "y_label": "revenue",
                        "aggregation": "sum",
                        "series": [{"x": "North", "y": 100.0}, {"x": "South", "y": 200.0}],
                    },
                    "warnings": [],
                    "request_id": "f" * 32,
                },
            )
        if request.url.path == "/api/v1/planning/preview":
            return httpx.Response(
                200,
                headers={"X-Request-ID": "req_plan_001"},
                json={
                    "run_id": "e" * 32,
                    "session_id": "a" * 32,
                    "dataset_id": "b" * 32,
                    "dataset_version": 1,
                    "run_state": "AWAIT_CONFIRMATION",
                    "provider_mode": "LIVE_VULTR_AI",
                    "simulated_response": False,
                    "provider_label": "Vultr Serverless Inference (llama-3.3-70b-instruct)",
                    "is_synthetic_dataset": False,
                    "execution_enabled": False,
                    "model": "llama-3.3-70b-instruct",
                    "question": "Which region has the highest revenue?",
                    "dataset_schema": {
                        "version": 1,
                        "row_count": 2,
                        "column_count": 2,
                        "columns": [
                            {"column_id": "col_001", "name": "region", "inferred_type": "text", "missing_count": 0},
                            {"column_id": "col_002", "name": "revenue", "inferred_type": "number", "missing_count": 0},
                        ],
                        "schema_sha256": "1" * 64,
                    },
                    "envelope": {
                        "version": 1,
                        "status": "PLAN_READY",
                        "plan": {
                            "version": 1,
                            "schema_sha256": "1" * 64,
                            "intent_summary": "Find region with highest revenue",
                            "required_columns": [
                                {"column_id": "col_001", "name": "region", "expected_type": "text"},
                                {"column_id": "col_002", "name": "revenue", "expected_type": "number"},
                            ],
                            "operations": [
                                {
                                    "step_number": 1,
                                    "operation": "SORT",
                                    "target_columns": ["revenue"],
                                    "sort_direction": "desc",
                                    "limit_rows": 1,
                                    "rationale": "Highest revenue",
                                }
                            ],
                            "expected_result_type": "table",
                        },
                    },
                    "plan_sha256": "1" * 64,
                    "real_data_result": {
                        "answer_text": "Region South had highest revenue ($200.00).",
                        "scalar_value": None,
                        "result_type": "table",
                        "columns": ["region", "revenue"],
                        "column_headers": {"region": "region", "revenue": "revenue"},
                        "rows": [{"region": "South", "revenue": 200.0}],
                        "row_count": 1,
                        "chart_kind": "BAR",
                        "chart_x_label": "region",
                        "chart_y_label": "revenue",
                        "chart_series": [{"x": "South", "y": 200.0}],
                        "execution_mode": "DETERMINISTIC_DATAFRAME_HOST",
                        "ai_code_executed": False,
                    },
                    "request_id": "req_plan_001",
                },
            )
        return httpx.Response(404)

    client = _mock_client(mock_backend_handler)

    # 1. Health check: uses short standard timeout (5s)
    client.check_health()
    assert captured_requests[-1]["path"] == "/api/v1/health"
    assert captured_requests[-1]["timeout"]["read"] == 5.0

    # 2. Ready check: uses short standard timeout (5s)
    client.check_ready()
    assert captured_requests[-1]["path"] == "/api/v1/ready"
    assert captured_requests[-1]["timeout"]["read"] == 5.0

    # 3. Session creation: uses short standard timeout (5s)
    client.create_synthetic_session()
    assert captured_requests[-1]["path"] == "/api/v1/sessions"
    assert captured_requests[-1]["timeout"]["read"] == 5.0

    # 4. CSV upload: uses short standard timeout (5s)
    client.upload_csv_for_analytics(
        filename="test.csv",
        content=b"region,revenue\nNorth,100.0\nSouth,200.0\n",
    )
    assert captured_requests[-1]["path"] == "/api/v1/planning/csv-analytics"
    assert captured_requests[-1]["timeout"]["read"] == 5.0

    # 5. AI Planning request: uses dedicated bounded planning timeout (40s)
    preview = client.create_planning_preview("Which region has the highest revenue?")
    plan_req = captured_requests[-1]
    assert plan_req["path"] == "/api/v1/planning/preview"
    assert plan_req["timeout"]["read"] == 40.0
    assert plan_req["timeout"]["connect"] == 2.0

    # 6. Session authentication & CSRF boundary verified
    assert plan_req["origin"] == TEST_ORIGIN
    assert plan_req["csrf"] == "c" * 64
    assert plan_req["cookie"] == "__Host-sheetsafe_session=" + "S" * 43

    # 7. Provider mode and response attributes accurately reported
    assert preview.provider_mode == "LIVE_VULTR_AI"
    assert preview.simulated_response is False
    assert "Vultr Serverless Inference" in preview.provider_label
    assert preview.real_data_result is not None
    assert preview.real_data_result.ai_code_executed is False


def test_ai_planning_provider_modes_and_failure_boundaries() -> None:
    current_mode = "SIMULATED_MOCK"
    backend_status_code = 200

    def mock_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/sessions":
            return httpx.Response(
                201,
                headers={"Set-Cookie": "__Host-sheetsafe_session=" + "T" * 43 + "; HttpOnly; SameSite=Strict; Path=/"},
                json={
                    "session_id": "1" * 32,
                    "mode": "synthetic",
                    "expires_at": 1800000000,
                    "lifetime_seconds": 3600,
                    "private_uploads_enabled": False,
                    "csrf_token": "2" * 64,
                },
            )
        if request.url.path == "/api/v1/planning/preview":
            if backend_status_code == 504:
                return httpx.Response(
                    504,
                    headers={"X-Request-ID": "e" * 32},
                    json={
                        "code": "PROVIDER_TIMEOUT",
                        "message": "AI inference provider timed out while generating a plan.",
                        "retryable": True,
                        "request_id": "e" * 32,
                    },
                )
            if backend_status_code == 503:
                return httpx.Response(
                    503,
                    headers={"X-Request-ID": "e" * 32},
                    json={
                        "code": "PROVIDER_UNAVAILABLE",
                        "message": "AI inference provider is currently unavailable.",
                        "retryable": True,
                        "request_id": "e" * 32,
                    },
                )
            sim = (current_mode != "LIVE_VULTR_AI")
            label = (
                "SheetSafe Deterministic Intent Parser (Offline Fallback)"
                if current_mode == "DETERMINISTIC_FALLBACK"
                else "Simulated Deterministic Planning Mock"
            )
            return httpx.Response(
                200,
                headers={"X-Request-ID": "p" * 32},
                json={
                    "run_id": "3" * 32,
                    "session_id": "1" * 32,
                    "dataset_id": "4" * 32,
                    "dataset_version": 1,
                    "run_state": "AWAIT_CONFIRMATION",
                    "provider_mode": current_mode,
                    "simulated_response": sim,
                    "provider_label": label,
                    "is_synthetic_dataset": (current_mode == "SIMULATED_MOCK"),
                    "execution_enabled": False,
                    "model": "simulated-v1",
                    "question": "Show revenue",
                    "dataset_schema": {
                        "version": 1,
                        "row_count": 2,
                        "column_count": 1,
                        "columns": [{"column_id": "col_001", "name": "revenue", "inferred_type": "number", "missing_count": 0}],
                        "schema_sha256": "5" * 64,
                    },
                    "envelope": {
                        "version": 1,
                        "status": "PLAN_READY",
                        "plan": {
                            "version": 1,
                            "schema_sha256": "5" * 64,
                            "intent_summary": "Show revenue",
                            "required_columns": [{"column_id": "col_001", "name": "revenue", "expected_type": "number"}],
                            "operations": [{"step_number": 1, "operation": "SELECT", "target_columns": ["revenue"], "rationale": "Select"}],
                            "expected_result_type": "table",
                        },
                    },
                    "plan_sha256": "6" * 64,
                    "request_id": "p" * 32,
                },
            )
        return httpx.Response(404)

    client = _mock_client(mock_handler)
    client.create_synthetic_session()

    # Verify SIMULATED_MOCK mode
    current_mode = "SIMULATED_MOCK"
    sim_preview = client.create_planning_preview("Show revenue")
    assert sim_preview.provider_mode == "SIMULATED_MOCK"
    assert sim_preview.simulated_response is True

    # Verify DETERMINISTIC_FALLBACK mode
    current_mode = "DETERMINISTIC_FALLBACK"
    fallback_preview = client.create_planning_preview("Show revenue")
    assert fallback_preview.provider_mode == "DETERMINISTIC_FALLBACK"
    assert fallback_preview.simulated_response is True
    assert "Deterministic Intent Parser" in fallback_preview.provider_label

    # Verify upstream 504 provider timeout failure maps to BACKEND_TIMEOUT with retryable=True
    backend_status_code = 504
    with pytest.raises(FrontendClientError) as exc_504:
        client.create_planning_preview("Show revenue")
    assert exc_504.value.code is FrontendClientCode.BACKEND_TIMEOUT
    assert exc_504.value.retryable is True
    assert exc_504.value.status_code == 504

    # Verify upstream 503 provider unavailable maps to SERVICE_UNAVAILABLE with retryable=True
    backend_status_code = 503
    with pytest.raises(FrontendClientError) as exc_503:
        client.create_planning_preview("Show revenue")
    assert exc_503.value.code is FrontendClientCode.SERVICE_UNAVAILABLE
    assert exc_503.value.retryable is True
    assert exc_503.value.status_code == 503

    # Verify client-side HTTPX timeout exception during planning maps safely to BACKEND_TIMEOUT
    def timeout_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/sessions":
            return mock_handler(request)
        raise httpx.ReadTimeout("Read timed out after 40 seconds", request=request)

    timeout_client = _mock_client(timeout_handler)
    timeout_client.create_synthetic_session()
    with pytest.raises(FrontendClientError) as exc_read_timeout:
        timeout_client.create_planning_preview("Show revenue")
    assert exc_read_timeout.value.code is FrontendClientCode.BACKEND_TIMEOUT
    assert exc_read_timeout.value.retryable is True
    assert "FastAPI backend timed out" in exc_read_timeout.value.safe_message


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows Security blocks temp directory and Starlette TestClient lifespan thread; verified on Vultr Ubuntu",
)
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


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows Security blocks temp directory and Starlette TestClient lifespan thread; verified on Vultr Ubuntu",
)
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


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows Security blocks temp directory and Starlette TestClient lifespan thread; verified on Vultr Ubuntu",
)
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


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows Security blocks temp directory and Starlette TestClient lifespan thread; verified on Vultr Ubuntu",
)
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


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows Security blocks temp directory and Starlette TestClient lifespan thread; verified on Vultr Ubuntu",
)
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


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows Security blocks temp directory and Streamlit AppTest process; verified on Vultr Ubuntu",
)
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


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows Security blocks temp directory and Streamlit AppTest process; verified on Vultr Ubuntu",
)
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


def test_format_analysis_summary_table_rows_renders_clean_records_without_pandas() -> None:
    """Verify that table rows are mapped to column headers without pandas or mutation."""
    # 1. Non-empty rows with custom column headers mapping
    rows = (
        {"department": "Enterprise", "revenue_usd": 425000.50},
        {"department": "MidMarket", "revenue_usd": 198500.00},
    )
    headers = {"department": "Department", "revenue_usd": "Total Revenue (USD)"}
    formatted = format_analysis_summary_table_rows(rows, headers)
    assert formatted == [
        {"Department": "Enterprise", "Total Revenue (USD)": 425000.50},
        {"Department": "MidMarket", "Total Revenue (USD)": 198500.00},
    ]

    # 2. Non-empty rows without column headers mapping preserves original keys
    raw_formatted = format_analysis_summary_table_rows(rows, None)
    assert raw_formatted == list(rows)

    # 3. Empty rows safely return empty list
    assert format_analysis_summary_table_rows(()) == []
    assert format_analysis_summary_table_rows([]) == []
    assert format_analysis_summary_table_rows(None) == []

    # 4. Rows containing empty or non-dict items are filtered safely
    assert format_analysis_summary_table_rows([{}, None]) == []  # type: ignore[list-item]


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows Security blocks temp directory and Streamlit AppTest process; verified on Vultr Ubuntu",
)
def test_streamlit_ai_analysis_page_renders_summary_table_and_badges() -> None:
    """Verify that real CSV analysis summary table and provider badges render cleanly."""
    from frontend.api_client import (
        AnalysisPlanView,
        ChartPointView,
        DatasetSchemaView,
        OperationStepView,
        PlanningEnvelopeView,
        PlanningPreviewView,
        RealDataAnalysisResultView,
        RequiredColumnView,
        SchemaColumnView,
    )

    schema = DatasetSchemaView(
        version=1,
        row_count=5,
        column_count=2,
        columns=(
            SchemaColumnView(column_id="col_001", name="department", inferred_type="text", missing_count=0),
            SchemaColumnView(column_id="col_002", name="revenue_usd", inferred_type="number", missing_count=0),
        ),
        schema_sha256="a" * 64,
    )
    plan = AnalysisPlanView(
        version=1,
        schema_sha256="a" * 64,
        intent_summary="Aggregate revenue by department",
        required_columns=(
            RequiredColumnView(column_id="col_001", name="department", expected_type="text"),
            RequiredColumnView(column_id="col_002", name="revenue_usd", expected_type="number"),
        ),
        operations=(
            OperationStepView(
                step_number=1,
                operation="GROUP_AGGREGATE",
                target_columns=("col_002",),
                group_by_columns=("col_001",),
                aggregation="sum",
                rationale="Sum revenue",
            ),
        ),
        expected_result_type="GROUPED_TABLE",
    )
    envelope = PlanningEnvelopeView(
        version=1,
        status="PLAN_READY",
        plan=plan,
    )
    real_data = RealDataAnalysisResultView(
        answer_text="Enterprise generated highest revenue ($425,000.50).",
        scalar_value=425000.50,
        result_type="GROUPED_TABLE",
        columns=("department", "revenue_usd"),
        column_headers={"department": "Department", "revenue_usd": "Total Revenue"},
        rows=(
            {"department": "Enterprise", "revenue_usd": 425000.50},
            {"department": "MidMarket", "revenue_usd": 198500.00},
        ),
        row_count=2,
        chart_kind="BAR",
        chart_x_label="Department",
        chart_y_label="Total Revenue",
        chart_series=(
            ChartPointView(x="Enterprise", y=425000.50),
            ChartPointView(x="MidMarket", y=198500.00),
        ),
        execution_mode="DETERMINISTIC_DATAFRAME_HOST",
        ai_code_executed=False,
    )

    preview = PlanningPreviewView(
        run_id="1" * 32,
        session_id="2" * 32,
        dataset_id="3" * 32,
        dataset_version=1,
        run_state="AWAIT_CONFIRMATION",
        provider_mode="LIVE_VULTR_AI",
        simulated_response=False,
        provider_label="Vultr Serverless Inference (DeepSeek)",
        is_synthetic_dataset=False,
        model="deepseek-v4.1-flash-1017",
        question="Which department had highest revenue?",
        dataset_schema=schema,
        envelope=envelope,
        plan_sha256="4" * 64,
        real_data_result=real_data,
    )

    session_id = "2" * 32

    def mock_handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/api/v1/sessions":
            return httpx.Response(
                201,
                headers={
                    "Set-Cookie": f"sheetsafe_dev_session={'s' * 43}; Path=/; HttpOnly; SameSite=Strict",
                },
                json={
                    "session_id": session_id,
                    "mode": "synthetic",
                    "expires_at": 1800000000,
                    "lifetime_seconds": 3600,
                    "private_uploads_enabled": False,
                    "csrf_token": "b" * 64,
                },
            )
        return httpx.Response(200, json={"status": "ok"})

    client = _mock_client(mock_handler)
    client.create_synthetic_session()

    at = AppTest.from_file(str(APP_PATH), default_timeout=15)
    at.session_state["api_client"] = client
    at.session_state["backend_status"] = client.probe_backend_status()
    at.session_state["latest_plan_preview"] = preview
    at.run()
    assert not at.exception

    # Navigate to AI Analysis
    at.sidebar.radio[0].set_value("AI Analysis").run()
    assert not at.exception
    assert any("LIVE VULTR SERVERLESS" in s.value for s in at.success)
    assert any("Enterprise generated highest revenue" in i.value for i in at.info)
    metric_values = {m.label: m.value for m in at.metric}
    assert "425,000.50" in metric_values.get("Calculated Result", "")
    assert any("Analysis Summary Table" in m.value for m in at.markdown)
    assert len(at.dataframe) >= 1
    assert len(at.dataframe[-1].value) == 2

    # Test DETERMINISTIC_FALLBACK badge rendering
    preview_fallback = PlanningPreviewView(
        run_id="5" * 32,
        session_id="2" * 32,
        dataset_id="3" * 32,
        dataset_version=1,
        run_state="AWAIT_CONFIRMATION",
        provider_mode="DETERMINISTIC_FALLBACK",
        simulated_response=True,
        provider_label="SheetSafe Deterministic Intent Parser (Offline Fallback)",
        is_synthetic_dataset=False,
        model="deterministic-fallback-v1",
        question="Which department had highest revenue?",
        dataset_schema=schema,
        envelope=envelope,
        plan_sha256="4" * 64,
        real_data_result=real_data,
    )
    at.session_state["latest_plan_preview"] = preview_fallback
    at.run()
    assert not at.exception
    assert any("DETERMINISTIC INTENT PARSER" in i.value for i in at.info)
