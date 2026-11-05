"""Focused tests for the deterministic pandas CSV analytics workflow across FastAPI and Streamlit."""

from pathlib import Path
import json
import sys
import time

from fastapi.testclient import TestClient
import httpx
import pytest
from streamlit.testing.v1 import AppTest

from backend.config import Settings
from backend.inference import build_validated_dataset_schema
from backend.main import create_app
from backend.planning import UploadedCsvAnalyticsOutcome
from frontend.api_client import (
    FrontendClientCode,
    FrontendClientError,
    MAX_CSV_UPLOAD_BYTES,
    SheetSafeApiClient,
)
from validator.csv_analytics import (
    CsvAnalyticsCode,
    CsvAnalyticsError,
    compute_validated_csv_analytics,
)


ORIGIN = "http://localhost:8501"
DEV_BASE = "http://127.0.0.1:8000"
APP_PATH = Path(__file__).resolve().parents[1] / "frontend" / "app.py"

SAMPLE_CSV_BYTES = (
    b"order_date,region,department,revenue_usd,units,notes\n"
    b"2025-01-15,North America,Enterprise,12500.50,25, normal_note\n"
    b"2025-01-15,Europe,MidMarket,8400.00,14,=SUM(A1:A2)\n"
    b"2025-02-15,North America,Enterprise,15500.25,,\n"
    b"2025-02-15,Asia Pacific,Commercial,6200.75,10,+cmd|' /C calc'!A0\n"
    b"2025-03-15,Europe,MidMarket,9100.00,16,\n"
    b"2025-03-15,North America,Enterprise,18300.50,30,final_row\n"
)


@pytest.fixture
def csv_app_client(tmp_path: Path):
    settings = Settings(
        _env_file=None,
        environment="development",
        allow_insecure_local_cookies=True,
        synthetic_planning_enabled=True,
        planning_requests_per_session_per_minute=10,
        max_runs_per_session=20,
        database_path=tmp_path / "csv_analytics.sqlite3",
        private_storage_path=tmp_path / "storage",
        allowed_origins=(ORIGIN,),
        database_busy_timeout_ms=2000,
    )
    app = create_app(settings)
    with TestClient(app, base_url=DEV_BASE, client=("127.0.0.1", 50000)) as tc:
        yield tc


def _bootstrap_session(client: TestClient) -> tuple[str, str, str]:
    resp = client.post(
        "/api/v1/sessions",
        json={"mode": "synthetic"},
        headers={"Origin": ORIGIN, "X-SheetSafe-Request": "1"},
    )
    assert resp.status_code == 201
    data = resp.json()
    cookie_name = client.app.state.settings.session_cookie_name
    credential = client.cookies.get(cookie_name)
    assert credential is not None
    return data["session_id"], credential, data["csrf_token"]


def _auth_headers(
    client: TestClient,
    credential: str,
    csrf_token: str | None = None,
) -> dict[str, str]:
    cookie_name = client.app.state.settings.session_cookie_name
    headers = {
        "Origin": ORIGIN,
        "Cookie": f"{cookie_name}={credential}",
    }
    if csrf_token is not None:
        headers["X-CSRF-Token"] = csrf_token
    return headers


def test_deterministic_pandas_csv_analytics_bundle_computes_exact_stats() -> None:
    bundle = compute_validated_csv_analytics(
        filename="regional_sales_2025.csv",
        raw_bytes=SAMPLE_CSV_BYTES,
    )
    assert bundle.filename == "regional_sales_2025.csv"
    assert bundle.byte_count == len(SAMPLE_CSV_BYTES)
    assert bundle.delimiter == ","
    assert bundle.row_count == 6
    assert bundle.column_count == 6
    assert bundle.total_missing_cells == 3  # 1 missing in units, 2 missing in notes
    assert bundle.dataset_completeness_pct == round((33 / 36) * 100.0, 2)

    col_by_name = {c.name: c for c in bundle.columns}
    assert col_by_name["order_date"].inferred_type == "text"
    assert col_by_name["order_date"].pandas_dtype == "date[ISO-8601]"
    assert col_by_name["region"].inferred_type == "text"
    assert col_by_name["region"].pandas_dtype == "string"
    assert col_by_name["revenue_usd"].inferred_type == "number"
    assert col_by_name["revenue_usd"].pandas_dtype == "float64"
    assert col_by_name["units"].inferred_type == "integer"
    assert col_by_name["units"].pandas_dtype == "Int64"
    assert col_by_name["units"].missing_count == 1
    assert col_by_name["notes"].missing_count == 2

    # First few rows (capped at 5 rows) with formula-injection neutralization
    assert len(bundle.preview_rows) == 5
    assert bundle.preview_rows[1][5] == "'=SUM(A1:A2)"
    assert bundle.preview_rows[3][5] == "'+cmd|' /C calc'!A0"

    # Numerical summaries
    num_by_name = {ns.column_name: ns for ns in bundle.numeric_summaries}
    assert set(num_by_name) == {"revenue_usd", "units"}
    rev = num_by_name["revenue_usd"]
    assert rev.non_null_count == 6
    assert rev.null_count == 0
    assert rev.total_sum == 70002.0
    assert rev.mean_value == 11667.0
    assert rev.min_value == 6200.75
    assert rev.max_value == 18300.5

    units = num_by_name["units"]
    assert units.non_null_count == 5
    assert units.null_count == 1
    assert units.total_sum == 95.0
    assert units.mean_value == 19.0
    assert units.median_value == 16.0
    assert units.min_value == 10.0
    assert units.max_value == 30.0

    # Chart (date + numeric -> chronological LINE chart)
    assert bundle.chart.chart_kind == "LINE"
    assert bundle.chart.x_label == "order_date"
    assert bundle.chart.y_label == "revenue_usd"
    assert bundle.chart.aggregation == "sum"
    assert [(pt.x, pt.y) for pt in bundle.chart.series] == [
        ("2025-01-15", 20900.5),
        ("2025-02-15", 21701.0),
        ("2025-03-15", 27400.5),
    ]


def test_deterministic_pandas_chart_modes_for_categorical_and_text_only_csvs() -> None:
    # Categorical + numeric -> BAR chart sorted by sum descending
    cat_csv = b"category,score\nBeta,10\nAlpha,35\nBeta,15\n"
    cat_bundle = compute_validated_csv_analytics(filename="scores.csv", raw_bytes=cat_csv)
    assert cat_bundle.chart.chart_kind == "BAR"
    assert cat_bundle.chart.aggregation == "sum"
    assert [(pt.x, pt.y) for pt in cat_bundle.chart.series] == [
        ("Alpha", 35.0),
        ("Beta", 25.0),
    ]

    # Numeric-only -> BAR chart by row
    num_csv = b"metric_a,metric_b\n10.5,1\n20.0,2\n"
    num_bundle = compute_validated_csv_analytics(filename="numbers.csv", raw_bytes=num_csv)
    assert num_bundle.chart.chart_kind == "BAR"
    assert num_bundle.chart.aggregation == "value"
    assert [(pt.x, pt.y) for pt in num_bundle.chart.series] == [
        ("Row 1", 10.5),
        ("Row 2", 20.0),
    ]

    # Text-only -> BAR chart of value_counts
    txt_csv = b"status,owner\nOpen,Alice\nClosed,Bob\nOpen,Carol\n"
    txt_bundle = compute_validated_csv_analytics(filename="statuses.csv", raw_bytes=txt_csv)
    assert txt_bundle.chart.chart_kind == "BAR"
    assert txt_bundle.chart.aggregation == "count"
    assert [(pt.x, pt.y) for pt in txt_bundle.chart.series] == [
        ("Open", 2.0),
        ("Closed", 1.0),
    ]


@pytest.mark.parametrize(
    ("filename", "payload", "delimiter", "expected_code"),
    [
        ("report.xlsx", SAMPLE_CSV_BYTES, None, CsvAnalyticsCode.INVALID_CSV_FILENAME),
        ("../secret.csv", SAMPLE_CSV_BYTES, None, CsvAnalyticsCode.INVALID_CSV_FILENAME),
        ("sub/data.csv", SAMPLE_CSV_BYTES, None, CsvAnalyticsCode.INVALID_CSV_FILENAME),
        (".csv", SAMPLE_CSV_BYTES, None, CsvAnalyticsCode.INVALID_CSV_FILENAME),
        ("empty.csv", b"", None, CsvAnalyticsCode.EMPTY_CSV_UPLOAD),
        ("spaces.csv", b"   \n  ", None, CsvAnalyticsCode.EMPTY_CSV_UPLOAD),
        ("header_only.csv", b"col1,col2\n", None, CsvAnalyticsCode.EMPTY_CSV_UPLOAD),
        (
            "oversized.csv",
            b"a,b\n" + (b"1,2\n" * ((MAX_CSV_UPLOAD_BYTES // 4) + 10)),
            None,
            CsvAnalyticsCode.CSV_PAYLOAD_TOO_LARGE,
        ),
        ("binary.csv", b"col1,col2\n1\x00,2\n", None, CsvAnalyticsCode.INVALID_UTF8_ENCODING),
        ("bad_utf8.csv", b"col1,col2\n\xff\xfe,2\n", None, CsvAnalyticsCode.INVALID_UTF8_ENCODING),
        ("unclosed_quote.csv", b'col1,col2\n"abc,2\n', None, CsvAnalyticsCode.MALFORMED_CSV_CONTENT),
        ("ragged.csv", b"col1,col2\n1,2,3\n", None, CsvAnalyticsCode.MALFORMED_CSV_CONTENT),
        ("dup_header.csv", b"col1,col1\n1,2\n", None, CsvAnalyticsCode.MALFORMED_CSV_CONTENT),
        ("ambiguous.csv", b"a,b;c\n1,2;3\n", None, CsvAnalyticsCode.AMBIGUOUS_CSV_DELIMITER),
    ],
    ids=[
        "xlsx_ext",
        "path_traversal",
        "subdir_path",
        "bare_ext",
        "empty_bytes",
        "whitespace_only",
        "header_only",
        "oversized_payload",
        "nul_byte",
        "invalid_utf8",
        "unclosed_quote",
        "ragged_rows",
        "duplicate_header",
        "ambiguous_delimiter",
    ],
)
def test_csv_analytics_strict_validation_rejections(
    filename: str,
    payload: bytes,
    delimiter: str | None,
    expected_code: CsvAnalyticsCode,
) -> None:
    with pytest.raises(CsvAnalyticsError) as exc_info:
        compute_validated_csv_analytics(
            filename=filename,
            raw_bytes=payload,
            delimiter=delimiter,
        )
    assert exc_info.value.code is expected_code


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows Security blocks temp directory and Starlette TestClient lifespan thread; verified on Vultr Ubuntu",
)
def test_fastapi_csv_analytics_endpoint_and_coexistence_with_synthetic_demo(
    csv_app_client: TestClient,
) -> None:
    session_id, cred, csrf = _bootstrap_session(csv_app_client)

    # 1. Missing CSRF is rejected with 403
    no_csrf_resp = csv_app_client.post(
        "/api/v1/planning/csv-analytics",
        json={"filename": "sales.csv", "csv_text": SAMPLE_CSV_BYTES.decode("utf-8")},
        headers=_auth_headers(csv_app_client, cred, csrf_token=None),
    )
    assert no_csrf_resp.status_code == 403

    # 2. Valid CSV upload succeeds and returns full deterministic analytics
    ok_resp = csv_app_client.post(
        "/api/v1/planning/csv-analytics",
        json={"filename": "sales.csv", "csv_text": SAMPLE_CSV_BYTES.decode("utf-8")},
        headers=_auth_headers(csv_app_client, cred, csrf),
    )
    assert ok_resp.status_code == 200
    body = ok_resp.json()
    assert body["session_id"] == session_id
    assert body["filename"] == "sales.csv"
    assert body["row_count"] == 6
    assert body["column_count"] == 6
    assert body["is_synthetic_fixture"] is False
    assert body["execution_mode"] == "DETERMINISTIC_PANDAS_HOST"
    assert body["ai_code_executed"] is False
    assert len(body["columns"]) == 6
    assert len(body["preview_rows"]) == 5
    assert len(body["numeric_summaries"]) == 2
    assert body["chart"]["chart_kind"] == "LINE"

    # 3. Synthetic demo dataset still provisions cleanly in the same session
    syn_resp = csv_app_client.post(
        "/api/v1/planning/synthetic-dataset",
        json={},
        headers=_auth_headers(csv_app_client, cred, csrf),
    )
    assert syn_resp.status_code == 200
    assert syn_resp.json()["is_synthetic_fixture"] is True

    # 4. Sensitive column header is blocked with 422 SENSITIVE_METADATA_BLOCKED
    sensitive_resp = csv_app_client.post(
        "/api/v1/planning/csv-analytics",
        json={"filename": "bad.csv", "csv_text": "customer_ssn,amount\n123,456\n"},
        headers=_auth_headers(csv_app_client, cred, csrf),
    )
    assert sensitive_resp.status_code == 422
    assert sensitive_resp.json()["code"] == "SENSITIVE_METADATA_BLOCKED"


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows Security blocks temp directory and Streamlit AppTest process; verified on Vultr Ubuntu",
)
def test_streamlit_end_to_end_csv_upload_and_synthetic_demo_workflow(
    csv_app_client: TestClient,
) -> None:
    at = AppTest.from_file(str(APP_PATH), default_timeout=15)
    live_client = SheetSafeApiClient(
        api_base_url=DEV_BASE,
        client_origin=ORIGIN,
        transport=csv_app_client._transport,
    )
    at.session_state["api_client"] = live_client
    at.session_state["backend_status"] = live_client.probe_backend_status()
    at.run()
    assert not at.exception

    # Start session on Dashboard
    start_btn = [b for b in at.button if b.label == "Start Synthetic Session"][0]
    start_btn.click().run()
    assert not at.exception
    assert live_client.active_session is not None

    # Navigate to "My Datasets"
    at.sidebar.radio[0].set_value("My Datasets").run()
    assert not at.exception

    # Provide CSV filename and content and click "Upload & Analyze CSV (Deterministic Pandas)"
    filename_inputs = [t for t in at.text_input if t.key == "csv_manual_filename_input"]
    assert len(filename_inputs) == 1
    filename_inputs[0].set_value("hackathon_metrics.csv")

    csv_text_areas = [ta for ta in at.text_area if ta.key == "csv_manual_text_input"]
    assert len(csv_text_areas) == 1
    csv_text_areas[0].set_value(SAMPLE_CSV_BYTES.decode("utf-8"))

    analyze_btns = [
        b for b in at.button if b.key == "btn_upload_analyze_csv"
    ]
    assert len(analyze_btns) == 1
    assert analyze_btns[0].disabled is False
    analyze_btns[0].click().run()
    assert not at.exception

    uploaded_view = at.session_state["uploaded_csv_analytics"]
    assert uploaded_view is not None
    assert uploaded_view.filename == "hackathon_metrics.csv"
    assert uploaded_view.row_count == 6
    assert uploaded_view.column_count == 6
    assert uploaded_view.total_missing_cells == 3
    assert uploaded_view.ai_code_executed is False
    assert len(uploaded_view.numeric_summaries) == 2
    assert len(uploaded_view.chart.series) == 3

    metrics = {m.label: m.value for m in at.metric}
    assert metrics["Uploaded Row Count"] == "6"
    assert metrics["Uploaded Column Count"] == "6"
    assert metrics["Total Missing Cells"] == "3"

    # Also provision synthetic demo dataset in the same session to verify demo mode preservation
    provision_btns = [
        b for b in at.button if "Provision Synthetic Demo Dataset" in b.label
    ]
    assert len(provision_btns) == 1
    provision_btns[0].click().run()
    assert not at.exception
    assert at.session_state["synthetic_dataset"] is not None
    assert at.session_state["synthetic_dataset"].is_synthetic_fixture is True

    # Revoke session on Settings / Privacy and confirm uploaded CSV state is cleared
    at.sidebar.radio[0].set_value("Settings / Privacy").run()
    revoke_btn = [b for b in at.button if "Revoke Session & Queue Deletion" in b.label][0]
    revoke_btn.click().run()
    assert not at.exception
    assert at.session_state["uploaded_csv_analytics"] is None
    assert at.session_state["synthetic_dataset"] is None

    # Legacy gated methods remain fail-closed
    with pytest.raises(FrontendClientError) as exc_info:
        live_client.submit_dataset_upload(SAMPLE_CSV_BYTES)
    assert exc_info.value.code is FrontendClientCode.FEATURE_DISABLED_BY_GATE


def test_api_client_csv_analytics_via_mock_transport() -> None:
    session_id = "a" * 32
    csrf_token = "b" * 64
    dataset_id = "c" * 32

    def mock_handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        req_id = "d" * 32
        if path == "/api/v1/sessions" and request.method == "POST":
            return httpx.Response(
                201,
                headers={
                    "X-Request-ID": req_id,
                    "Set-Cookie": "__Host-sheetsafe_session=" + ("A" * 43) + "; HttpOnly; SameSite=Strict; Path=/",
                },
                json={
                    "session_id": session_id,
                    "mode": "synthetic",
                    "expires_at": int(time.time()) + 3600,
                    "lifetime_seconds": 3600,
                    "private_uploads_enabled": False,
                    "csrf_token": csrf_token,
                },
            )
        if path == "/api/v1/planning/csv-analytics" and request.method == "POST":
            assert request.headers.get("X-CSRF-Token") == csrf_token
            body = json.loads(request.content.decode("utf-8"))
            bundle = compute_validated_csv_analytics(
                filename=body["filename"],
                raw_bytes=body["csv_text"].encode("utf-8"),
                delimiter=body.get("delimiter"),
            )
            schema = build_validated_dataset_schema(bundle.profile)
            outcome = UploadedCsvAnalyticsOutcome(
                dataset_id=dataset_id,
                session_id=session_id,
                filename=bundle.filename,
                byte_count=bundle.byte_count,
                source_sha256=bundle.source_sha256,
                schema_sha256=schema.schema_sha256,
                delimiter=bundle.delimiter,
                row_count=bundle.row_count,
                column_count=bundle.column_count,
                nonempty_cells=bundle.nonempty_cells,
                total_missing_cells=bundle.total_missing_cells,
                dataset_completeness_pct=bundle.dataset_completeness_pct,
                columns=bundle.columns,
                preview_headers=bundle.preview_headers,
                preview_rows=bundle.preview_rows,
                numeric_summaries=bundle.numeric_summaries,
                chart=bundle.chart,
                warnings=bundle.warnings,
            )
            return httpx.Response(
                200,
                headers={"X-Request-ID": req_id},
                content=outcome.model_dump_json().encode("utf-8"),
            )
        return httpx.Response(404, json={"code": "NOT_FOUND", "message": "Not found", "retryable": False})

    mock_client = SheetSafeApiClient(
        api_base_url=DEV_BASE,
        client_origin=ORIGIN,
        transport=httpx.MockTransport(mock_handler),
    )
    mock_client.create_synthetic_session()
    uploaded_view = mock_client.upload_csv_for_analytics(
        filename="regional_sales.csv",
        content=SAMPLE_CSV_BYTES,
    )
    assert uploaded_view.filename == "regional_sales.csv"
    assert uploaded_view.row_count == 6
    assert uploaded_view.column_count == 6
    assert uploaded_view.total_missing_cells == 3
    assert len(uploaded_view.numeric_summaries) == 2
    assert uploaded_view.chart.chart_kind == "LINE"
    assert len(uploaded_view.chart.series) == 3

    # Verify client-side validation rejections
    with pytest.raises(FrontendClientError) as exc_info:
        mock_client.upload_csv_for_analytics(filename="bad.xlsx", content=SAMPLE_CSV_BYTES)
    assert exc_info.value.code is FrontendClientCode.INVALID_REQUEST

    with pytest.raises(FrontendClientError) as exc_info:
        mock_client.upload_csv_for_analytics(filename="empty.csv", content=b"")
    assert exc_info.value.code is FrontendClientCode.INVALID_REQUEST

