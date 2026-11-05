"""Focused tests for the deterministic pandas CSV analytics workflow across FastAPI and Streamlit."""

from pathlib import Path
import json
import shutil
import sys
import time

from fastapi.testclient import TestClient
import httpx
import pytest
from streamlit.testing.v1 import AppTest

from backend.config import Settings
from backend.inference import build_validated_dataset_schema
from backend.main import create_app
from backend.planning import (
    PlanningCode,
    PlanningError,
    PlanningPreviewOutcome,
    PlanningService,
    UploadedCsvAnalyticsOutcome,
)
from validator.natural_language_analysis import (
    ChartPointPreview,
    RealDataAnalysisResult,
    execute_deterministic_dataframe_analysis,
    parse_natural_language_intent,
)
from backend.security.sessions import SessionPrincipal
from backend.storage.database import Database
from backend.storage.files import (
    CATEGORIES,
    INPUT_LIMIT,
    PARSED_LIMIT,
    PrivateStorage,
    SessionError,
    TYPES,
)
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
            b"col_a,col_b\n" + (b"1234567890," * 9 + b"123456789\n") * 21000,
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

    # Verify storage contract: stored under 'version' input category with sealed SHA256 and null run_id
    db = csv_app_client.app.state.database
    storage = csv_app_client.app.state.storage
    with db.connection() as conn:
        st_row = conn.execute(
            "SELECT * FROM storage_objects WHERE session_id=? AND category='version'",
            (session_id,),
        ).fetchone()
        assert st_row is not None
        assert st_row["category"] == "version"
        assert st_row["file_type"] == "csv"
        assert st_row["run_id"] is None
        assert st_row["candidate_version"] == 0
        assert st_row["state"] == "SEALED"
        assert st_row["byte_count"] == len(SAMPLE_CSV_BYTES)

    # 3. Synthetic demo dataset still provisions cleanly in the same session without storage-slot conflict
    syn_resp = csv_app_client.post(
        "/api/v1/planning/synthetic-dataset",
        json={},
        headers=_auth_headers(csv_app_client, cred, csrf),
    )
    assert syn_resp.status_code == 200
    assert syn_resp.json()["is_synthetic_fixture"] is True

    # Verify coexistence: both 'version' (uploaded) and 'original' (synthetic) exist in the same session
    with db.connection() as conn:
        categories = {
            r["category"]
            for r in conn.execute(
                "SELECT category FROM storage_objects WHERE session_id=?",
                (session_id,),
            ).fetchall()
        }
        assert "version" in categories
        assert "original" in categories

    # 4. Sensitive column header is blocked with 422 SENSITIVE_METADATA_BLOCKED
    sensitive_resp = csv_app_client.post(
        "/api/v1/planning/csv-analytics",
        json={"filename": "bad.csv", "csv_text": "customer_ssn,amount\n123,456\n"},
        headers=_auth_headers(csv_app_client, cred, csrf),
    )
    assert sensitive_resp.status_code == 422
    assert sensitive_resp.json()["code"] == "SENSITIVE_METADATA_BLOCKED"

    # 5. Multiple CSV uploads in the same session succeed without storage collision
    second_csv = b"item,price\nwidget,19.99\ngadget,29.99\n"
    second_resp = csv_app_client.post(
        "/api/v1/planning/csv-analytics",
        json={"filename": "second.csv", "csv_text": second_csv.decode("utf-8")},
        headers=_auth_headers(csv_app_client, cred, csrf),
    )
    assert second_resp.status_code == 200
    assert second_resp.json()["row_count"] == 2


def test_csv_analytics_storage_lifecycle_contract_and_limits() -> None:
    """Direct contract verification of category/type rules, metadata bounds, and storage coexistence."""
    assert "snapshot" not in CATEGORIES
    assert "version" in CATEGORIES
    assert "csv" in TYPES["version"]
    assert PrivateStorage._limit("version", "csv") == PARSED_LIMIT
    assert PrivateStorage._limit("original", "csv") == INPUT_LIMIT

    scratch = Path(__file__).resolve().parents[1] / "var" / "test_scratch_storage_contract"
    if scratch.exists():
        shutil.rmtree(scratch)
    scratch.mkdir(parents=True)

    try:
        settings = Settings(
            _env_file=None,
            environment="development",
            database_path=scratch / "test.sqlite3",
            private_storage_path=scratch / "store",
            allowed_origins=(ORIGIN,),
        )
        db = Database(settings)
        db.initialize()
        storage = PrivateStorage(db, settings)
        storage.initialize()

        principal = SessionPrincipal(
            session_id="1" * 32,
            audit_pseudonym="p" * 16,
            expires_at=2000000000,
            auth_token_hash="0" * 64,
            csrf_token="0" * 64,
        )
        with db.transaction() as conn:
            conn.execute(
                "INSERT INTO sessions(session_id, auth_token_hash, audit_pseudonym) VALUES (?, ?, ?)",
                (principal.session_id, "0" * 64, principal.audit_pseudonym),
            )

        # 1. Reject unallowlisted category 'snapshot' -> 415
        with pytest.raises(SessionError) as exc_info:
            storage.store(
                principal,
                category="snapshot",
                file_type="csv",
                chunks=[b"a,b\n1,2\n"],
                byte_count=8,
            )
        assert exc_info.value.status_code == 415

        # 2. Reject non-input metadata (run_id) with input category 'version' -> 400
        with pytest.raises(SessionError) as exc_info:
            storage.store(
                principal,
                category="version",
                file_type="csv",
                chunks=[b"a,b\n1,2\n"],
                byte_count=8,
                run_id="r" * 32,
            )
        assert exc_info.value.status_code == 400

        # 3. Reject non-input metadata (candidate_version != 0) with 'version' -> 400
        with pytest.raises(SessionError) as exc_info:
            storage.store(
                principal,
                category="version",
                file_type="csv",
                chunks=[b"a,b\n1,2\n"],
                byte_count=8,
                candidate_version=1,
            )
        assert exc_info.value.status_code == 400

        # 4. Reject unsupported file type for 'version' -> 415
        with pytest.raises(SessionError) as exc_info:
            storage.store(
                principal,
                category="version",
                file_type="py",
                chunks=[b"print(1)\n"],
                byte_count=9,
            )
        assert exc_info.value.status_code == 415

        # 5. Valid store with category='version', file_type='csv' -> SEALED and readable
        csv_data = b"col_a,col_b\n10,20\n30,40\n"
        stored = storage.store(
            principal,
            category="version",
            file_type="csv",
            chunks=[csv_data],
            byte_count=len(csv_data),
            run_id=None,
            candidate_version=0,
        )
        assert stored.category == "version"
        assert stored.file_type == "csv"
        assert stored.byte_count == len(csv_data)

        # 6. Read back matches original uploaded bytes exactly
        assert storage.read(principal, stored.object_id) == csv_data

        # 7. Multiple 'version' files in the same session succeed without collision
        stored2 = storage.store(
            principal,
            category="version",
            file_type="csv",
            chunks=[b"x,y\n1,2\n"],
            byte_count=8,
        )
        assert stored2.object_id != stored.object_id

        # 8. Synthetic fixture 'original' also stores in the same session without slot conflict
        stored_orig = storage.store(
            principal,
            category="original",
            file_type="csv",
            chunks=[b"orig,val\n1,1\n"],
            byte_count=13,
        )
        assert stored_orig.category == "original"
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


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


def test_natural_language_intent_parser_allowlisted_operations() -> None:
    bundle = compute_validated_csv_analytics(filename="sales.csv", raw_bytes=SAMPLE_CSV_BYTES)
    schema = build_validated_dataset_schema(bundle.profile)

    # 1. Extremum question: "Which region has the highest total revenue?"
    env1 = parse_natural_language_intent("Which region has the highest total revenue?", schema)
    assert env1.status == "PLAN_READY"
    assert env1.plan is not None
    assert env1.plan.expected_result_type in {"RANKED_TABLE", "SCALAR_METRIC"}
    assert any(op.operation in {"TOP_N", "GROUP_AGGREGATE"} for op in env1.plan.operations)
    assert any(op.aggregation in {"max", "sum"} for op in env1.plan.operations)

    # 2. Average metric question: "What is the average revenue_usd?"
    env2 = parse_natural_language_intent("What is the average revenue_usd?", schema)
    assert env2.status == "PLAN_READY"
    assert env2.plan is not None
    assert env2.plan.expected_result_type == "SCALAR_METRIC"
    assert any(op.operation == "SUMMARY_STATS" and op.aggregation == "mean" for op in env2.plan.operations)

    # 3. Grouped breakdown question: "Show total revenue by department."
    env3 = parse_natural_language_intent("Show total revenue by department.", schema)
    assert env3.status == "PLAN_READY"
    assert env3.plan is not None
    assert env3.plan.expected_result_type in {"GROUPED_TABLE", "BAR_CHART"}
    assert any(op.operation == "GROUP_AGGREGATE" for op in env3.plan.operations)


def test_natural_language_intent_parser_rejects_missing_column() -> None:
    bundle = compute_validated_csv_analytics(filename="sales.csv", raw_bytes=SAMPLE_CSV_BYTES)
    schema = build_validated_dataset_schema(bundle.profile)

    # Missing metric column: "profit" does not exist in schema
    env = parse_natural_language_intent("What is the average profit?", schema)
    assert env.status == "CLARIFICATION_REQUIRED"
    assert env.clarification is not None
    assert env.clarification.reason_code == "MISSING_TARGET_COLUMN"
    assert "profit" in env.clarification.clarification_prompt
    assert len(env.clarification.candidate_columns) > 0

    # Missing grouping column: "nonexistent_dept"
    env2 = parse_natural_language_intent("Show revenue by nonexistent_dept", schema)
    assert env2.status == "CLARIFICATION_REQUIRED"
    assert env2.clarification is not None
    assert env2.clarification.reason_code == "MISSING_TARGET_COLUMN"


def test_natural_language_intent_parser_handles_ambiguous_question() -> None:
    bundle = compute_validated_csv_analytics(filename="sales.csv", raw_bytes=SAMPLE_CSV_BYTES)
    schema = build_validated_dataset_schema(bundle.profile)

    env = parse_natural_language_intent("Which metric has the best performance?", schema)
    assert env.status == "CLARIFICATION_REQUIRED"
    assert env.clarification is not None
    assert env.clarification.reason_code == "AMBIGUOUS_METRIC"


def test_deterministic_dataframe_analysis_answers_real_csv_queries() -> None:
    bundle = compute_validated_csv_analytics(filename="sales.csv", raw_bytes=SAMPLE_CSV_BYTES)
    schema = build_validated_dataset_schema(bundle.profile)

    # 1. Extremum / Ranked question
    env_top = parse_natural_language_intent("Which region has the highest total revenue?", schema)
    assert env_top.plan is not None
    res_top = execute_deterministic_dataframe_analysis(
        csv_bytes=SAMPLE_CSV_BYTES,
        delimiter=bundle.profile.delimiter,
        plan=env_top.plan,
        schema=schema,
    )
    assert res_top.scalar_value == 46301.25
    assert "North America" in res_top.answer_text
    assert res_top.ai_code_executed is False
    assert res_top.execution_mode == "DETERMINISTIC_DATAFRAME_HOST"

    # 2. Scalar average question
    env_avg = parse_natural_language_intent("What is the average revenue_usd?", schema)
    assert env_avg.plan is not None
    res_avg = execute_deterministic_dataframe_analysis(
        csv_bytes=SAMPLE_CSV_BYTES,
        delimiter=bundle.profile.delimiter,
        plan=env_avg.plan,
        schema=schema,
    )
    assert res_avg.scalar_value == 11667.0
    assert "11,667" in res_avg.answer_text

    # 3. Grouped breakdown with chart series
    env_grp = parse_natural_language_intent("Show total revenue by department.", schema)
    assert env_grp.plan is not None
    res_grp = execute_deterministic_dataframe_analysis(
        csv_bytes=SAMPLE_CSV_BYTES,
        delimiter=bundle.profile.delimiter,
        plan=env_grp.plan,
        schema=schema,
    )
    assert len(res_grp.rows) == 3
    assert res_grp.chart_kind == "BAR"
    assert len(res_grp.chart_series) == 3
    sums_by_dept = {str(pt.x): pt.y for pt in res_grp.chart_series}
    assert sums_by_dept["Enterprise"] == 46301.25
    assert sums_by_dept["MidMarket"] == 17500.00
    assert sums_by_dept["Commercial"] == 6200.75


def test_planning_service_real_csv_natural_language_workflow() -> None:
    scratch = Path(__file__).resolve().parents[1] / "var" / "test_scratch_planning_nla"
    if scratch.exists():
        shutil.rmtree(scratch)
    scratch.mkdir(parents=True)

    try:
        settings = Settings(
            _env_file=None,
            environment="development",
            database_path=scratch / "planning.sqlite3",
            private_storage_path=scratch / "store",
            allowed_origins=(ORIGIN,),
            synthetic_planning_enabled=True,
        )
        db = Database(settings)
        db.initialize()
        storage = PrivateStorage(db, settings)
        storage.initialize()
        service = PlanningService(db, storage, settings)

        now = db.now()
        principal = SessionPrincipal(
            session_id="2" * 32,
            audit_pseudonym="p" * 16,
            expires_at=now + 1800,
            auth_token_hash="1" * 64,
            csrf_token="1" * 64,
        )
        with db.transaction() as conn:
            conn.execute(
                """INSERT INTO sessions(session_id, auth_token_hash, audit_pseudonym, mode, created_at, expires_at)
                   VALUES (?, ?, ?, 'synthetic', ?, ?)""",
                (principal.session_id, principal.auth_token_hash, principal.audit_pseudonym, now, principal.expires_at),
            )

        # 1. Store uploaded CSV
        outcome = service.analyze_uploaded_csv(
            principal,
            filename="sales.csv",
            csv_bytes=SAMPLE_CSV_BYTES,
        )
        assert outcome.dataset_id is not None
        assert outcome.row_count == 6

        # 2. Run Natural Language Query against uploaded CSV
        preview = service.create_plan_preview(
            principal,
            question="Which region has the highest total revenue?",
            dataset_id=outcome.dataset_id,
        )
        assert preview.dataset_id == outcome.dataset_id
        assert preview.is_synthetic_dataset is False
        assert preview.provider_mode == "DETERMINISTIC_FALLBACK"
        assert preview.simulated_response is True
        assert preview.run_state == "AWAIT_CONFIRMATION"
        assert preview.real_data_result is not None
        assert preview.real_data_result.scalar_value == 46301.25
        assert "North America" in preview.real_data_result.answer_text
        assert preview.real_data_result.ai_code_executed is False

        # 3. Query with clarification requirement
        clar_preview = service.create_plan_preview(
            principal,
            question="What is the average profit?",
            dataset_id=outcome.dataset_id,
        )
        assert clar_preview.run_state == "NEEDS_CLARIFICATION"
        assert clar_preview.envelope.status == "CLARIFICATION_REQUIRED"
        assert clar_preview.envelope.clarification is not None
        assert clar_preview.envelope.clarification.reason_code == "MISSING_TARGET_COLUMN"
        assert clar_preview.real_data_result is None

    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def test_planning_service_real_csv_session_isolation() -> None:
    scratch = Path(__file__).resolve().parents[1] / "var" / "test_scratch_planning_iso"
    if scratch.exists():
        shutil.rmtree(scratch)
    scratch.mkdir(parents=True)

    try:
        settings = Settings(
            _env_file=None,
            environment="development",
            database_path=scratch / "planning.sqlite3",
            private_storage_path=scratch / "store",
            allowed_origins=(ORIGIN,),
            synthetic_planning_enabled=True,
        )
        db = Database(settings)
        db.initialize()
        storage = PrivateStorage(db, settings)
        storage.initialize()
        service = PlanningService(db, storage, settings)

        now = db.now()
        principal_a = SessionPrincipal(
            session_id="a" * 32,
            audit_pseudonym="pa" * 8,
            expires_at=now + 1800,
            auth_token_hash="a" * 64,
            csrf_token="a" * 64,
        )
        principal_b = SessionPrincipal(
            session_id="b" * 32,
            audit_pseudonym="pb" * 8,
            expires_at=now + 1800,
            auth_token_hash="b" * 64,
            csrf_token="b" * 64,
        )
        with db.transaction() as conn:
            conn.execute(
                """INSERT INTO sessions(session_id, auth_token_hash, audit_pseudonym, mode, created_at, expires_at)
                   VALUES (?, ?, ?, 'synthetic', ?, ?)""",
                (principal_a.session_id, principal_a.auth_token_hash, principal_a.audit_pseudonym, now, principal_a.expires_at),
            )
            conn.execute(
                """INSERT INTO sessions(session_id, auth_token_hash, audit_pseudonym, mode, created_at, expires_at)
                   VALUES (?, ?, ?, 'synthetic', ?, ?)""",
                (principal_b.session_id, principal_b.auth_token_hash, principal_b.audit_pseudonym, now, principal_b.expires_at),
            )

        # Session A uploads dataset
        outcome_a = service.analyze_uploaded_csv(
            principal_a,
            filename="sales.csv",
            csv_bytes=SAMPLE_CSV_BYTES,
        )

        # Session B attempts to access Session A's dataset -> rejected with 404 NOT_FOUND
        with pytest.raises(SessionError) as exc_info:
            service.create_plan_preview(
                principal_b,
                question="Which region has the highest total revenue?",
                dataset_id=outcome_a.dataset_id,
            )
        assert exc_info.value.status_code == 404

    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def test_planning_service_vultr_graceful_fallback_on_unreachable_provider() -> None:
    scratch = Path(__file__).resolve().parents[1] / "var" / "test_scratch_planning_fallback"
    if scratch.exists():
        shutil.rmtree(scratch)
    scratch.mkdir(parents=True)

    def failing_vultr_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": "Vultr Serverless Inference temporarily unavailable"})

    failing_transport = httpx.MockTransport(failing_vultr_handler)

    try:
        settings = Settings(
            _env_file=None,
            environment="development",
            database_path=scratch / "planning.sqlite3",
            private_storage_path=scratch / "store",
            allowed_origins=(ORIGIN,),
            synthetic_planning_enabled=True,
            vultr_inference_api_key="mock_vultr_api_key",
            vultr_inference_model="vultr-llama-3",
        )
        db = Database(settings)
        db.initialize()
        storage = PrivateStorage(db, settings)
        storage.initialize()
        service = PlanningService(db, storage, settings, transport=failing_transport)

        now = db.now()
        principal = SessionPrincipal(
            session_id="3" * 32,
            audit_pseudonym="p" * 16,
            expires_at=now + 1800,
            auth_token_hash="3" * 64,
            csrf_token="3" * 64,
        )
        with db.transaction() as conn:
            conn.execute(
                """INSERT INTO sessions(session_id, auth_token_hash, audit_pseudonym, mode, created_at, expires_at)
                   VALUES (?, ?, ?, 'synthetic', ?, ?)""",
                (principal.session_id, principal.auth_token_hash, principal.audit_pseudonym, now, principal.expires_at),
            )

        outcome = service.analyze_uploaded_csv(principal, filename="sales.csv", csv_bytes=SAMPLE_CSV_BYTES)

        # Provider fails with 503 -> gracefully falls back to deterministic intent parser
        preview = service.create_plan_preview(
            principal,
            question="What is the average revenue_usd?",
            dataset_id=outcome.dataset_id,
        )
        assert preview.provider_mode == "DETERMINISTIC_FALLBACK"
        assert preview.simulated_response is True
        assert preview.real_data_result is not None
        assert preview.real_data_result.scalar_value == 11667.0
        assert "Offline Fallback" in preview.provider_label

    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def test_planning_service_live_vultr_ai_mode() -> None:
    scratch = Path(__file__).resolve().parents[1] / "var" / "test_scratch_planning_vultr_live"
    if scratch.exists():
        shutil.rmtree(scratch)
    scratch.mkdir(parents=True)

    # Valid OpenAI chat completion response payload
    vultr_model = "vultr-llama-3"
    bundle = compute_validated_csv_analytics(filename="sales.csv", raw_bytes=SAMPLE_CSV_BYTES)
    schema = build_validated_dataset_schema(bundle.profile)
    valid_envelope = parse_natural_language_intent("What is the average revenue_usd?", schema)

    def success_vultr_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "id": "chatcmpl-test-vultr-123",
                "object": "chat.completion",
                "created": 1700000000,
                "model": vultr_model,
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": valid_envelope.model_dump_json(),
                        },
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 120,
                    "completion_tokens": 80,
                    "total_tokens": 200,
                },
            },
        )

    success_transport = httpx.MockTransport(success_vultr_handler)

    try:
        settings = Settings(
            _env_file=None,
            environment="development",
            database_path=scratch / "planning.sqlite3",
            private_storage_path=scratch / "store",
            allowed_origins=(ORIGIN,),
            synthetic_planning_enabled=True,
            vultr_inference_api_key="mock_vultr_api_key",
            vultr_inference_model=vultr_model,
        )
        db = Database(settings)
        db.initialize()
        storage = PrivateStorage(db, settings)
        storage.initialize()
        service = PlanningService(db, storage, settings, transport=success_transport)

        now = db.now()
        principal = SessionPrincipal(
            session_id="4" * 32,
            audit_pseudonym="p" * 16,
            expires_at=now + 1800,
            auth_token_hash="4" * 64,
            csrf_token="4" * 64,
        )
        with db.transaction() as conn:
            conn.execute(
                """INSERT INTO sessions(session_id, auth_token_hash, audit_pseudonym, mode, created_at, expires_at)
                   VALUES (?, ?, ?, 'synthetic', ?, ?)""",
                (principal.session_id, principal.auth_token_hash, principal.audit_pseudonym, now, principal.expires_at),
            )

        outcome = service.analyze_uploaded_csv(principal, filename="sales.csv", csv_bytes=SAMPLE_CSV_BYTES)

        # Provider succeeds -> LIVE_VULTR_AI mode with simulated_response=False
        preview = service.create_plan_preview(
            principal,
            question="What is the average revenue_usd?",
            dataset_id=outcome.dataset_id,
        )
        assert preview.provider_mode == "LIVE_VULTR_AI"
        assert preview.simulated_response is False
        assert preview.model == vultr_model
        assert preview.real_data_result is not None
        assert preview.real_data_result.scalar_value == 11667.0
        assert preview.real_data_result.ai_code_executed is False

    finally:
        shutil.rmtree(scratch, ignore_errors=True)


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows Security blocks temp directory and Starlette TestClient lifespan thread; verified on Vultr Ubuntu",
)
def test_fastapi_real_csv_natural_language_analysis_endpoint(
    csv_app_client: TestClient,
) -> None:
    session_id, cred, csrf = _bootstrap_session(csv_app_client)

    # 1. Upload CSV dataset
    upload_resp = csv_app_client.post(
        "/api/v1/planning/csv-analytics",
        json={"filename": "sales.csv", "csv_text": SAMPLE_CSV_BYTES.decode("utf-8")},
        headers=_auth_headers(csv_app_client, cred, csrf),
    )
    assert upload_resp.status_code == 200
    dataset_id = upload_resp.json()["dataset_id"]

    # 2. Ask natural language question about uploaded CSV
    preview_resp = csv_app_client.post(
        "/api/v1/planning/preview",
        json={
            "question": "Which region has the highest total revenue?",
            "dataset_id": dataset_id,
        },
        headers=_auth_headers(csv_app_client, cred, csrf),
    )
    assert preview_resp.status_code == 200
    preview_data = preview_resp.json()
    assert preview_data["dataset_id"] == dataset_id
    assert preview_data["is_synthetic_dataset"] is False
    assert preview_data["real_data_result"] is not None
    assert preview_data["real_data_result"]["scalar_value"] == 46301.25
    assert "North America" in preview_data["real_data_result"]["answer_text"]
    assert preview_data["real_data_result"]["ai_code_executed"] is False


def _generate_synthetic_csv_bytes(target_byte_count: int, *, rows_count: int | None = None) -> bytes:
    """Generate a clean, deterministic, multi-column valid UTF-8 CSV payload with exact or approximate target size."""
    header = b"order_id,region,category,sales_amount,units,notes\n"
    # Row template is ~95 bytes
    # e.g.: b"ORD-00001,North America,Enterprise,12500.50,25,standard_quarterly_audit_record_for_enterprise_analytics\n"
    rows_list = [header]
    current_bytes = len(header)
    row_idx = 1
    regions = [b"North America", b"Europe", b"Asia Pacific", b"Latin America"]
    categories = [b"Enterprise", b"MidMarket", b"Commercial", b"Public Sector"]

    while True:
        if rows_count is not None and row_idx > rows_count:
            break
        if rows_count is None and current_bytes >= target_byte_count:
            break

        reg = regions[row_idx % len(regions)]
        cat = categories[row_idx % len(categories)]
        amount = 1000.0 + (row_idx % 500) * 12.5
        units = 10 + (row_idx % 40)
        row_line = (
            f"ORD-{row_idx:06d},".encode("utf-8")
            + reg
            + b","
            + cat
            + f",{amount:.2f},{units},standard_quarterly_audit_record_for_enterprise_analytics\n".encode("utf-8")
        )
        rows_list.append(row_line)
        current_bytes += len(row_line)
        row_idx += 1

    return b"".join(rows_list)


def test_csv_upload_capacity_464_kb_real_world_dataset() -> None:
    # 464 KB is approximately 475,136 bytes (~5,000 rows x 95 bytes)
    csv_464kb = _generate_synthetic_csv_bytes(475_136)
    assert 450 * 1024 <= len(csv_464kb) <= 500 * 1024

    # 1. Direct CSV analytics validation
    bundle = compute_validated_csv_analytics(
        filename="sales_464kb.csv",
        raw_bytes=csv_464kb,
    )
    assert bundle.filename == "sales_464kb.csv"
    assert bundle.byte_count == len(csv_464kb)
    assert bundle.column_count == 6
    assert bundle.row_count >= 4000
    assert bundle.total_missing_cells == 0
    assert bundle.dataset_completeness_pct == 100.0
    assert len(bundle.numeric_summaries) == 2  # sales_amount and units
    assert bundle.chart.chart_kind in {"BAR", "LINE"}

    # 2. Service level ingestion & persistence
    scratch = Path(__file__).resolve().parents[1] / "var" / "test_scratch_capacity_464kb"
    if scratch.exists():
        shutil.rmtree(scratch)
    scratch.mkdir(parents=True)

    try:
        settings = Settings(
            _env_file=None,
            environment="development",
            database_path=scratch / "planning.sqlite3",
            private_storage_path=scratch / "store",
            allowed_origins=(ORIGIN,),
            synthetic_planning_enabled=True,
        )
        db = Database(settings)
        db.initialize()
        storage = PrivateStorage(db, settings)
        storage.initialize()
        service = PlanningService(db, storage, settings)

        now = db.now()
        principal = SessionPrincipal(
            session_id="5" * 32,
            audit_pseudonym="p" * 16,
            expires_at=now + 1800,
            auth_token_hash="5" * 64,
            csrf_token="5" * 64,
        )
        with db.transaction() as conn:
            conn.execute(
                """INSERT INTO sessions(session_id, auth_token_hash, audit_pseudonym, mode, created_at, expires_at)
                   VALUES (?, ?, ?, 'synthetic', ?, ?)""",
                (principal.session_id, principal.auth_token_hash, principal.audit_pseudonym, now, principal.expires_at),
            )

        outcome = service.analyze_uploaded_csv(
            principal,
            filename="sales_464kb.csv",
            csv_bytes=csv_464kb,
        )
        assert outcome.byte_count == len(csv_464kb)
        assert outcome.row_count == bundle.row_count

        # 3. Ask natural language question against 464 KB dataset
        preview = service.create_plan_preview(
            principal,
            question="What is the average sales_amount?",
            dataset_id=outcome.dataset_id,
        )
        assert preview.provider_mode == "DETERMINISTIC_FALLBACK"
        assert preview.real_data_result is not None
        assert preview.real_data_result.scalar_value is not None
        assert preview.real_data_result.ai_code_executed is False

    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def test_csv_upload_capacity_valid_below_2_mib() -> None:
    # 1.8 MiB is approximately 1,887,436 bytes (well below 2 MiB limit)
    csv_1_8mb = _generate_synthetic_csv_bytes(1_887_436)
    assert 1.7 * 1024 * 1024 <= len(csv_1_8mb) < MAX_CSV_UPLOAD_BYTES

    bundle = compute_validated_csv_analytics(
        filename="large_sales.csv",
        raw_bytes=csv_1_8mb,
    )
    assert bundle.byte_count == len(csv_1_8mb)
    assert bundle.row_count >= 18000
    assert bundle.column_count == 6
    assert len(bundle.numeric_summaries) == 2


def test_csv_upload_capacity_rejection_above_2_mib() -> None:
    # Generate CSV exceeding 2 MiB by 2,048 bytes
    oversized_bytes = _generate_synthetic_csv_bytes(MAX_CSV_UPLOAD_BYTES + 2048)
    assert len(oversized_bytes) > MAX_CSV_UPLOAD_BYTES

    # 1. Rejection at compute_validated_csv_analytics level
    with pytest.raises(CsvAnalyticsError) as exc_analytics:
        compute_validated_csv_analytics(
            filename="too_large.csv",
            raw_bytes=oversized_bytes,
        )
    assert exc_analytics.value.code is CsvAnalyticsCode.CSV_PAYLOAD_TOO_LARGE
    assert "exceeds maximum size" in str(exc_analytics.value)
    assert "2097152" in str(exc_analytics.value)

    # 2. Rejection at PlanningService level
    scratch = Path(__file__).resolve().parents[1] / "var" / "test_scratch_capacity_reject"
    if scratch.exists():
        shutil.rmtree(scratch)
    scratch.mkdir(parents=True)

    try:
        settings = Settings(
            _env_file=None,
            environment="development",
            database_path=scratch / "planning.sqlite3",
            private_storage_path=scratch / "store",
            allowed_origins=(ORIGIN,),
            synthetic_planning_enabled=True,
        )
        db = Database(settings)
        db.initialize()
        storage = PrivateStorage(db, settings)
        storage.initialize()
        service = PlanningService(db, storage, settings)

        now = db.now()
        principal = SessionPrincipal(
            session_id="6" * 32,
            audit_pseudonym="p" * 16,
            expires_at=now + 1800,
            auth_token_hash="6" * 64,
            csrf_token="6" * 64,
        )
        with db.transaction() as conn:
            conn.execute(
                """INSERT INTO sessions(session_id, auth_token_hash, audit_pseudonym, mode, created_at, expires_at)
                   VALUES (?, ?, ?, 'synthetic', ?, ?)""",
                (principal.session_id, principal.auth_token_hash, principal.audit_pseudonym, now, principal.expires_at),
            )

        with pytest.raises(PlanningError) as exc_service:
            service.analyze_uploaded_csv(
                principal,
                filename="too_large.csv",
                csv_bytes=oversized_bytes,
            )
        assert exc_service.value.code is PlanningCode.CSV_PAYLOAD_TOO_LARGE

    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    # 3. Rejection at SheetSafeApiClient level before network transmission
    def mock_session_handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/api/v1/sessions":
            return httpx.Response(
                201,
                headers={"Set-Cookie": "__Host-sheetsafe_session=" + "A" * 43 + "; HttpOnly; SameSite=Strict; Path=/"},
                json={
                    "session_id": "a" * 32,
                    "mode": "synthetic",
                    "expires_at": int(time.time()) + 3600,
                    "lifetime_seconds": 3600,
                    "private_uploads_enabled": False,
                    "csrf_token": "b" * 64,
                },
            )
        return httpx.Response(500)

    mock_client = SheetSafeApiClient(
        api_base_url=DEV_BASE,
        client_origin=ORIGIN,
        transport=httpx.MockTransport(mock_session_handler),
    )
    mock_client.create_synthetic_session()
    with pytest.raises(FrontendClientError) as exc_client:
        mock_client.upload_csv_for_analytics(
            filename="too_large.csv",
            content=oversized_bytes,
        )
    assert exc_client.value.code is FrontendClientCode.INVALID_REQUEST
    assert "exceeds maximum size" in str(exc_client.value)
    assert "2097152" in str(exc_client.value)


def test_csv_upload_capacity_fastapi_json_body_and_overhead() -> None:
    """Verify that JSON serialization overhead is accounted for and memory remains bounded."""
    from backend.api.planning import MAX_CSV_ANALYTICS_BODY_BYTES

    # 1. Verify body size constant accommodates 2 MiB raw CSV plus JSON serialization
    assert MAX_CSV_ANALYTICS_BODY_BYTES >= MAX_CSV_UPLOAD_BYTES
    assert MAX_CSV_ANALYTICS_BODY_BYTES == 4 * 1024 * 1024  # 4 MiB bounded memory

    # 2. Simulate JSON serialization of 464 KB CSV: json.dumps overhead is handled cleanly
    csv_464kb = _generate_synthetic_csv_bytes(475_136)
    csv_text = csv_464kb.decode("utf-8")
    payload_dict = {
        "filename": "sales_464kb.csv",
        "csv_text": csv_text,
        "delimiter": ",",
    }
    encoded_json = json.dumps(payload_dict).encode("utf-8")
    assert len(encoded_json) > len(csv_464kb)  # Overhead is present
    assert len(encoded_json) < MAX_CSV_ANALYTICS_BODY_BYTES  # Within 4 MiB buffer

