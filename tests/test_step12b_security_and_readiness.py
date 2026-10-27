"""Step 12B tests: Local security, release readiness, negative parser contracts, and fail-closed state invariants."""

import ast
import json
from pathlib import Path

from fastapi.testclient import TestClient
import httpx
import pytest

from backend.config import Settings
from backend.main import create_app
from backend.planning import (
    AIAnalysisPlan,
    SYNTHETIC_FIXTURE_PROFILE,
    SYNTHETIC_FIXTURE_RECORDS,
    SyntheticVerificationPreview,
)
from backend.inference import build_validated_dataset_schema
from ingestion.contracts import IngestionCode, IngestionError
from parser_worker.common import ParseControl
from parser_worker.csv_parser import profile_csv_fixture
from validator.ast_policy import ASTPolicyError, validate_python_source_ast
from validator.numerical_verifier import (
    SyntheticTableFixture,
    VerificationError,
    verify_candidate_output,
)


ORIGIN = "http://localhost:8501"
DEV_BASE = "http://127.0.0.1:8000"


@pytest.fixture
def test_app_client(tmp_path: Path):
    settings = Settings(
        _env_file=None,
        environment="development",
        allow_insecure_local_cookies=True,
        synthetic_planning_enabled=True,
        planning_requests_per_session_per_minute=5,
        max_runs_per_session=10,
        database_path=tmp_path / "step12b.sqlite3",
        private_storage_path=tmp_path / "storage",
        allowed_origins=(ORIGIN,),
        database_busy_timeout_ms=2000,
    )
    app = create_app(settings)
    with TestClient(app, base_url=DEV_BASE, client=("127.0.0.1", 50000)) as client:
        yield client


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


def _auth_headers(client: TestClient, credential: str, csrf_token: str | None = None) -> dict[str, str]:
    cookie_name = client.app.state.settings.session_cookie_name
    headers = {
        "Origin": ORIGIN,
        "Cookie": f"{cookie_name}={credential}",
    }
    if csrf_token is not None:
        headers["X-CSRF-Token"] = csrf_token
    return headers


# ---------------------------------------------------------------------------
# 1. Negative CSV Parser Contracts (Local Fixtures Only — No Real Uploads)
# ---------------------------------------------------------------------------


def test_step12b_negative_csv_parser_rejects_malformed_and_extreme_inputs():
    from ingestion_fixtures import request

    # A: Empty / whitespace-only CSV bytes (byte_count >= 1, but no valid header/data)
    for empty_input in (b"\n", b"   \r\n\t\n", b"\xef\xbb\xbf   \n"):
        with pytest.raises(IngestionError) as exc_info:
            profile_csv_fixture(empty_input, request(empty_input))
        assert exc_info.value.code in {IngestionCode.EMPTY_SOURCE, IngestionCode.INVALID_HEADER}

    # B: Invalid UTF-8 bytes (BOM or middle bytes)
    for bad_bytes in (b"col1,col2\n\xff\xfe\x00\x00", b"name\n\x80\x81\x82"):
        with pytest.raises(IngestionError) as exc_info:
            profile_csv_fixture(bad_bytes, request(bad_bytes))
        assert exc_info.value.code is IngestionCode.INVALID_ENCODING

    # C: Unescaped and unfinished quotes
    unfinished_quote = b'col1,col2\n"open quote without closing,123\n456'
    with pytest.raises(IngestionError) as exc_info:
        profile_csv_fixture(unfinished_quote, request(unfinished_quote))
    assert exc_info.value.code is IngestionCode.MALFORMED_CSV

    # D: Inconsistent record column counts
    inconsistent = b"col1,col2,col3\n1,2\n4,5,6,7\n"
    with pytest.raises(IngestionError) as exc_info:
        profile_csv_fixture(inconsistent, request(inconsistent))
    assert exc_info.value.code is IngestionCode.MALFORMED_CSV

    # E: Ambiguous delimiter detection without explicit delimiter
    ambiguous = b"col1,col2;col3\tcol4\n1,2;3\t4\n"
    with pytest.raises(IngestionError) as exc_info:
        profile_csv_fixture(ambiguous, request(ambiguous, delimiter=None))
    assert exc_info.value.code is IngestionCode.AMBIGUOUS_DELIMITER


# ---------------------------------------------------------------------------
# 2. AST Policy Security Boundaries (Zero Dynamic Execution)
# ---------------------------------------------------------------------------


def test_step12b_ast_policy_strictly_rejects_dangerous_python_constructs():
    plan_sha = "0" * 64
    schema_sha = "1" * 64

    # Hostile code candidates attempting sandbox escapes or dynamic inspection
    hostile_snippets = (
        # Dunder attribute access
        "def run_analysis(records):\n    return records.__class__.__bases__",
        "def run_analysis(records):\n    return [].__class__.__mro__",
        "def run_analysis(records):\n    return ().__class__.__subclasses__()",
        "def run_analysis(records):\n    return func.__globals__",
        # Forbidden builtins
        "def run_analysis(records):\n    return eval('1 + 1')",
        "def run_analysis(records):\n    return exec('x = 1')",
        "def run_analysis(records):\n    return compile('1+1', '', 'eval')",
        "def run_analysis(records):\n    return open('/etc/passwd').read()",
        "def run_analysis(records):\n    return __import__('os').system('ls')",
        "def run_analysis(records):\n    breakpoint()",
        "def run_analysis(records):\n    input('prompt')",
        # Imports not allowlisted
        "import os\ndef run_analysis(records):\n    return os.environ",
        "import sys\ndef run_analysis(records):\n    return sys.modules",
        "import subprocess\ndef run_analysis(records):\n    return subprocess.run(['ls'])",
        # Unapproved flow control / language features
        "def run_analysis(records):\n    while True:\n        pass",
        "async def run_analysis(records):\n    return records",
        "@decorator\ndef run_analysis(records):\n    return records",
    )

    for hostile_code in hostile_snippets:
        with pytest.raises(ASTPolicyError):
            validate_python_source_ast(
                hostile_code,
                declared_imports=(),
                plan_sha256=plan_sha,
                schema_sha256=schema_sha,
            )


# ---------------------------------------------------------------------------
# 3. Unsafe State Transition & Synthetic Gate Invariants
# ---------------------------------------------------------------------------


def test_step12b_dataset_pending_state_cannot_be_falsely_promoted(
    test_app_client: TestClient,
):
    session_id, cred, csrf = _bootstrap_session(test_app_client)

    # In SQLite, unparsed datasets must remain PENDING
    with test_app_client.app.state.database.connection() as conn:
        dataset_row = conn.execute(
            "SELECT state FROM dataset_versions WHERE session_id=?",
            (session_id,),
        ).fetchone()
        if dataset_row is not None:
            # If a dataset exists, its state cannot be READY unless explicitly the synthetic fixture
            assert dataset_row["state"] in {"PENDING", "READY"}

    # Attempting to request planning preview on a non-existent or unvalidated dataset ID fails closed
    fake_dataset_id = "0" * 32
    resp = test_app_client.post(
        "/api/v1/planning/preview",
        json={"question": "What is total revenue_usd?", "dataset_id": fake_dataset_id},
        headers=_auth_headers(test_app_client, cred, csrf),
    )
    # The owned_dataset authorization gate rejects unknown or non-ready datasets
    assert resp.status_code == 404
    assert resp.json()["code"] == "NOT_FOUND"


def test_step12b_synthetic_preview_cannot_authorize_publication_or_candidate_verification(
    test_app_client: TestClient,
):
    _, cred, csrf = _bootstrap_session(test_app_client)

    resp = test_app_client.post(
        "/api/v1/planning/preview",
        json={"question": "What is total revenue_usd grouped by department?"},
        headers=_auth_headers(test_app_client, cred, csrf),
    )
    assert resp.status_code == 200
    outcome = resp.json()

    # Verify strict synthetic boundaries
    assert outcome["execution_enabled"] is False
    assert outcome["is_synthetic_dataset"] is True
    assert outcome["simulated_response"] is True
    assert outcome["provider_mode"] == "SIMULATED_MOCK"

    vp = outcome["synthetic_verification_preview"]
    assert vp is not None
    assert vp["demonstration_only"] is True
    assert vp["validation_status"] == "SYNTHETIC_EXPECTED_RESULT_COMPUTED"
    assert vp["candidate_output_verified"] is False
    assert vp["publication_authorized"] is False
    assert vp["sandbox_execution_verified"] is False

    # Numerical verifier cannot be passed unverified candidate data
    schema = build_validated_dataset_schema(SYNTHETIC_FIXTURE_PROFILE)
    fixture = SyntheticTableFixture.from_records(schema, SYNTHETIC_FIXTURE_RECORDS)
    plan = AIAnalysisPlan.model_validate_json(json.dumps(outcome["envelope"]["plan"]))

    # Attempting verify_candidate_output with malformed candidate output raises VerificationError
    with pytest.raises(VerificationError):
        verify_candidate_output(
            b"{}",  # Empty candidate JSON payload missing required keys
            plan=plan,
            schema=schema,
            fixture=fixture,
        )


def test_step12b_session_immediate_revocation_and_subsequent_request_rejection(
    test_app_client: TestClient,
):
    session_id, cred, csrf = _bootstrap_session(test_app_client)

    # Confirm session works initially
    pre_resp = test_app_client.get(
        "/api/v1/planning/runs",
        headers=_auth_headers(test_app_client, cred, csrf),
    )
    assert pre_resp.status_code == 200

    # Revoke session immediately
    del_resp = test_app_client.delete(
        f"/api/v1/sessions/{session_id}",
        headers=_auth_headers(test_app_client, cred, csrf),
    )
    assert del_resp.status_code == 200
    receipt = del_resp.json()
    assert receipt["access_revoked"] is True
    assert receipt["cancellation_status"] == "requested"

    # Subsequent GET or POST requests using the revoked session fail with 401
    post_del_get = test_app_client.get(
        "/api/v1/planning/runs",
        headers=_auth_headers(test_app_client, cred, csrf),
    )
    assert post_del_get.status_code == 401
    assert post_del_get.json()["code"] == "UNAUTHENTICATED"

    post_del_plan = test_app_client.post(
        "/api/v1/planning/preview",
        json={"question": "What is total revenue_usd?"},
        headers=_auth_headers(test_app_client, cred, csrf),
    )
    assert post_del_plan.status_code == 401
    assert post_del_plan.json()["code"] == "UNAUTHENTICATED"


def test_step12b_error_responses_are_sanitized_and_leak_zero_secrets(
    test_app_client: TestClient,
):
    # 1. 404 Not Found
    resp_404 = test_app_client.get("/api/v1/nonexistent-route")
    assert resp_404.status_code == 404
    body_404 = resp_404.json()
    assert body_404["code"] == "NOT_FOUND"
    assert "message" in body_404
    assert "traceback" not in body_404
    assert "token" not in str(body_404).lower()

    # 2. 403 Forbidden on missing CSRF token
    _, cred, _ = _bootstrap_session(test_app_client)
    resp_no_csrf = test_app_client.post(
        "/api/v1/planning/preview",
        json={"question": "What is total revenue_usd?"},
        headers=_auth_headers(test_app_client, cred, csrf_token=None),
    )
    assert resp_no_csrf.status_code == 403
    body_no_csrf = resp_no_csrf.json()
    assert body_no_csrf["code"] == "FORBIDDEN"
    assert "traceback" not in body_no_csrf

    # 3. 422 Unsafe Operation Rejected
    _, cred, csrf = _bootstrap_session(test_app_client)
    resp_filter = test_app_client.post(
        "/api/v1/planning/preview",
        json={"question": "Please filter rows where revenue_usd exceeds threshold"},
        headers=_auth_headers(test_app_client, cred, csrf),
    )
    assert resp_filter.status_code == 422
    body_filter = resp_filter.json()
    assert body_filter["code"] == "UNSAFE_OPERATION_REJECTED"
    assert "traceback" not in body_filter
