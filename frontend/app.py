"""SheetSafe AI — Streamlit Dashboard (Step 11A + Step 9B AI Planning Preview).

Connects to the live FastAPI control plane (`/api/v1/health`, `/api/v1/ready`,
`POST /api/v1/sessions`, `DELETE /api/v1/sessions/{session_id}`,
`POST /api/v1/planning/synthetic-dataset`, `POST /api/v1/planning/preview`,
`GET /api/v1/planning/runs`).
Never fabricates analytical results or charts, clearly labels offline mock
planning as DEMO / SIMULATED, distinguishes immediate access revocation from
pending physical cleanup, and never exposes session secrets.
"""

from datetime import datetime, timezone
import os

import streamlit as st

from frontend.api_client import (
    ActiveSessionView,
    BackendStatusSnapshot,
    DEFAULT_API_BASE_URL,
    DEFAULT_CLIENT_ORIGIN,
    FrontendClientError,
    PlanningPreviewView,
    SessionDeletionReceiptView,
    SheetSafeApiClient,
    SyntheticDatasetView,
)


PAGES: tuple[str, ...] = (
    "Dashboard",
    "My Datasets",
    "AI Analysis",
    "Analysis History",
    "Settings / Privacy",
)

SUPPORTED_OPERATIONS: tuple[tuple[str, str], ...] = (
    ("SELECT_COLUMNS", "Project an explicit subset of validated columns (col_001..col_100)"),
    ("FILTER_ROWS", "Declarative row predicate filtering without arbitrary code eval"),
    ("DROP_MISSING", "Remove records containing missing values on required columns"),
    ("GROUP_AGGREGATE", "Group by categorical/date columns with count/sum/mean/median/min/max/std"),
    ("SUMMARY_STATS", "Compute bounded descriptive statistics over numeric columns"),
    ("SORT_VALUES", "Deterministic ascending or descending order on target columns"),
    ("TOP_N", "Bounded top/bottom N selection (1 to 1,000 rows)"),
    ("COMPUTE_RATIO", "Safe two-column numeric ratio with zero-division handling"),
    ("TIME_SERIES_ROLLUP", "Period aggregation over verified date columns"),
    ("CHART_SERIES", "Bounded bar or line chart specification for quarantined rendering"),
)


def _custom_styles() -> str:
    return """
    <style>
        .block-container {
            padding-top: 1.5rem;
            padding-bottom: 2.5rem;
            max-width: 1200px;
        }
        .ss-hero {
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #f8fafc;
            padding: 1.5rem 1.75rem;
            border-radius: 12px;
            border: 1px solid #334155;
            margin-bottom: 1.25rem;
        }
        .ss-hero h1 {
            margin: 0 0 0.35rem 0;
            font-size: 1.75rem;
            font-weight: 700;
            color: #f8fafc;
        }
        .ss-hero p {
            margin: 0;
            color: #cbd5e1;
            font-size: 0.96rem;
        }
        .ss-card {
            background-color: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 10px;
            padding: 1.15rem 1.25rem;
            margin-bottom: 1rem;
            box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
            color: #0f172a;
        }
        .ss-card h4 {
            margin: 0 0 0.45rem 0;
            color: #0f172a;
            font-size: 1.05rem;
        }
        .ss-badge-ok {
            display: inline-block;
            padding: 0.2rem 0.65rem;
            border-radius: 999px;
            font-size: 0.78rem;
            font-weight: 600;
            background-color: #dcfce7;
            color: #166534;
            border: 1px solid #86efac;
        }
        .ss-badge-warn {
            display: inline-block;
            padding: 0.2rem 0.65rem;
            border-radius: 999px;
            font-size: 0.78rem;
            font-weight: 600;
            background-color: #fef9c3;
            color: #854d0e;
            border: 1px solid #fde047;
        }
        .ss-badge-err {
            display: inline-block;
            padding: 0.2rem 0.65rem;
            border-radius: 999px;
            font-size: 0.78rem;
            font-weight: 600;
            background-color: #fee2e2;
            color: #991b1b;
            border: 1px solid #fca5a5;
        }
        .ss-gate-note {
            background-color: #f8fafc;
            border-left: 4px solid #0284c7;
            padding: 0.85rem 1rem;
            border-radius: 6px;
            color: #1e293b;
            font-size: 0.9rem;
            margin-bottom: 0.85rem;
        }
        .ss-sim-banner {
            background-color: #fffbeb;
            border-left: 4px solid #d97706;
            padding: 0.85rem 1rem;
            border-radius: 6px;
            color: #78350f;
            font-size: 0.9rem;
            margin-bottom: 0.85rem;
        }
    </style>
    """


def _init_state() -> None:
    """Initialize per-user Streamlit session state. Never uses global or cached state."""
    if "api_client" not in st.session_state:
        api_url = os.environ.get("SHEETSAFE_UI_API_BASE_URL", DEFAULT_API_BASE_URL)
        origin = os.environ.get("SHEETSAFE_UI_CLIENT_ORIGIN", DEFAULT_CLIENT_ORIGIN)
        st.session_state["api_client"] = SheetSafeApiClient(
            api_base_url=api_url,
            client_origin=origin,
        )
    if "backend_status" not in st.session_state:
        st.session_state["backend_status"] = st.session_state["api_client"].probe_backend_status()
    if "activity_log" not in st.session_state:
        st.session_state["activity_log"] = []
    if "last_deletion_receipt" not in st.session_state:
        st.session_state["last_deletion_receipt"] = None
    if "synthetic_dataset" not in st.session_state:
        st.session_state["synthetic_dataset"] = None
    if "latest_plan_preview" not in st.session_state:
        st.session_state["latest_plan_preview"] = None
    if "planning_error" not in st.session_state:
        st.session_state["planning_error"] = None
    if "ui_notice" not in st.session_state:
        st.session_state["ui_notice"] = None


def _clear_ephemeral_session_views() -> None:
    """Clear session-scoped dataset and planning views upon revocation or expiry."""
    st.session_state["synthetic_dataset"] = None
    st.session_state["latest_plan_preview"] = None
    st.session_state["planning_error"] = None


def _record_activity(event_type: str, detail: str, request_id: str | None = None) -> None:
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    entry = {
        "timestamp_utc": now_str,
        "event": event_type,
        "detail": detail,
        "request_id": request_id or "—",
    }
    history: list[dict[str, str]] = list(st.session_state.get("activity_log", []))
    history.insert(0, entry)
    st.session_state["activity_log"] = history[:25]


def _refresh_backend_status() -> BackendStatusSnapshot:
    client: SheetSafeApiClient = st.session_state["api_client"]
    snapshot = client.probe_backend_status()
    st.session_state["backend_status"] = snapshot
    _record_activity(
        "BACKEND_PROBE",
        f"Status: {snapshot.status_label}",
        snapshot.request_id,
    )
    return snapshot


def _format_utc(timestamp: int) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _status_badge_html(snapshot: BackendStatusSnapshot) -> str:
    if snapshot.status_label == "ONLINE & READY":
        return '<span class="ss-badge-ok">ONLINE &amp; READY</span>'
    if snapshot.status_label == "DEGRADED (NOT READY)":
        return '<span class="ss-badge-warn">DEGRADED (NOT READY)</span>'
    return '<span class="ss-badge-err">OFFLINE</span>'


def _revocation_notice_text(receipt: SessionDeletionReceiptView) -> str:
    return (
        f"Session `{receipt.session_id}` access is immediately revoked "
        f"(`access_revoked={receipt.access_revoked}`, `cancellation_status={receipt.cancellation_status}`). "
        f"Deletion receipt: `{receipt.receipt_id}`. "
        f"Physical storage and metadata cleanup is queued (`cleanup_status={receipt.cleanup_status}`) "
        f"for asynchronous background verification by the retention worker (target window: 5 minutes) — "
        f"physical erasure is not yet complete."
    )


def _render_header(snapshot: BackendStatusSnapshot, session: ActiveSessionView | None) -> None:
    st.markdown(
        """
        <div class="ss-hero">
            <h1>SheetSafe AI — Privacy-First Autonomous Spreadsheet Analyst</h1>
            <p>Team Titan &bull; Vultr Agent Rush Hackathon &bull; Zero-Raw-Row AI Planning &amp; Fail-Closed Execution Architecture</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric(
            label="FastAPI Control Plane",
            value="Online" if snapshot.liveness_ok else "Offline",
            delta="Ready (/api/v1/ready)" if snapshot.readiness_ok else "Not Ready",
            delta_color="normal" if snapshot.readiness_ok else "inverse",
        )
    with col2:
        st.metric(
            label="Active Session",
            value=f"{session.session_id[:8]}..." if session else "None",
            delta="Synthetic Mode" if session else "Unauthenticated",
            delta_color="normal" if session else "off",
        )
    with col3:
        st.metric(
            label="Dataset Upload Gate",
            value="Disabled",
            delta="Awaiting Linux SEC01-10",
            delta_color="off",
        )
    with col4:
        st.metric(
            label="Vultr AI Execution",
            value="Disabled",
            delta="Simulated Planning Only",
            delta_color="off",
        )


def _render_sidebar(snapshot: BackendStatusSnapshot, session: ActiveSessionView | None) -> str:
    with st.sidebar:
        st.markdown("### SheetSafe AI Navigation")
        selected_page = st.radio(
            "Select Workspace",
            options=list(PAGES),
            index=0,
            label_visibility="collapsed",
        )
        st.divider()
        st.markdown("#### Control Plane Connection")
        st.markdown(_status_badge_html(snapshot), unsafe_allow_html=True)
        st.caption(f"Endpoint: `{snapshot.api_base_url}`")
        st.caption(snapshot.detail_message)

        if st.button("Refresh API Status", width="stretch"):
            with st.spinner("Probing /api/v1/health and /api/v1/ready..."):
                _refresh_backend_status()
            st.rerun()

        st.divider()
        st.markdown("#### Session & Data Control")
        if session is not None:
            st.success(f"Session `{session.session_id[:12]}...` active (Synthetic)")
            st.caption(f"Expires: `{_format_utc(session.expires_at)}`")
            if st.button("Delete My Data Now (Revoke)", type="primary", width="stretch"):
                client: SheetSafeApiClient = st.session_state["api_client"]
                try:
                    with st.spinner("Revoking session via DELETE /api/v1/sessions/{id}..."):
                        receipt = client.revoke_active_session()
                    _clear_ephemeral_session_views()
                    st.session_state["last_deletion_receipt"] = receipt
                    _record_activity(
                        "SESSION_REVOKED",
                        (
                            f"Session {receipt.session_id[:8]}... access revoked; "
                            f"receipt {receipt.receipt_id[:8]}... (cleanup_status={receipt.cleanup_status})"
                        ),
                        receipt.request_id,
                    )
                    st.session_state["ui_notice"] = (
                        "success",
                        _revocation_notice_text(receipt),
                    )
                    st.rerun()
                except FrontendClientError as exc:
                    if exc.status_code == 401:
                        _clear_ephemeral_session_views()
                    _record_activity("SESSION_REVOKE_FAILED", exc.safe_message, exc.request_id)
                    st.session_state["ui_notice"] = ("error", f"{exc.backend_code}: {exc.safe_message}")
                    st.rerun()
        else:
            st.info("No active session. Start a synthetic session in Settings / Privacy or Dashboard.")

        st.divider()
        st.caption(
            "Security Posture: `HttpOnly` + `SameSite=Strict` cookies &bull; `X-CSRF-Token` enforced "
            "&bull; Zero raw rows sent to LLM &bull; Offline Mock Planning labeled DEMO/SIMULATED."
        )
    return selected_page


def _render_dashboard_page(snapshot: BackendStatusSnapshot, session: ActiveSessionView | None) -> None:
    st.subheader("System Overview & Security Gate Status")

    left, right = st.columns([3, 2])
    with left:
        st.markdown(
            """
            <div class="ss-card">
                <h4>Operational vs. Gated Subsystems</h4>
                <p>SheetSafe AI enforces a strict fail-closed architecture. Only verified control-plane
                operations and clearly labeled offline simulated planning are active; untrusted file parsing
                and sandboxed code execution remain locked until native Linux security gates pass.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        gate_rows = [
            {
                "Subsystem": "FastAPI Liveness & Readiness (/api/v1/health, /api/v1/ready)",
                "State": "OPERATIONAL" if snapshot.readiness_ok else ("DEGRADED" if snapshot.liveness_ok else "OFFLINE"),
                "Security Guarantee": "Probes SQLite WAL integrity, foreign keys, private storage root, and retention worker.",
            },
            {
                "Subsystem": "Session Bootstrap & Immediate Revocation (/api/v1/sessions)",
                "State": "OPERATIONAL" if snapshot.readiness_ok else "UNAVAILABLE",
                "Security Guarantee": "256-bit credential hashed in DB, HttpOnly/SameSite=Strict cookie, HMAC CSRF token, exact Origin check.",
            },
            {
                "Subsystem": "Step 9B AI Planning Preview (/api/v1/planning/preview)",
                "State": "DEMO / SIMULATED (OFFLINE MOCK)" if snapshot.readiness_ok else "UNAVAILABLE",
                "Security Guarantee": "Uses server-owned synthetic fixture and deterministic HTTPX mock transport; zero live Vultr calls.",
            },
            {
                "Subsystem": "CSV / XLSX Dataset Upload & Isolated Parser Worker",
                "State": "GATED (DISABLED)",
                "Security Guarantee": "Parser image statically built (sha256:8e7cc828...); blocked awaiting native Linux SEC01-SEC10 & AM01-AM04 transport approval.",
            },
            {
                "Subsystem": "Sandboxed Candidate Execution & Independent Validator",
                "State": "GATED (DISABLED)",
                "Security Guarantee": "Requires native Linux AppArmor/seccomp/cgroup v2 host acceptance and verified teardown receipts.",
            },
        ]
        st.dataframe(gate_rows, width="stretch", hide_index=True)

    with right:
        st.markdown(
            """
            <div class="ss-card">
                <h4>Quick Session Actions</h4>
                <p>Bootstrap or revoke an authenticated synthetic session against the connected FastAPI server.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if session is None:
            if st.button(
                "Start Synthetic Session",
                disabled=not snapshot.readiness_ok,
                width="stretch",
                type="primary",
            ):
                client: SheetSafeApiClient = st.session_state["api_client"]
                try:
                    with st.spinner("Calling POST /api/v1/sessions..."):
                        created = client.create_synthetic_session()
                    _clear_ephemeral_session_views()
                    _record_activity(
                        "SESSION_CREATED",
                        f"Created synthetic session {created.session_id[:8]}... (cookie: {created.cookie_name})",
                    )
                    st.session_state["ui_notice"] = (
                        "success",
                        f"Synthetic session `{created.session_id}` created. Private uploads remain disabled.",
                    )
                    st.rerun()
                except FrontendClientError as exc:
                    _record_activity("SESSION_CREATE_FAILED", exc.safe_message, exc.request_id)
                    st.session_state["ui_notice"] = (
                        "error",
                        f"Session creation failed ({exc.backend_code}): {exc.safe_message}",
                    )
                    st.rerun()
            if not snapshot.readiness_ok:
                st.caption("Session creation requires the FastAPI backend to be ONLINE & READY.")
        else:
            st.markdown(
                f"""
                - **Session ID**: `{session.session_id}`
                - **Mode**: `{session.mode}`
                - **Private Uploads Enabled**: `{session.private_uploads_enabled}`
                - **Cookie Name**: `{session.cookie_name}` (`HttpOnly=True`, `SameSite=Strict`)
                - **Expires At**: `{_format_utc(session.expires_at)}`
                """
            )

        receipt: SessionDeletionReceiptView | None = st.session_state.get("last_deletion_receipt")
        if receipt is not None:
            st.markdown("##### Latest Deletion Receipt (Access Revoked; Cleanup Queued)")
            st.code(
                f"receipt_id:          {receipt.receipt_id}\n"
                f"session_id:          {receipt.session_id}\n"
                f"access_revoked:      {receipt.access_revoked} (Immediate)\n"
                f"cancellation_status: {receipt.cancellation_status}\n"
                f"cleanup_status:      {receipt.cleanup_status} (Queued for retention worker; not yet physically erased)",
                language="yaml",
            )

    st.divider()
    st.subheader("Recent Control-Plane Activity (Current UI Session)")
    activity_log: list[dict[str, str]] = st.session_state.get("activity_log", [])
    if not activity_log:
        st.info("No control-plane actions recorded in this view yet.")
    else:
        st.dataframe(activity_log, width="stretch", hide_index=True)


def _render_datasets_page(session: ActiveSessionView | None) -> None:
    st.subheader("My Datasets & Isolated Ingestion Workspace")

    st.markdown(
        """
        <div class="ss-gate-note">
            <strong>Security Gate Notice (Real User Uploads Disabled):</strong> Real CSV/XLSX upload submission and
            parser container dispatch are disabled in this milestone. Spreadsheet parsing is strictly forbidden inside
            the FastAPI or Streamlit process and requires the isolated <code>sheetsafe-parser</code> container on an
            accepted native Linux host.
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_upload, col_limits = st.columns([3, 2])
    with col_upload:
        st.markdown("#### Upload & Parsing Configuration (Gated)")
        selected_type = st.selectbox(
            "Declared File Format",
            options=["csv — UTF-8 Delimited Text (.csv)", "xlsx — Transitional OOXML Workbook (.xlsx)"],
            index=0,
        )
        is_xlsx = selected_type.startswith("xlsx")

        st.file_uploader(
            "Select CSV or XLSX Spreadsheet (Submission Gated)",
            type=["csv", "xlsx"],
            disabled=True,
            help="File uploads are disabled until native Linux sandbox acceptance (SEC01-SEC10) and PRD transport amendments (AM01-AM04) pass.",
        )

        if is_xlsx:
            st.text_input(
                "Required Explicit Worksheet Name (<= 31 chars)",
                value="",
                max_chars=31,
                placeholder="e.g., Q4_Financials",
                disabled=True,
                help="XLSX ingestion requires an explicit single worksheet name; macros, external links, and active formula evaluation are rejected.",
            )
        else:
            st.selectbox(
                "CSV Delimiter Selection",
                options=["Auto-detect unambiguous (, ; or tab)", "Comma (,)", "Semicolon (;)", "Tab (\\t)"],
                index=0,
                disabled=True,
                help="Ambiguous CSV headers enter NEEDS_CLARIFICATION until an explicit delimiter is chosen.",
            )

        st.button(
            "Submit Dataset for Isolated Profiling (Disabled by Gate)",
            disabled=True,
            width="stretch",
        )

    with col_limits:
        st.markdown("#### Enforced Ingestion & Archive Limits")
        limits_table = [
            {"Control": "Allowed Formats", "Limit": "CSV (strict UTF-8), XLSX (OOXML)"},
            {"Control": "Rejected Formats", "Limit": ".xls, .xlsb, .xlsm, macros, encrypted files"},
            {"Control": "Max Original Upload Size", "Limit": "20 MiB"},
            {"Control": "Max Normalized / Expanded Size", "Limit": "100 MiB (<= 100:1 ZIP ratio, <= 1,000 entries)"},
            {"Control": "Max Tabular Dimensions", "Limit": "100,000 data rows x 100 columns"},
            {"Control": "Max Non-Empty Cells", "Limit": "2,000,000 cells (including header)"},
            {"Control": "Max XLSX Worksheets", "Limit": "<= 10 sheets (1 explicit target sheet)"},
            {"Control": "Parser Sandbox Budget", "Limit": "1 vCPU, 10s CPU, 20s wall, 1 GiB RAM, network=none"},
        ]
        st.dataframe(limits_table, width="stretch", hide_index=True)

    st.divider()
    st.markdown("#### Active Session Datasets & Synthetic Demonstration Fixture")
    if session is None:
        st.info("No active session. Start a synthetic session to view session-scoped dataset state.")
    else:
        syn_ds: SyntheticDatasetView | None = st.session_state.get("synthetic_dataset")
        if syn_ds is None:
            st.info(
                f"Session `{session.session_id[:12]}...` has **0 user datasets** (`private_uploads_enabled=False`). "
                "You can provision the server-owned synthetic demonstration dataset in the **AI Analysis** tab "
                "when `SHEETSAFE_SYNTHETIC_PLANNING_ENABLED=true`."
            )
        else:
            st.warning(
                f"**{syn_ds.fixture_label}** (`dataset_id={syn_ds.dataset_id}`, "
                f"`is_synthetic_fixture={syn_ds.is_synthetic_fixture}`, `state={syn_ds.state}`). "
                "This is a server-owned offline development fixture, not an uploaded user file."
            )
            cols_rows = [
                {
                    "column_id": col.column_id,
                    "name": col.name,
                    "inferred_type": col.inferred_type,
                    "missing_count": col.missing_count,
                }
                for col in syn_ds.dataset_schema.columns
            ]
            st.dataframe(cols_rows, width="stretch", hide_index=True)


def _render_analysis_page(session: ActiveSessionView | None) -> None:
    st.subheader("AI Analysis Planning Workspace (Step 9B Offline Simulated Workflow)")

    st.markdown(
        """
        <div class="ss-sim-banner">
            <strong>DEMO / SIMULATED PLANNING MODE:</strong> This workspace connects to FastAPI
            <code>POST /api/v1/planning/preview</code> using a server-owned synthetic demonstration dataset and
            a deterministic in-memory HTTPX mock provider (<code>provider_mode = SIMULATED_MOCK</code>).
            <strong>No live Vultr API calls are made, no generated Python code is executed, and no analytical
            results or charts are fabricated.</strong>
        </div>
        """,
        unsafe_allow_html=True,
    )

    client: SheetSafeApiClient = st.session_state["api_client"]
    syn_ds: SyntheticDatasetView | None = st.session_state.get("synthetic_dataset")
    latest_preview: PlanningPreviewView | None = st.session_state.get("latest_plan_preview")
    planning_error: str | None = st.session_state.get("planning_error")

    col_q, col_schema = st.columns([3, 2])
    with col_q:
        st.markdown("#### 1. Select Demonstration Dataset & Enter Analysis Question")
        st.text_input(
            "Selected Dataset Source",
            value=(
                f"{syn_ds.fixture_label} [{syn_ds.dataset_id[:8]}...]"
                if syn_ds is not None
                else "DEMO / SYNTHETIC FIXTURE — Quarterly Regional Revenue & Headcount (Server-Owned)"
            ),
            disabled=True,
        )

        if session is None:
            st.info("Start a synthetic session on the Dashboard or Settings / Privacy page to enable planning preview.")
        else:
            if st.button("Load / Verify Synthetic Demo Dataset Schema", width="stretch"):
                try:
                    with st.spinner("Provisioning synthetic demo dataset via POST /api/v1/planning/synthetic-dataset..."):
                        loaded_ds = client.bootstrap_synthetic_dataset()
                    st.session_state["synthetic_dataset"] = loaded_ds
                    st.session_state["planning_error"] = None
                    _record_activity(
                        "SYNTHETIC_DATASET_READY",
                        f"Dataset {loaded_ds.dataset_id[:8]}... schema={loaded_ds.dataset_schema.schema_sha256[:12]}...",
                        loaded_ds.request_id,
                    )
                    st.rerun()
                except FrontendClientError as exc:
                    if exc.status_code == 401:
                        _clear_ephemeral_session_views()
                    st.session_state["planning_error"] = f"{exc.backend_code}: {exc.safe_message}"
                    _record_activity("SYNTHETIC_DATASET_FAILED", exc.safe_message, exc.request_id)
                    st.rerun()

        question_input = st.text_area(
            "Enter an analysis question (3 to 500 characters; treated strictly as untrusted data)",
            value="What is total revenue_usd grouped by department, sorted highest to lowest?",
            max_chars=500,
            height=105,
            help=(
                "Questions are checked against prompt-injection overrides, filesystem paths, "
                "inline PII (emails/SSNs/cards), and forbidden runtime capabilities before dispatch."
            ),
        )

        plan_btn_clicked = st.button(
            "Generate Simulated AI Analysis Plan (DEMO / SIMULATED)",
            disabled=session is None,
            width="stretch",
            type="primary",
        )
        if plan_btn_clicked and session is not None:
            try:
                with st.spinner("Calling POST /api/v1/planning/preview (Simulated Mock Transport)..."):
                    target_ds_id = syn_ds.dataset_id if syn_ds is not None else None
                    preview_outcome = client.create_planning_preview(
                        question_input,
                        dataset_id=target_ds_id,
                    )
                st.session_state["latest_plan_preview"] = preview_outcome
                st.session_state["planning_error"] = None
                if syn_ds is None:
                    st.session_state["synthetic_dataset"] = SyntheticDatasetView(
                        dataset_id=preview_outcome.dataset_id,
                        session_id=preview_outcome.session_id,
                        fixture_id="synthetic_quarterly_revenue_v1",
                        fixture_label=(
                            "DEMO / SYNTHETIC FIXTURE — Quarterly Regional Revenue & Headcount "
                            "(Server-Owned Offline Dataset)"
                        ),
                        dataset_schema=preview_outcome.dataset_schema,
                        request_id=preview_outcome.request_id,
                    )
                _record_activity(
                    "PLAN_PREVIEW_CREATED",
                    (
                        f"Run {preview_outcome.run_id[:8]}... state={preview_outcome.run_state} "
                        f"mode={preview_outcome.provider_mode}"
                    ),
                    preview_outcome.request_id,
                )
                st.rerun()
            except FrontendClientError as exc:
                if exc.status_code == 401:
                    _clear_ephemeral_session_views()
                st.session_state["planning_error"] = f"{exc.backend_code}: {exc.safe_message}"
                _record_activity("PLAN_PREVIEW_FAILED", f"{exc.backend_code}: {exc.safe_message}", exc.request_id)
                st.rerun()

        st.button(
            "Execute Generated Python in Sandbox (Disabled — Execution Gate Locked)",
            disabled=True,
            width="stretch",
        )

    with col_schema:
        st.markdown("#### 2. Validated Schema Metadata (`ValidatedDatasetSchema.v1`)")
        active_schema = (
            latest_preview.dataset_schema
            if latest_preview is not None
            else syn_ds.dataset_schema
            if syn_ds is not None
            else None
        )
        if active_schema is None:
            st.info(
                "Load the synthetic demonstration dataset or submit a planning preview to inspect "
                "the validated `ValidatedDatasetSchema` (column IDs, vetted names, inferred types, "
                "and missing counts — zero raw cells or preview rows)."
            )
        else:
            st.caption(
                f"Rows: `{active_schema.row_count}` &bull; Columns: `{active_schema.column_count}` "
                f"&bull; Schema SHA-256: `{active_schema.schema_sha256[:16]}...`"
            )
            schema_table = [
                {
                    "Column ID": col.column_id,
                    "Column Name": col.name,
                    "Inferred Type": col.inferred_type,
                    "Missing Count": col.missing_count,
                }
                for col in active_schema.columns
            ]
            st.dataframe(schema_table, width="stretch", hide_index=True)
            st.caption(
                "Strictly Excluded from Outbound Payload: Raw CSV/XLSX bytes, preview rows, cell values, "
                "worksheet names, storage paths, session tokens, and API credentials."
            )

    if planning_error is not None:
        st.error(f"Planning Request Rejected — {planning_error}")

    st.divider()
    tab_plan, tab_ops, tab_validation = st.tabs([
        "Simulated AI Plan & Clarification Output",
        "Allowlisted Declarative Operations",
        "Sandbox & Independent Validation Gates",
    ])

    with tab_plan:
        if latest_preview is None:
            st.info(
                "No active `AIAnalysisPlan` preview in this view yet. Start a synthetic session and click "
                "**Generate Simulated AI Analysis Plan (DEMO / SIMULATED)** above."
            )
        else:
            st.warning(
                f"**{latest_preview.provider_label}** &bull; "
                f"`provider_mode={latest_preview.provider_mode}` &bull; "
                f"`simulated_response={latest_preview.simulated_response}` &bull; "
                f"`execution_enabled={latest_preview.execution_enabled}` (No Code Executed)"
            )
            m1, m2, m3, m4 = st.columns(4)
            with m1:
                st.metric("Persisted Run State", latest_preview.run_state)
            with m2:
                st.metric("Envelope Status", latest_preview.envelope.status)
            with m3:
                st.metric("Provider Mode", latest_preview.provider_mode)
            with m4:
                st.metric(
                    "Expected Result Type",
                    (
                        latest_preview.envelope.plan.expected_result_type
                        if latest_preview.envelope.plan is not None
                        else "CLARIFICATION"
                    ),
                )

            st.markdown(
                f"- **Run ID**: `{latest_preview.run_id}`  \n"
                f"- **Dataset ID**: `{latest_preview.dataset_id}` (`is_synthetic_dataset={latest_preview.is_synthetic_dataset}`)  \n"
                f"- **Simulated Model ID**: `{latest_preview.model}`  \n"
                f"- **Validated Question**: `{latest_preview.question}`  \n"
                f"- **Plan SHA-256**: `{latest_preview.plan_sha256 or 'N/A (Clarification Required)'}`"
            )

            if latest_preview.envelope.status == "PLAN_READY" and latest_preview.envelope.plan is not None:
                plan = latest_preview.envelope.plan
                st.markdown(f"##### Plan Intent Summary (DEMO / SIMULATED)\n> {plan.intent_summary}")

                st.markdown("##### Required Columns (`RequiredColumnRef`)")
                req_cols_rows = [
                    {
                        "Column ID": rc.column_id,
                        "Column Name": rc.name,
                        "Expected Type": rc.expected_type,
                    }
                    for rc in plan.required_columns
                ]
                st.dataframe(req_cols_rows, width="stretch", hide_index=True)

                st.markdown("##### Proposed Declarative Operations (`ProposedOperation`)")
                op_rows = [
                    {
                        "Step": op.step_number,
                        "Operation": op.operation,
                        "Target Columns": ", ".join(op.target_columns),
                        "Group By": ", ".join(op.group_by_columns) if op.group_by_columns else "—",
                        "Aggregation": op.aggregation or "—",
                        "Sort": op.sort_direction or "—",
                        "Limit": str(op.limit_rows) if op.limit_rows is not None else "—",
                        "Rationale": op.rationale,
                    }
                    for op in plan.operations
                ]
                st.dataframe(op_rows, width="stretch", hide_index=True)

            elif (
                latest_preview.envelope.status == "CLARIFICATION_REQUIRED"
                and latest_preview.envelope.clarification is not None
            ):
                clar = latest_preview.envelope.clarification
                st.info(
                    f"**Clarification Required (`{clar.reason_code}`)** — {clar.clarification_prompt}"
                )
                if clar.candidate_columns:
                    st.caption(f"Candidate Columns: `{', '.join(clar.candidate_columns)}`")

    with tab_ops:
        ops_table = [
            {"Operation": op_code, "Permitted Semantics": desc}
            for op_code, desc in SUPPORTED_OPERATIONS
        ]
        st.dataframe(ops_table, width="stretch", hide_index=True)

    with tab_validation:
        st.markdown(
            """
            1. **Plan & Column Binding**: Every `RequiredColumnRef` in `AIAnalysisPlan` must match an existing `col_XXX`, exact column name, and compatible `inferred_type`.
            2. **Candidate Code Policy (`GeneratedCodeCandidate.v1`)**: `execution_authorized` defaults to `False`. Only allowlisted analytical imports (`pandas`, `numpy`, `matplotlib`, `math`, `statistics`, `decimal`, `datetime`, `json`, `csv`) are permitted; `os`, `sys`, `subprocess`, `socket`, `open()`, `eval()`, and `docker.sock` are rejected.
            3. **Isolated Execution & Self-Healing**: Capped at $\\le 3$ attempts within a 180s total run budget (20s wall / 10s CPU per candidate attempt, 1 GiB RAM, 32 PIDs).
            4. **Independent Validator**: Quarantined artifacts (`<= 10` files, `<= 10 MiB` each, `<= 20 MiB` total) must pass a fresh validator container check and verified runtime teardown before atomic publication.
            """
        )


def _render_history_page(session: ActiveSessionView | None) -> None:
    st.subheader("Analysis History & Persisted Run State")

    client: SheetSafeApiClient = st.session_state["api_client"]
    if session is None:
        st.info("No active session. Start a synthetic session to inspect session-owned SQLite planning runs.")
    else:
        try:
            runs = client.list_planning_runs()
        except FrontendClientError as exc:
            if exc.status_code == 401:
                _clear_ephemeral_session_views()
            st.error(f"Could not fetch session runs ({exc.backend_code}): {exc.safe_message}")
            runs = ()

        if not runs:
            st.info(
                f"Session `{session.session_id[:12]}...` currently has **0 persisted runs** in SQLite."
            )
        else:
            st.warning(
                f"Showing **{len(runs)}** persisted SQLite planning run(s) for session `{session.session_id[:12]}...` "
                "(`provider_mode=SIMULATED_MOCK`, `execution_enabled=False`)."
            )
            runs_table = [
                {
                    "Run ID": r.run_id[:12] + "...",
                    "State": r.state,
                    "Provider Mode": r.provider_mode,
                    "Result / Clarification": r.expected_result_type or r.clarification_reason or "—",
                    "Question": r.question,
                    "Summary": r.intent_summary or "—",
                    "Updated (UTC)": _format_utc(r.updated_at),
                }
                for r in runs
            ]
            st.dataframe(runs_table, width="stretch", hide_index=True)

    st.divider()
    st.markdown("#### Current UI Session Control-Plane Events")
    activity_log: list[dict[str, str]] = st.session_state.get("activity_log", [])
    if not activity_log:
        st.caption("No events recorded yet.")
    else:
        st.dataframe(activity_log, width="stretch", hide_index=True)


def _render_privacy_settings_page(snapshot: BackendStatusSnapshot, session: ActiveSessionView | None) -> None:
    st.subheader("Settings, Session Protocol & Privacy Controls")

    col_priv, col_sess = st.columns([3, 2])
    with col_priv:
        st.markdown(
            """
            <div class="ss-card">
                <h4>Data Storage, Immediate Revocation &amp; Asynchronous Cleanup Policy</h4>
                <ul>
                    <li><strong>Current Mode:</strong> Synthetic-only foundation (<code>private_uploads_enabled = False</code>).</li>
                    <li><strong>Session Lifetime:</strong> Maximum 1 hour (3,600 seconds), non-sliding server-enforced expiry.</li>
                    <li><strong>Immediate Access Revocation vs. Physical Cleanup:</strong> Clicking <em>Delete My Data Now</em> issues <code>DELETE /api/v1/sessions/{session_id}</code> with the session's <code>HttpOnly</code> cookie, exact <code>Origin</code>, and HMAC-bound <code>X-CSRF-Token</code>. Access is revoked <strong>immediately</strong> inside the SQLite writer transaction (<code>access_revoked = True</code>) and active runs are marked for cancellation (<code>cancellation_status = requested</code>).</li>
                    <li><strong>Honest Cleanup Status Reporting:</strong> The deletion receipt returns <code>cleanup_status = not_started</code> because physical storage and metadata purging are performed asynchronously by the background <code>LifecycleCoordinator</code> retention worker (target window: 5 minutes). The UI never claims physical erasure has completed while cleanup is pending.</li>
                    <li><strong>Audit Separation:</strong> Content-free security audit events retain only SHA-256 digests, byte/token counts, and pseudonymous IDs for 24 hours — never filenames, cell values, questions, or credentials.</li>
                </ul>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown(
            """
            <div class="ss-card">
                <h4>Browser &amp; Server-Side Streamlit Cookie Architecture</h4>
                <p>FastAPI issues session credentials exclusively via <code>HttpOnly; SameSite=Strict</code> cookies
                (<code>__Host-sheetsafe_session</code> over HTTPS, or <code>sheetsafe_dev_session</code> in explicit
                loopback development mode). Because Streamlit renders on the server and makes server-to-server HTTPX
                requests to FastAPI on behalf of each browser tab, each Streamlit user session holds its own isolated
                <code>SheetSafeApiClient</code> instance in <code>st.session_state</code> (never in global variables or
                <code>@st.cache_resource</code>). The client stores the raw cookie and <code>csrf_token</code> inside
                non-printable <code>SecretStr(repr=False)</code> fields and never exposes them to page HTML, logs,
                or exception messages.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_sess:
        st.markdown("#### Connection & Session Management")
        client: SheetSafeApiClient = st.session_state["api_client"]
        st.text_input("FastAPI Base URL", value=client.api_base_url, disabled=True)
        st.text_input("Configured Client Origin", value=client.client_origin, disabled=True)

        if session is None:
            st.warning("No active session is currently established.")
            if st.button(
                "Bootstrap New Synthetic Session",
                disabled=not snapshot.readiness_ok,
                width="stretch",
                type="primary",
            ):
                try:
                    with st.spinner("Creating synthetic session..."):
                        created = client.create_synthetic_session()
                    _clear_ephemeral_session_views()
                    _record_activity(
                        "SESSION_CREATED",
                        f"Created synthetic session {created.session_id[:8]}...",
                    )
                    st.session_state["ui_notice"] = (
                        "success",
                        f"Created synthetic session `{created.session_id}`.",
                    )
                    st.rerun()
                except FrontendClientError as exc:
                    _record_activity("SESSION_CREATE_FAILED", exc.safe_message, exc.request_id)
                    st.session_state["ui_notice"] = (
                        "error",
                        f"Could not create session ({exc.backend_code}): {exc.safe_message}",
                    )
                    st.rerun()
            if not snapshot.readiness_ok:
                st.caption("Backend must be ONLINE & READY to create a session.")
        else:
            st.success(f"Active Session ID: `{session.session_id}`")
            st.markdown(
                f"""
                - **Cookie**: `{session.cookie_name}`
                - **HttpOnly / SameSite**: `True` / `strict`
                - **Expires**: `{_format_utc(session.expires_at)}`
                """
            )
            if st.button(
                "Revoke Session & Queue Deletion",
                type="primary",
                width="stretch",
            ):
                try:
                    with st.spinner("Sending authenticated DELETE /api/v1/sessions/{id}..."):
                        receipt = client.revoke_active_session()
                    _clear_ephemeral_session_views()
                    st.session_state["last_deletion_receipt"] = receipt
                    _record_activity(
                        "SESSION_REVOKED",
                        (
                            f"Revoked session {receipt.session_id[:8]}... "
                            f"(receipt {receipt.receipt_id[:8]}..., cleanup_status={receipt.cleanup_status})"
                        ),
                        receipt.request_id,
                    )
                    st.session_state["ui_notice"] = (
                        "success",
                        _revocation_notice_text(receipt),
                    )
                    st.rerun()
                except FrontendClientError as exc:
                    if exc.status_code == 401:
                        _clear_ephemeral_session_views()
                    _record_activity("SESSION_REVOKE_FAILED", exc.safe_message, exc.request_id)
                    st.session_state["ui_notice"] = ("error", f"{exc.backend_code}: {exc.safe_message}")
                    st.rerun()


def render_app() -> None:
    st.set_page_config(
        page_title="SheetSafe AI — Privacy-First Spreadsheet Analyst",
        page_icon=":shield:",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    st.markdown(_custom_styles(), unsafe_allow_html=True)
    _init_state()

    client: SheetSafeApiClient = st.session_state["api_client"]
    snapshot: BackendStatusSnapshot = st.session_state["backend_status"]
    session = client.active_session

    notice = st.session_state.get("ui_notice")
    if notice is not None:
        kind, text = notice
        if kind == "success":
            st.success(text)
        elif kind == "error":
            st.error(text)
        else:
            st.info(text)
        st.session_state["ui_notice"] = None

    _render_header(snapshot, session)
    selected_page = _render_sidebar(snapshot, session)

    if selected_page == "Dashboard":
        _render_dashboard_page(snapshot, session)
    elif selected_page == "My Datasets":
        _render_datasets_page(session)
    elif selected_page == "AI Analysis":
        _render_analysis_page(session)
    elif selected_page == "Analysis History":
        _render_history_page(session)
    elif selected_page == "Settings / Privacy":
        _render_privacy_settings_page(snapshot, session)


if __name__ == "__main__":
    render_app()
