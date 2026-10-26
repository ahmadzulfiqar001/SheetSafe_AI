"""SheetSafe AI — Streamlit Dashboard (Step 11A).

Connects to the live FastAPI control plane (`/api/v1/health`, `/api/v1/ready`,
`POST /api/v1/sessions`, `DELETE /api/v1/sessions/{session_id}`).
Never fabricates analysis outputs, never imports backend internals (SQLite,
storage, parser_worker, runner), and never displays secret credentials.
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
    SessionDeletionReceiptView,
    SheetSafeApiClient,
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
    </style>
    """


def _init_state() -> None:
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
    if "ui_notice" not in st.session_state:
        st.session_state["ui_notice"] = None


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
            delta="Zero Live Cloud Spend",
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
                    st.session_state["last_deletion_receipt"] = receipt
                    _record_activity(
                        "SESSION_REVOKED",
                        f"Session {receipt.session_id[:8]}... revoked; receipt {receipt.receipt_id[:8]}...",
                        receipt.request_id,
                    )
                    st.session_state["ui_notice"] = (
                        "success",
                        f"Session access immediately revoked. Deletion receipt: `{receipt.receipt_id}`.",
                    )
                    st.rerun()
                except FrontendClientError as exc:
                    _record_activity("SESSION_REVOKE_FAILED", exc.safe_message, exc.request_id)
                    st.session_state["ui_notice"] = ("error", f"{exc.code.value}: {exc.safe_message}")
                    st.rerun()
        else:
            st.info("No active session. Start a synthetic session in Settings / Privacy or Dashboard.")

        st.divider()
        st.caption("Security Posture: `HttpOnly` + `SameSite=Strict` cookies &bull; `X-CSRF-Token` enforced &bull; Zero raw rows sent to LLM.")
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
                operations are active; untrusted file parsing and sandboxed code execution remain locked until
                native Linux security gates pass.</p>
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
                "Subsystem": "CSV / XLSX Dataset Upload & Isolated Parser Worker",
                "State": "GATED (DISABLED)",
                "Security Guarantee": "Parser image statically built (sha256:8e7cc828...); blocked awaiting native Linux SEC01-SEC10 & AM01-AM04 transport approval.",
            },
            {
                "Subsystem": "Vultr Serverless Inference Planning Client (Step 9A)",
                "State": "FOUNDATION VERIFIED (OFFLINE)",
                "Security Guarantee": "Schema-only projection excludes preview rows/cells/PII; live network calls disabled until API key & dataset are active.",
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
                        f"Session creation failed ({exc.code.value}): {exc.safe_message}",
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
            st.markdown("##### Latest Deletion Receipt")
            st.code(
                f"receipt_id:          {receipt.receipt_id}\n"
                f"session_id:          {receipt.session_id}\n"
                f"access_revoked:      {receipt.access_revoked}\n"
                f"cancellation_status: {receipt.cancellation_status}\n"
                f"cleanup_status:      {receipt.cleanup_status}",
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
            <strong>Security Gate Notice (Uploads Disabled):</strong> Real CSV/XLSX upload submission and parser
            dispatch are disabled in this milestone. Spreadsheet parsing is strictly forbidden inside the FastAPI or
            Streamlit process and requires the isolated <code>sheetsafe-parser</code> container on an accepted native
            Linux host.
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_upload, col_limits = st.columns([3, 2])
    with col_upload:
        st.markdown("#### Upload & Parsing Configuration")
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
    st.markdown("#### Active Session Datasets & Clarification States")
    if session is None:
        st.info("No active session. Start a synthetic session to view session-scoped dataset state.")
    else:
        st.info(
            f"Session `{session.session_id[:12]}...` has **0 datasets** (`private_uploads_enabled=False`). "
            "No fake or placeholder dataset profiles are displayed."
        )

    with st.expander("View Ingestion Lifecycle & Clarification States (Reference Contract)"):
        st.markdown(
            """
            - **`PENDING`**: Opaque original bytes sealed in `PrivateStorage` with verified SHA-256; awaiting isolated parser claim.
            - **`PROFILING`**: Dedicated `sheetsafe-parser` container running under UID `10001:10001` with `ReadonlyRootfs=True`.
            - **`NEEDS_CLARIFICATION`**: Triggered on `AMBIGUOUS_DELIMITER`, `DUPLICATE_COLUMNS`, or `FORMULA_VALUES_MISSING` (requires values-only export).
            - **`READY`**: Validated `DatasetProfile` committed; eligible for privacy-safe AI schema conversion.
            - **`REJECTED` / `FAILED`**: Deterministic ingestion code (`MALFORMED_CSV`, `UNSAFE_ARCHIVE`, `ROW_LIMIT`, `TIMED_OUT`, etc.) with zero partial profile leakage.
            """
        )


def _render_analysis_page(session: ActiveSessionView | None) -> None:
    st.subheader("AI Analysis Planning & Sandboxed Execution Workspace")

    st.markdown(
        """
        <div class="ss-gate-note">
            <strong>Execution Gate Notice:</strong> Live AI analysis planning and candidate Python execution require
            (1) an authorized <code>READY</code> dataset in the current session, (2) server-side
            <code>SHEETSAFE_VULTR_INFERENCE_API_KEY</code> and <code>SHEETSAFE_VULTR_INFERENCE_MODEL</code>, and
            (3) native Linux runner acceptance. No fabricated charts or synthetic AI answers are generated here.
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_q, col_contract = st.columns([3, 2])
    with col_q:
        st.markdown("#### Natural-Language Analysis Question")
        question_input = st.text_area(
            "Enter an analysis question (3 to 500 characters; treated strictly as untrusted data)",
            value="",
            max_chars=500,
            height=110,
            placeholder="e.g., What is the total quarterly revenue grouped by department, sorted highest to lowest?",
        )
        st.caption(
            "Questions are checked locally and server-side against prompt-injection overrides, "
            "filesystem paths, inline PII (emails/SSNs/cards), and forbidden runtime capabilities before dispatch."
        )
        st.button(
            "Generate AI Analysis Plan (Requires Ready Dataset & Vultr Config)",
            disabled=True,
            width="stretch",
            type="primary",
        )
        if question_input.strip():
            st.info(
                "Question captured in UI preview only. Submission is disabled because no `READY` dataset is attached to this session."
            )

    with col_contract:
        st.markdown("#### Outbound AI Privacy Envelope (`ValidatedDatasetSchema.v1`)")
        st.markdown(
            """
            When enabled, **only** these fields leave the backend toward `https://api.vultrinference.com/v1`:
            - `row_count` & `column_count`
            - `schema_sha256` (64-char hex digest)
            - Per column: `column_id` (`col_001`..), vetted `name`, `inferred_type`, `missing_count`
            - `untrusted_user_question` (inside a fenced JSON data literal)

            **Strictly Excluded:** Raw CSV/XLSX bytes, preview rows, cell values, worksheet names, storage paths, session tokens, and API keys.
            """
        )

    st.divider()
    tab_plan, tab_ops, tab_validation = st.tabs([
        "Analysis Plan & Result Contract",
        "Allowlisted Declarative Operations",
        "Sandbox & Independent Validation Gates",
    ])

    with tab_plan:
        st.info(
            "No active `AIAnalysisPlan` or execution artifacts exist for this session. "
            "Results appear here only after `VALIDATION_PASSED` and `CLEANUP_CONFIRMED`."
        )
        st.markdown(
            """
            **Supported `ExpectedResultType` Targets:**
            `SCALAR_METRIC` &bull; `SUMMARY_TABLE` &bull; `GROUPED_TABLE` &bull; `RANKED_TABLE` &bull;
            `TIME_SERIES_TABLE` &bull; `BAR_CHART` &bull; `LINE_CHART`
            """
        )

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
    st.subheader("Analysis History & Control-Plane Audit Log")

    if session is None:
        st.info("No active session. No analysis runs have been executed.")
    else:
        st.info(
            f"Session `{session.session_id[:12]}...` has **0 analysis runs**. "
            "Runs are listed only when backed by real SQLite `runs` and `attempts` records."
        )

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
                <h4>Data Storage &amp; Retention Policy</h4>
                <ul>
                    <li><strong>Current Mode:</strong> Synthetic-only foundation (<code>private_uploads_enabled = False</code>).</li>
                    <li><strong>Session Lifetime:</strong> Maximum 1 hour (3,600 seconds), non-sliding server-enforced expiry.</li>
                    <li><strong>Immediate Revocation:</strong> Clicking <em>Delete My Data Now</em> issues <code>DELETE /api/v1/sessions/{session_id}</code> with the session's <code>HttpOnly</code> cookie, exact <code>Origin</code>, and HMAC-bound <code>X-CSRF-Token</code>.</li>
                    <li><strong>Deletion Target:</strong> Access is revoked immediately inside the SQLite writer transaction, active runs are marked for cancellation, and the retention worker purges registered storage/metadata within the 5-minute target window.</li>
                    <li><strong>Audit Separation:</strong> Content-free security audit events retain only SHA-256 digests, byte/token counts, and pseudonymous IDs for 24 hours — never filenames, cell values, questions, or credentials.</li>
                </ul>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown(
            """
            <div class="ss-card">
                <h4>Browser &amp; Streamlit Session Security Note</h4>
                <p>FastAPI issues session credentials exclusively via <code>HttpOnly; SameSite=Strict</code> cookies
                (<code>__Host-sheetsafe_session</code> over HTTPS, or <code>sheetsafe_dev_session</code> in explicit
                loopback development mode). The typed <code>SheetSafeApiClient</code> keeps the cookie and
                <code>csrf_token</code> sealed inside non-printable <code>SecretStr</code> fields and never exposes
                them to UI widgets, query strings, logs, or exception messages.</p>
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
                        f"Could not create session ({exc.code.value}): {exc.safe_message}",
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
                "Revoke Session & Request Immediate Deletion",
                type="primary",
                width="stretch",
            ):
                try:
                    with st.spinner("Sending authenticated DELETE /api/v1/sessions/{id}..."):
                        receipt = client.revoke_active_session()
                    st.session_state["last_deletion_receipt"] = receipt
                    _record_activity(
                        "SESSION_REVOKED",
                        f"Revoked session {receipt.session_id[:8]}... (receipt {receipt.receipt_id[:8]}...)",
                        receipt.request_id,
                    )
                    st.session_state["ui_notice"] = (
                        "success",
                        f"Session `{receipt.session_id}` revoked. Receipt ID: `{receipt.receipt_id}`.",
                    )
                    st.rerun()
                except FrontendClientError as exc:
                    _record_activity("SESSION_REVOKE_FAILED", exc.safe_message, exc.request_id)
                    st.session_state["ui_notice"] = ("error", f"{exc.code.value}: {exc.safe_message}")
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
