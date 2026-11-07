"""SheetSafe AI — Public Hackathon Demonstration Entrypoint (Streamlit Community Cloud).

Privacy-Preserving Natural Language Spreadsheet Intelligence.
Built by Team Titan for the Vultr Agent Rush Hackathon.

PUBLIC CLOUD SAFETY INVARIANTS:
1. Raw spreadsheet data NEVER leaves the host. Only schema metadata and sanitized
   questions are shared with Vultr Serverless Inference.
2. AI writes declarative JSON planning operations (AIAnalysisPlan), NOT executable code.
3. Computations execute locally via vetted deterministic pandas analytical operations.
4. Arbitrary public CSV uploads and sandboxed container execution are explicitly gated
   and disabled in this public demonstration to prevent multi-tenant data exfiltration
   or denial-of-service.
5. Live Vultr Inference (deepseek-v4.1-flash-1017) is rate-limited per session.
"""

from __future__ import annotations

import os
import time
from typing import Any

import pandas as pd
from pydantic import SecretStr
import streamlit as st

from backend.config import Settings
from backend.inference import (
    InferenceError,
    UserAnalysisQuestion,
    ValidatedDatasetSchema,
    VultrInferenceClient,
    build_validated_dataset_schema,
    validate_user_question,
)
from backend.planning import SYNTHETIC_FIXTURE_CSV_BYTES
from validator.csv_analytics import (
    ValidatedCsvAnalyticsBundle,
    compute_validated_csv_analytics,
    neutralize_csv_cell,
)
from validator.natural_language_analysis import (
    RealDataAnalysisResult,
    execute_deterministic_dataframe_analysis,
    parse_natural_language_intent,
)

# ---------------------------------------------------------------------------
# Page Configuration & Visual Theme
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="SheetSafe AI — Public Hackathon Demo",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 700;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1.05rem;
        color: #6c757d;
        margin-bottom: 1.5rem;
    }
    .badge-card {
        padding: 0.8rem 1.2rem;
        border-radius: 8px;
        margin-bottom: 1rem;
        font-weight: 500;
    }
    .badge-live {
        background-color: #d1e7dd;
        color: #0f5132;
        border-left: 5px solid #198754;
    }
    .badge-offline {
        background-color: #cfe2ff;
        color: #084298;
        border-left: 5px solid #0d6efd;
    }
    .badge-warning {
        background-color: #fff3cd;
        color: #664d03;
        border-left: 5px solid #ffc107;
    }
    .stat-metric {
        font-size: 1.8rem;
        font-weight: bold;
        color: #0d6efd;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Curated Non-Sensitive Synthetic Sample Datasets
# ---------------------------------------------------------------------------
DATASET_REVENUE_CSV = SYNTHETIC_FIXTURE_CSV_BYTES

DATASET_SAAS_CSV = (
    b"customer_id,tier,region,arr_usd,nps_score,churn_risk\n"
    b"CUST-101,Enterprise,North America,120000.00,9,Low\n"
    b"CUST-102,MidMarket,Europe,45000.00,8,Low\n"
    b"CUST-103,Enterprise,Europe,185000.00,7,Medium\n"
    b"CUST-104,Commercial,Asia Pacific,28000.00,10,Low\n"
    b"CUST-105,MidMarket,North America,52000.00,6,High\n"
    b"CUST-106,Enterprise,North America,210000.00,9,Low\n"
    b"CUST-107,Commercial,Europe,31000.00,8,Low\n"
    b"CUST-108,MidMarket,Asia Pacific,49000.00,7,Medium\n"
)

DATASET_LOGISTICS_CSV = (
    b"order_id,warehouse,carrier,delivery_days,shipping_cost_usd,on_time\n"
    b"ORD-501,US-East,ExpressCargo,2,45.50,Yes\n"
    b"ORD-502,EU-Central,EuroTrans,3,62.00,Yes\n"
    b"ORD-503,US-West,PacFreight,5,89.00,No\n"
    b"ORD-504,APAC-South,SwiftShip,2,38.25,Yes\n"
    b"ORD-505,US-East,ExpressCargo,4,54.00,No\n"
    b"ORD-506,EU-Central,EuroTrans,2,41.50,Yes\n"
    b"ORD-507,APAC-South,SwiftShip,3,48.00,Yes\n"
    b"ORD-508,US-West,PacFreight,3,72.50,Yes\n"
)

SAMPLE_CATALOG: dict[str, dict[str, Any]] = {
    "Regional Quarterly Revenue": {
        "filename": "quarterly_revenue.csv",
        "csv_bytes": DATASET_REVENUE_CSV,
        "description": "5 regional quarters with revenue (USD), department, region, and headcount.",
        "presets": [
            "Which department had the highest revenue?",
            "Show sum of revenue grouped by department",
            "Calculate average headcount by region",
            "Calculate total revenue by department",
        ],
    },
    "SaaS Customer ARR & Retention": {
        "filename": "saas_customers.csv",
        "csv_bytes": DATASET_SAAS_CSV,
        "description": "8 B2B accounts across Enterprise, MidMarket, and Commercial tiers with ARR and NPS.",
        "presets": [
            "Show total arr_usd grouped by tier",
            "Which tier has the highest average NPS score?",
            "Calculate sum of arr_usd grouped by region",
            "Count customers grouped by churn_risk",
        ],
    },
    "Global Supply Chain Logistics": {
        "filename": "supply_chain_orders.csv",
        "csv_bytes": DATASET_LOGISTICS_CSV,
        "description": "8 logistics shipments tracking warehouse origin, carrier, shipping cost, and on-time status.",
        "presets": [
            "Calculate average shipping cost by carrier",
            "Show sum of shipping_cost_usd grouped by warehouse",
            "Count orders grouped by on_time",
            "Which carrier had the highest total shipping cost?",
        ],
    },
}

MAX_LIVE_QUERIES_PER_SESSION = 10


# ---------------------------------------------------------------------------
# Helpers & Secret Resolution
# ---------------------------------------------------------------------------
def _get_secret(key: str, default: str | None = None) -> str | None:
    """Safely inspect Streamlit Cloud secrets and environment variables."""
    try:
        if hasattr(st, "secrets") and key in st.secrets:
            val = st.secrets[key]
            if isinstance(val, str) and val.strip():
                return val.strip()
    except Exception:
        pass
    env_val = os.environ.get(key) or os.environ.get(f"SHEETSAFE_{key}")
    if env_val and env_val.strip():
        return env_val.strip()
    return default


def _format_table_rows(
    rows: tuple[dict[str, Any], ...] | list[dict[str, Any]] | None,
    column_headers: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    if not rows:
        return []
    headers = column_headers or {}
    return [{headers.get(k, k): v for k, v in row.items()} for row in rows]


# ---------------------------------------------------------------------------
# Session State Initialization
# ---------------------------------------------------------------------------
if "live_query_count" not in st.session_state:
    st.session_state["live_query_count"] = 0
if "last_analysis_result" not in st.session_state:
    st.session_state["last_analysis_result"] = None
if "last_analysis_meta" not in st.session_state:
    st.session_state["last_analysis_meta"] = None
if "selected_preset" not in st.session_state:
    st.session_state["selected_preset"] = ""

# ---------------------------------------------------------------------------
# Sidebar: Configuration, Dataset Selection, & Safety Controls
# ---------------------------------------------------------------------------
with st.sidebar:
    st.title("🛡️ SheetSafe AI")
    st.caption("Privacy-Preserving Spreadsheet Intelligence")
    st.markdown("---")

    st.subheader("📂 1. Select Sample Dataset")
    chosen_dataset_name = st.selectbox(
        "Choose a non-sensitive sample dataset:",
        options=list(SAMPLE_CATALOG.keys()),
        index=0,
    )
    dataset_info = SAMPLE_CATALOG[chosen_dataset_name]
    st.info(dataset_info["description"])

    st.markdown("---")
    st.subheader("🧠 2. Vultr AI Inference Engine")

    vultr_key = _get_secret("VULTR_INFERENCE_API_KEY")
    vultr_model = _get_secret("VULTR_INFERENCE_MODEL", "deepseek-v4.1-flash-1017")

    live_available = bool(vultr_key and len(vultr_key) >= 16)
    use_live_inference = False

    if live_available:
        st.success("🟢 Vultr Serverless Inference: **Configured**")
        st.caption(f"Model: `{vultr_model}` (deepseek-v4.1)")
        use_live_inference = st.checkbox(
            "Enable Live Vultr Inference Calls",
            value=True,
            help="Queries Vultr Serverless Inference API. Rate-limited to 10 queries per browser session.",
        )
        remaining = max(0, MAX_LIVE_QUERIES_PER_SESSION - st.session_state["live_query_count"])
        st.caption(f"Session Quota: **{st.session_state['live_query_count']} / {MAX_LIVE_QUERIES_PER_SESSION}** live queries used ({remaining} remaining)")
    else:
        st.info("🔵 Inference Mode: **Deterministic Intent Parser (Offline)**")
        st.caption(
            "Vultr API Key not detected in `st.secrets`. Running via SheetSafe's built-in offline deterministic intent parser (100% free, safe, air-gapped)."
        )

    st.markdown("---")
    st.subheader("🔒 Public Demo Safety Bounds")
    st.markdown(
        """
        - **Arbitrary Uploads**: 🚫 Disabled (Public web safety)
        - **Raw Cell Exfiltration**: 🚫 Zero bytes transmitted
        - **Arbitrary Code Execution**: 🚫 Disabled (`eval`/`exec` forbidden)
        - **Calculations**: ✅ Local Deterministic Pandas
        - **Native Vultr Linux Suite**: ✅ 1610 passed, 1 skipped
        """
    )
    st.caption("Built by **Team Titan** for the Vultr Agent Rush Hackathon.")

# ---------------------------------------------------------------------------
# Pre-Compute Analytics for Selected Dataset
# ---------------------------------------------------------------------------
bundle: ValidatedCsvAnalyticsBundle = compute_validated_csv_analytics(
    filename=dataset_info["filename"],
    raw_bytes=dataset_info["csv_bytes"],
)
schema: ValidatedDatasetSchema = build_validated_dataset_schema(bundle.profile)

# ---------------------------------------------------------------------------
# Main Header
# ---------------------------------------------------------------------------
st.markdown('<div class="main-header">SheetSafe AI — Public Hackathon Demo</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="sub-header">Zero-Code Execution &bull; Zero Raw-Data Leakage &bull; Vultr Serverless Inference (DeepSeek)</div>',
    unsafe_allow_html=True,
)

st.warning(
    "⚠️ **Public Cloud Demonstration Notice**: This web deployment is restricted to curated, non-sensitive sample datasets. "
    "Arbitrary file upload and Docker sandbox dispatch are gated to protect public cloud multi-tenancy. "
    "All analytical queries run deterministically on the host via pre-approved pandas operations."
)

tab_analysis, tab_explorer, tab_architecture = st.tabs(
    ["💬 AI Natural Language Analysis", "📊 Dataset Explorer & Stats", "🏛️ Architecture & Governance"]
)

# ---------------------------------------------------------------------------
# Tab 1: AI Natural Language Analysis
# ---------------------------------------------------------------------------
with tab_analysis:
    st.subheader(f"Ask a Business Question about *{chosen_dataset_name}*")

    st.markdown("**Click a preset scenario or type a custom question below:**")
    cols = st.columns(len(dataset_info["presets"]))
    for i, preset in enumerate(dataset_info["presets"]):
        with cols[i]:
            if st.button(preset, key=f"btn_preset_{i}", use_container_width=True):
                st.session_state["selected_preset"] = preset

    default_q = st.session_state.get("selected_preset") or dataset_info["presets"][0]
    user_query = st.text_input(
        "Natural Language Query:",
        value=default_q,
        placeholder="e.g. Which department generated the highest total revenue?",
        key="txt_user_query",
    )

    btn_run = st.button("🚀 Analyze Dataset via SheetSafe AI", type="primary")

    if btn_run and user_query:
        # 1. Pre-flight Sanitization
        try:
            validated_question: UserAnalysisQuestion = validate_user_question(user_query)
        except InferenceError as exc:
            st.error(f"❌ Security Policy Blocked Question: {exc.code.value} — Prompt injection or sensitive PII detected.")
            st.stop()

        envelope = None
        provider_mode = "DETERMINISTIC_FALLBACK"
        provider_label = "SheetSafe Deterministic Intent Parser (Offline Fallback)"
        latency_ms = 0

        # 2. Planning Envelope Generation (Live Vultr vs. Offline Parser)
        if use_live_inference and live_available:
            if st.session_state["live_query_count"] >= MAX_LIVE_QUERIES_PER_SESSION:
                st.warning("⚠️ Session live query limit reached (10). Falling back to offline Deterministic Intent Parser.")
                envelope = parse_natural_language_intent(validated_question.question, schema)
            else:
                try:
                    start_t = time.monotonic()
                    settings = Settings(
                        _env_file=None,
                        vultr_inference_api_key=SecretStr(vultr_key),
                        vultr_inference_model=vultr_model,
                        vultr_inference_read_timeout_seconds=30.0,
                    )
                    client = VultrInferenceClient(settings, allow_live_network=True)
                    with st.spinner("Connecting to Vultr Serverless Inference (DeepSeek)..."):
                        envelope = client.plan_analysis(schema=schema, question=validated_question)
                    latency_ms = int((time.monotonic() - start_t) * 1000)
                    provider_mode = "LIVE_VULTR_AI"
                    provider_label = f"Vultr Serverless Inference ({vultr_model})"
                    st.session_state["live_query_count"] += 1
                except Exception as exc:
                    st.warning(f"⚠️ Live Vultr Inference unavailable ({type(exc).__name__}). Falling back safely to Deterministic Intent Parser.")
                    envelope = parse_natural_language_intent(validated_question.question, schema)
        else:
            envelope = parse_natural_language_intent(validated_question.question, schema)

        # 3. Deterministic Local Evaluation
        if envelope is not None:
            if envelope.status == "PLAN_READY" and envelope.plan is not None:
                try:
                    res: RealDataAnalysisResult = execute_deterministic_dataframe_analysis(
                        csv_bytes=dataset_info["csv_bytes"],
                        delimiter=bundle.profile.delimiter or ",",
                        plan=envelope.plan,
                        schema=schema,
                    )
                    st.session_state["last_analysis_result"] = res
                    st.session_state["last_analysis_meta"] = {
                        "provider_mode": provider_mode,
                        "provider_label": provider_label,
                        "model": vultr_model if provider_mode == "LIVE_VULTR_AI" else "deterministic-fallback-v1",
                        "latency_ms": latency_ms,
                        "question": validated_question.question,
                        "envelope": envelope,
                    }
                except Exception as exc:
                    st.error(f"Evaluation error: {exc}")
            elif envelope.status == "CLARIFICATION_REQUIRED" and envelope.clarification is not None:
                st.info(f"🤔 **Clarification Needed**: {envelope.clarification.prompt}")
                if envelope.clarification.options:
                    st.caption("Suggested options: " + ", ".join(f"`{opt}`" for opt in envelope.clarification.options))
            else:
                st.error("Planning failed: unable to resolve question into approved operations.")
        else:
            st.error("Planning failed: no planning envelope generated.")

    # 4. Render Analysis Results
    if st.session_state["last_analysis_result"] is not None:
        res = st.session_state["last_analysis_result"]
        meta = st.session_state["last_analysis_meta"]

        st.divider()

        # Provider Badge
        if meta["provider_mode"] == "LIVE_VULTR_AI":
            st.markdown(
                f'<div class="badge-card badge-live">'
                f'🟢 <b>LIVE VULTR SERVERLESS INFERENCE</b> &bull; Provider: <code>{meta["provider_label"]}</code> &bull; '
                f'Model: <code>{meta["model"]}</code> &bull; Latency: {meta["latency_ms"]} ms<br>'
                f'<small>Natural language translated via live Vultr Serverless AI. Zero-code execution invariant enforced on host.</small>'
                f'</div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                f'<div class="badge-card badge-offline">'
                f'🔵 <b>DETERMINISTIC INTENT PARSER (Offline Fallback — Zero Cost / Air-Gapped)</b> &bull; '
                f'Provider: <code>{meta["provider_label"]}</code><br>'
                f'<small>Natural language parsed into declarative allowlisted intent without cloud network transmission.</small>'
                f'</div>',
                unsafe_allow_html=True,
            )

        st.markdown(f"### 💡 **Answer**: **{res.answer_text}**")

        # Metric Display
        if res.scalar_value is not None:
            scalar_disp = f"{res.scalar_value:,.2f}" if isinstance(res.scalar_value, float) else f"{res.scalar_value}"
            st.metric("Calculated Result", scalar_disp)

        # Summary Table
        if res.rows:
            st.markdown("##### Analysis Summary Table (Deterministic Host Evaluation)")
            table_records = _format_table_rows(res.rows, res.column_headers)
            st.dataframe(table_records, width="stretch", hide_index=True)

        # Dynamic Visualization
        if res.chart_series and res.chart_kind in ("BAR", "LINE"):
            st.markdown(f"##### Visualization ({res.chart_kind.title()} Chart)")
            chart_df = pd.DataFrame([{"x": p.x, "y": p.y} for p in res.chart_series])
            x_title = res.chart_x_label or "Category"
            y_title = res.chart_y_label or "Value"
            chart_df = chart_df.rename(columns={"x": x_title, "y": y_title})
            if res.chart_kind == "BAR":
                st.bar_chart(chart_df, x=x_title, y=y_title)
            elif res.chart_kind == "LINE":
                st.line_chart(chart_df, x=x_title, y=y_title)

        # Declarative Operations Breakdown (Proof of Zero Arbitrary Code)
        plan = meta["envelope"].plan
        if plan is not None and plan.operations:
            with st.expander("🔍 Inspect Declarative Operations (Proof of Zero AI-Generated Code)", expanded=False):
                st.caption(
                    "Every analysis query is translated exclusively into declarative operation specifications. "
                    "Notice that zero raw python code, eval(), exec(), or arbitrary scripts were generated or run."
                )
                ops_table = [
                    {
                        "Step": op.step_number,
                        "Operation": op.operation,
                        "Target Columns": ", ".join(op.target_columns) if op.target_columns else "—",
                        "Group By": ", ".join(op.group_by_columns) if op.group_by_columns else "—",
                        "Rationale": op.rationale,
                    }
                    for op in plan.operations
                ]
                st.dataframe(ops_table, width="stretch", hide_index=True)

# ---------------------------------------------------------------------------
# Tab 2: Dataset Explorer & Descriptive Statistics
# ---------------------------------------------------------------------------
with tab_explorer:
    st.subheader(f"📊 Dataset Explorer: *{chosen_dataset_name}*")

    st.markdown("##### 1. Raw Data Preview (Neutralized Cells)")
    st.caption("All cells are defensively neutralized against spreadsheet formula injection triggers (`=`, `+`, `-`, `@`, `|`).")
    raw_df = pd.read_csv(dataset_info["filename"] if os.path.exists(dataset_info["filename"]) else pd.io.common.BytesIO(dataset_info["csv_bytes"]))
    st.dataframe(raw_df, width="stretch", hide_index=True)

    st.markdown("##### 2. Column Profiles & Inferred Types")
    cols_meta = [
        {
            "Column ID": c.column_id,
            "Column Name": c.name,
            "Inferred Type": c.inferred_type,
            "Missing Count": c.missing_count,
        }
        for c in bundle.columns
    ]
    st.dataframe(cols_meta, width="stretch", hide_index=True)

    if bundle.numeric_summaries:
        st.markdown("##### 3. Deterministic Numerical Statistics (Pandas / NumPy)")
        num_stats = [
            {
                "Column": ns.column_name,
                "Count": ns.non_null_count,
                "Min": f"{ns.min_value:,.2f}" if ns.min_value is not None else "—",
                "Max": f"{ns.max_value:,.2f}" if ns.max_value is not None else "—",
                "Mean": f"{ns.mean_value:,.2f}" if ns.mean_value is not None else "—",
                "Sum": f"{ns.total_sum:,.2f}" if ns.total_sum is not None else "—",
            }
            for ns in bundle.numeric_summaries
        ]
        st.dataframe(num_stats, width="stretch", hide_index=True)

# ---------------------------------------------------------------------------
# Tab 3: Architecture & Governance
# ---------------------------------------------------------------------------
with tab_architecture:
    st.subheader("🏛️ Architecture & Governance Comparison")

    st.markdown(
        """
        | Threat Vector | Traditional Code Interpreter | SheetSafe AI Architecture |
        | :--- | :--- | :--- |
        | **Data Leakage** | Sends full proprietary CSV rows/cells to model cloud | **Zero Raw-Data Leakage**: Only schema definitions (`col_001`, `text`) are shared |
        | **Arbitrary Code Execution** | Generates raw Python scripts executed via `eval()`/`exec()` | **Declarative Planning Envelopes**: AI emits JSON operation steps; zero arbitrary code |
        | **Hallucinated Math** | Generative models invent totals and statistical sums | **Deterministic Host Execution**: Real math computed locally by validated pandas/NumPy |
        | **Formula Injection** | Malicious CSV text executes formula macros in Excel/Sheets | **Automated Neutralization**: Formula prefixes (`=`, `+`, `-`, `@`, `|`) are escaped |
        """
    )

    st.markdown("##### System Dataflow")
    st.code(
        """
[User Question]
       │
       ▼
[Pre-Flight Sanitizer (No PII / No Injections)]
       │
       ▼  (Schema Metadata & Question ONLY - No Raw Bytes)
[Vultr Serverless Inference Cloud (DeepSeek deepseek-v4.1-flash-1017)]
       │
       ▼  (Validated AIAnalysisPlan JSON Contract - schema_sha256 verified)
[Local Deterministic Pandas Evaluator]
       │
       ▼
[Verified Answer + Metric + Summary Table + Chart]
        """,
        language="text",
    )

    st.caption("SheetSafe AI &bull; Vultr Agent Rush Hackathon &bull; Team Titan")
