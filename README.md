# SheetSafe AI

**Privacy-Preserving Natural Language Spreadsheet Intelligence**<br>
*Built by Team Titan for the Vultr Agent Rush Hackathon*

---

[![Vultr Serverless Inference](https://img.shields.io/badge/Vultr-Serverless%20Inference-007BFC?logo=vultr&logoColor=white)](https://www.vultr.com/products/serverless-inference/)
[![Model: DeepSeek](https://img.shields.io/badge/Model-deepseek--v4.1--flash--1017-blueviolet)](https://www.vultr.com/products/serverless-inference/)
[![FastAPI Control Plane](https://img.shields.io/badge/Backend-FastAPI%200.115+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Streamlit UI](https://img.shields.io/badge/Frontend-Streamlit%201.38+-FF4B4B?logo=streamlit&logoColor=white)](https://streamlit.io)
[![Test Suite Status](https://img.shields.io/badge/Tests%20(Ubuntu%2024.04)-1610%20passed%2C%201%20skipped-success)](docs/)
[![Python 3.12](https://img.shields.io/badge/Python-3.12%2B-blue?logo=python&logoColor=white)](https://www.python.org/)

---

## 📌 Executive Summary

Modern AI data analysis tools often introduce significant privacy and security risks by transmitting entire customer spreadsheets directly to external LLM providers or executing unconstrained AI-generated code on the host system.

**SheetSafe AI** addresses these challenges through a **Zero-Code Execution & Privacy-Guarded Planning** architecture:
1. **Raw spreadsheet data NEVER leaves the local host.** Outbound inference payloads include only the user's sanitized analysis question and permitted dataset schema metadata (`column_id`, column name, `inferred_type`, row/column counts, and `schema_sha256`). Raw spreadsheet bytes, cell values, and preview rows are never transmitted.
2. **Natural language queries are translated into strictly declarative planning envelopes** using **Vultr Serverless Inference** (`deepseek-v4.1-flash-1017`).
3. **Computations execute via approved, deterministic host analytics** (pre-defined pandas/NumPy routines on the host machine), preventing LLM arithmetic hallucination and eliminating AI-generated arbitrary code execution (`eval()`, `exec()`, shell escapes).

---

## 🚨 The Problem vs. The SheetSafe Solution

| Threat Vector | Industry Standard (e.g. Code Interpreter) | SheetSafe AI Invariant |
| :--- | :--- | :--- |
| **Data Leakage** | Transmits proprietary cell contents, PII, and financial records to third-party model servers. | **Guarded Metadata-Only Payloads**: Outbound requests include only the sanitized question and permitted schema metadata (`column_id`, `name`, `inferred_type`, dimensions, and `schema_sha256`). Raw CSV bytes, cell values, and rows are never transmitted. |
| **Arbitrary Code Execution** | LLM generates Python scripts executed via `eval()`, `exec()`, or subshells on the host machine. | **Declarative Planning Envelopes**: AI emits only structured JSON planning operations (`GROUP_AGGREGATE`, `SELECT`, `SORT`). Zero AI-generated code is executed. Approved, pre-defined deterministic host analytics compute the final result. |
| **Hallucinated Math** | Generative models invent numerical totals, sums, or statistical trends. | **Deterministic Host Execution**: Calculations are evaluated locally by approved deterministic pandas/NumPy analytical routines, preventing generative model hallucination of numerical totals. |
| **Prompt Injection** | Hidden spreadsheet text instructs the agent to exfiltrate tokens or run commands. | **Pre-flight Sanitization & Cryptographic Binding**: Questions are screened for injection patterns; operations are cryptographically bound to `schema_sha256`. |
| **Formula Injection** | Malicious CSV exports trigger DDE or spreadsheet formula execution (`=CMD(...)`). | **Automated Formula Neutralization**: Leading formula trigger characters (`=`, `+`, `-`, `@`, `|`) are escaped with `'` in all generated reports. |

---

## 🏛️ System Architecture

```text
┌───────────────────────────────────────────────────────────────────────────────────┐
│                                 USER BROWSER                                      │
└──────────────────────────┬────────────────────────────────────▲───────────────────┘
                           │ HTTP / Local Loopback               │
                           ▼                                    │
┌────────────────────────────────────────────────────────────────┴──────────────────┐
│                            STREAMLIT FRONTEND (Port 8501)                         │
│  • Dashboard & Health Monitors        • Interactive Visualizations (Bar/Line)    │
│  • Real CSV Upload Workspace          • Analysis History & Status Badges          │
│  • Natural Language Query Console     • One-Click Session Revocation              │
└──────────────────────────┬────────────────────────────────────▲───────────────────┘
                           │ Typed HTTPX Client (HttpOnly Cookies + CSRF Protection) │
                           ▼                                    │
┌────────────────────────────────────────────────────────────────┴──────────────────┐
│                          FASTAPI CONTROL PLANE (Port 8000)                        │
│                                                                                   │
│  ┌───────────────────────┐ ┌────────────────────────┐ ┌────────────────────────┐  │
│  │   Session & Privacy   │ │  Pre-Flight Sanitizer  │ │   Storage Lifecycle    │  │
│  │ Opaque Tokens & CSRF  │ │  PII & Injection Guard │ │ Ephemeral Byte Storage │  │
│  └───────────────────────┘ └───────────┬────────────┘ └────────────────────────┘  │
│                                        │                                          │
│                                        ▼ Question & Schema Metadata Only          │
│                                          (No Raw Cell Values / Bytes)             │
│               ┌─────────────────────────────────────────────────┐                 │
│               │          VultrInferenceClient (HTTPX)           │                 │
│               │      Dedicated 40s Read Timeout / Retries       │                 │
│               └────────────────────────┬────────────────────────┘                 │
└────────────────────────────────────────┼──────────────────────────────────────────┘
                                         │ HTTPS Outbound (api.vultrinference.com)
                                         ▼
                 ┌───────────────────────────────────────────────┐
                 │       VULTR SERVERLESS INFERENCE CLOUD        │
                 │      Model: deepseek-v4.1-flash-1017          │
                 │  Emits Validated AIAnalysisPlan JSON Contract │
                 └───────────────────────┬───────────────────────┘
                                         │ Validated Planning Envelope
                                         ▼
┌───────────────────────────────────────────────────────────────────────────────────┐
│                    DETERMINISTIC HOST ANALYTICS ENGINE                            │
│  • Cryptographic Schema Binding Verification (`schema_sha256`)                    │
│  • Strict 10-Operation Declarative Evaluator (`GROUP_AGGREGATE`, `SELECT`, etc.)  │
│  • Approved Deterministic Pandas / NumPy Execution on Local Dataset               │
│  • Automated Formula-Neutralized Reporting                                        │
└───────────────────────────────────────────────────────────────────────────────────┘
```

---

## ⚡ Working Features (Implemented & Verified)

### 1. Live Vultr Serverless Inference Integration
- Seamlessly connects to the official Vultr endpoint: `https://api.vultrinference.com/v1/chat/completions`.
- Driven by **DeepSeek** (`deepseek-v4.1-flash-1017`) using bounded token allocations (4096 input / 4096 output) and dedicated 40-second planning read timeouts.
- Transmits a strictly scoped, fenced JSON data envelope containing the sanitized user question and permitted dataset schema metadata (`version`, `schema_sha256`, `row_count`, `column_count`, and column references with `column_id`, `name`, `inferred_type`). Raw CSV/XLSX bytes, cell contents, preview records, worksheet names, file storage paths, session cookies, and API credentials are never included.
- Pre-flight security filters reject prompt injection patterns (e.g. system instruction override attempts) and sensitive metadata patterns (emails, SSNs, credit cards) before network dispatch.
- Converts free-form business questions (e.g., *"Which department generated the highest total revenue?"*) into structured, validated `AIAnalysisPlan` envelopes.
- Employs a fail-closed, offline **Deterministic Intent Parser** fallback (`DETERMINISTIC_FALLBACK`) whenever cloud inference is unconfigured or unavailable.

### 2. Real CSV Upload & Deterministic Analytics
- Real-world CSV upload and processing on the local host with strict 20 MiB file limits.
- Automated column type inference (`text`, `number`, `datetime`), null-value accounting, and descriptive statistics.
- Interactive data profiling: first-few row inspection, numerical summary tables, and dynamic charting.

### 3. Interactive Streamlit Control Plane (5 Full Workspaces)
- **Dashboard**: Real-time FastAPI health metrics, session status, and active security invariant monitors.
- **My Datasets**: Provision synthetic demonstration datasets or upload custom CSV spreadsheets for profiling.
- **AI Analysis**: Interactive query console, preset scenario testing, live provider mode badges (`LIVE_VULTR_AI` vs. `DETERMINISTIC_FALLBACK`), natural language answers, calculated scalar metrics, and structured summary dataframes.
- **Analysis History**: Audit-log inspection with full run lifecycle tracking (`AWAIT_CONFIRMATION`, `NEEDS_CLARIFICATION`, `BLOCKED_POLICY`, `TIMED_OUT`).
- **Settings / Privacy**: Real-time CSRF token verification, session expiry countdown, and one-click session revocation with guaranteed ephemeral state deletion.

### 4. Zero-Trust Session & Storage Security
- Opaque, cryptographically hashed session tokens (SHA-256) sealed in `HttpOnly`, `SameSite=Strict` cookies.
- Strict `Origin` allowlisting and `X-CSRF-Token` validation across all stateful endpoints.
- Auto-expiring local sessions with background cleanup enforcing ephemeral file purging.

---

## 🔬 Implementation Scope & Security Disclaimers

SheetSafe AI prioritizes honest engineering. The table below provides a clear, transparent view of what is fully functional in this release versus proposed or staged architectural components:

| Component / Subsystem | Current Status | Description |
| :--- | :--- | :--- |
| **FastAPI Control Plane & SQLite WAL** | ✅ **Implemented & Verified** | Full session lifecycle, CSRF defense, and database migrations 1–6 verified on native Ubuntu 24.04. |
| **Live Vultr Serverless Inference** | ✅ **Implemented & Verified** | Live DeepSeek planning envelope generation tested and verified on native Vultr Ubuntu 24.04. |
| **Deterministic Host Analytics** | ✅ **Implemented & Verified** | Zero-code execution invariant: queries evaluated strictly by approved, pre-defined pandas host functions. |
| **Streamlit Interactive UI** | ✅ **Implemented & Verified** | 5 complete UI pages with dynamic visualizations and summary tables. |
| **Real CSV Ingestion & Profiling** | ✅ **Implemented & Verified** | Local CSV ingestion with descriptive statistics and numerical summaries. |
| **Spreadsheet Formula Neutralization** | ✅ **Implemented & Verified** | Neutralizes `=Cmd()`, `@`, `+`, `-`, `\|` in exports to prevent client spreadsheet compromise. |
| **Test Network Isolation Guard** | ✅ **Implemented & Verified** | Pytest harness isolates host credentials and blocks unmocked external requests to Vultr hostnames. |
| **Sandboxed Docker Execution Runner** | 🟡 *Staged Foundation (SEC01–10)* | Security-gated: Digest-pinned container policy designed; runtime container execution disabled pending host LSM / AppArmor audit. |
| **Dedicated Unprivileged Parser Worker** | 🟡 *Staged Foundation* | Security-gated: Hardened parser image built offline; execution disabled pending transport approval. |
| **Untrusted Public Multi-Tenant Uploads** | 🟡 *Security-Gated (Non-Production)* | Security-gated: Intended for local/controlled demonstrations; public untrusted upload handling requires production parser sandboxing. |
| **Autonomous Self-Healing Execution** | ❌ *Not Authorized* | Out-of-scope for safe enterprise MVP; AI-generated Python code is strictly unexecuted on untrusted data. |
| **Public Multi-Tenant HTTPS Deployment** | ❌ *Not Authorized* | Configured strictly for local/loopback demonstration; requires production HSM/KMS keys. |

---

## 🛠️ Tech Stack

- **Cloud & AI**: Vultr Cloud Compute (Ubuntu 22.04 / 24.04), Vultr Serverless Inference (`deepseek-v4.1-flash-1017`).
- **Backend**: FastAPI 0.115+, Uvicorn, Pydantic v2 (Strict validation), HTTPX (Async/Sync).
- **Frontend**: Streamlit 1.38+, Altair visualization engine.
- **Data & Verification**: Pandas, NumPy, DefusedXML, SQLite (WAL Mode).
- **Tooling & Packaging**: Python 3.12, `uv` package manager, Pytest, Docker (staged).

---

## 🚀 Quickstart Guide

### Prerequisites
- Python 3.12+
- `uv` (recommended) or standard `pip` / `venv`
- Modern web browser (Chrome, Firefox, Edge)

### 1. Clone the Repository
```bash
git clone https://github.com/<your-repo>/SheetSafe_AI.git
cd SheetSafe_AI
```

### 2. Install Dependencies
Using `uv` (fastest):
```bash
uv sync --frozen --python 3.12
```
Or standard Python virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r pyproject.toml
```

### 3. Configure Local Environment
Create your local configuration file from the template:
```bash
cp .env.example .env.local
```
*(On Windows PowerShell: `Copy-Item .env.example .env.local`)*

Edit `.env.local` to allow local loopback origins:
```dotenv
SHEETSAFE_ENVIRONMENT=development
SHEETSAFE_ALLOWED_ORIGINS=["http://localhost:8501","http://127.0.0.1:8501","http://127.0.0.1:8000","http://localhost:8000"]
SHEETSAFE_ALLOW_INSECURE_LOCAL_COOKIES=true
SHEETSAFE_SYNTHETIC_PLANNING_ENABLED=true
SHEETSAFE_DATABASE_PATH=var/sheetsafe.sqlite3
```

*(Optional)* To enable **Live Vultr Serverless Inference**, export your Vultr inference credentials in your terminal session (do not hardcode in git):
```bash
export SHEETSAFE_VULTR_INFERENCE_API_KEY="your-vultr-inference-api-key"
export SHEETSAFE_VULTR_INFERENCE_MODEL="deepseek-v4.1-flash-1017"
```
*(On Windows PowerShell: `$env:SHEETSAFE_VULTR_INFERENCE_API_KEY="your-vultr-api-key"`; `$env:SHEETSAFE_VULTR_INFERENCE_MODEL="deepseek-v4.1-flash-1017"`)*

### 4. Launch the Application

#### Option A: One-Command PowerShell Launcher (Windows)
```powershell
# Terminal 1: Start FastAPI Control Plane
.\launch_local_demo.ps1 -Component fastapi

# Terminal 2: Start Streamlit Dashboard
.\launch_local_demo.ps1 -Component streamlit
```

#### Option B: Standard Terminal (Linux / macOS / Windows)
```bash
# Terminal 1: Start FastAPI Control Plane (Port 8000)
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers

# Terminal 2: Start Streamlit Frontend (Port 8501)
python -m streamlit run frontend/app.py --server.address 127.0.0.1 --server.port 8501
```

Access the Streamlit Dashboard at: **`http://localhost:8501`**

---

## 🧪 Verification & Test Suite

The SheetSafe AI repository includes an automated test suite verifying security controls, AST policies, inference timeouts, session protocols, and data analytics.

### Linux Verification (Native Vultr Ubuntu 24.04)
Run the full test suite:
```bash
pytest tests/ -o cache_dir=var/tmp/.pytest_cache --basetemp=var/tmp -q
```
**Verified Linux Result**:
```text
1610 passed, 1 skipped in 68.42s
```
*(1 skipped test requires root-level OS filesystem symlink creation privileges).*

### Windows Verification
Run the unit and client test suites:
```powershell
.venv\Scripts\python.exe -m pytest tests/test_frontend_dashboard.py tests/test_csv_analytics.py tests/test_inference_client.py tests/test_config.py -o cache_dir=var/tmp/.pytest_cache --basetemp=var/tmp -q
```
**Verified Windows Result**:
```text
156 passed, 11 skipped in 9.29s
```
*(Skipped tests bypass Streamlit subshell AppTest threads blocked by Windows sandbox security).*

### Bytecode Compilation & Diff Hygiene
```bash
python -m compileall -q backend frontend validator runner tests
git diff --check
```

---

## 🎬 Demonstration Walkthrough

1. **Initialize Session**: Open `http://localhost:8501`. On the **Dashboard**, click **Start Synthetic Session**. An opaque, cryptographically hashed session is established with `HttpOnly` security cookies.
2. **Inspect or Upload Data**:
   - Navigate to **My Datasets**.
   - Review the pre-loaded quarterly revenue dataset schema (`col_001` - department, `col_002` - revenue), OR upload your own CSV file to view real-time deterministic profiling and summary statistics.
3. **Execute Natural Language Query**:
   - Navigate to **AI Analysis**.
   - Enter a query: *"Which department had the highest revenue?"* or select a preset scenario.
   - Click **Generate AI Analysis Plan**.
4. **Observe Real-Time Badging & Results**:
   - **Live Inference**: Displays the green badge `🟢 LIVE VULTR SERVERLESS INFERENCE` citing model `deepseek-v4.1-flash-1017`.
   - **Answer**: Displays the verified natural-language explanation.
   - **Metric & Summary Table**: Displays the calculated scalar result (`$425,000.50`) and a structured 2-row summary table (`Enterprise` vs. `MidMarket`).
   - **Zero-Code Verification**: Expand *Proposed Declarative Operations* to verify that only a declarative JSON plan was created, executed safely via approved local deterministic pandas host routines.
5. **Session Revocation & Cleanup**:
   - Navigate to **Settings / Privacy**.
   - Click **Revoke Session & Queue Deletion**.
   - Confirm that all cached previews, active datasets, and ephemeral files are immediately purged.

---

## 👥 Team Titan

Built with pride by **Team Titan** for the **Vultr Agent Rush Hackathon**.<br>
Demonstrating how high-performance serverless AI inference can coexist with strict enterprise data privacy and deterministic computational safety.
