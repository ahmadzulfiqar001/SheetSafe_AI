# SheetSafe AI — Local Development & Presentation Demo Guide

This guide describes how to run and present the working local demonstration of **SheetSafe AI** for Team Titan in the **Vultr Agent Rush Hackathon**.

---

## 1. Executive Summary & Demo Boundaries

SheetSafe AI is an offline, security-hardened foundation for autonomous spreadsheet analysis. It features:
- **FastAPI Control Plane**: SQLite WAL database, cryptographically sealed session management, CSRF validation, strict origin checks, and non-sliding session lifetimes.
- **Streamlit Interactive UI**: Multi-page workspace, live backend probing, preset analysis scenario selector, structured planning review, deterministic Python compilation previews, static AST validation receipts, and interactive charts (`st.bar_chart` and `st.line_chart`).
- **Independent Expected Result Verifier**: Pure-stdlib verification over a server-owned synthetic dataset (`synthetic_quarterly_revenue_v1`) producing reference results, numerical descriptive statistics, completeness metrics, and formula-neutralized CSV/Markdown reports.

### Strict Security Boundaries (What is Real vs. Simulated)
| Capability | Current State | Notes |
| :--- | :--- | :--- |
| **Control Plane & Sessions** | **Real & Functional** | Full SQLite schema, encrypted cookie exchange, CSRF tokens, immediate access revocation. |
| **FastAPI REST Endpoints** | **Real & Functional** | Health, readiness, session bootstrap, planning preview, and run history. |
| **Streamlit Dashboard** | **Real & Functional** | Live client, state synchronization, interactive charts, and downloads. |
| **Deterministic Code Generator** | **Real & Functional** | Compiles validated plans to standalone Python source code. |
| **AST Security Admission** | **Real & Functional** | Defense-in-depth static parser admission checking nodes, depth, and imports. |
| **Numerical Expected Verifier** | **Real & Functional** | Computes reference expected results independently from synthetic fixtures. |
| **AI Inference Provider** | **Simulated Offline Mock** | Deterministic in-memory HTTPX mock (`provider_mode=SIMULATED_MOCK`); zero external Vultr API calls. |
| **User Spreadsheet Uploads** | **Disabled by Security Gate** | Requires accepted native Linux host with AppArmor/cgroup v2 isolation. |
| **Candidate Code Execution** | **Disabled by Security Gate** | Untrusted Python is **NEVER** executed on the host or inside the backend process. |
| **Docker Execution Runner** | **Gated (Pending Linux)** | Requires Linux LSM advertisement and SEC01–SEC10 validation before container starts. |

---

## 2. Windows PowerShell Launch Procedure

### Prerequisites
- Python 3.12+ (or approved virtual environment at `var\runtime-validation-31317\venv`).
- Windows PowerShell terminal.

### Step-by-Step Launch
Open **two separate Windows PowerShell terminals**:

#### Terminal 1 — Start the FastAPI Backend
```powershell
# From repository root:
.\launch_local_demo.ps1 -Component fastapi
```
*Expected output:*
```text
INFO:     Started server process [PID]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

#### Terminal 2 — Start the Streamlit Dashboard
```powershell
# From repository root:
.\launch_local_demo.ps1 -Component streamlit
```
*Expected output:*
```text
  You can now view your Streamlit app in your browser.
  Local URL: http://localhost:8501
  Network URL: http://127.0.0.1:8501
```

### Shutdown Instructions
In each PowerShell terminal, press `Ctrl+C` to terminate the process cleanly. SQLite database connections and temporary files will close safely.

---

## 3. Complete 14-Step Local User Journey (Presentation Walkthrough)

1. **Launch FastAPI**: Terminal 1 starts uvicorn on `http://127.0.0.1:8000`.
2. **Launch Streamlit**: Terminal 2 starts Streamlit on `http://localhost:8501`.
3. **Open Dashboard**: Navigate to `http://localhost:8501`. Observe:
   - *FastAPI Control Plane*: `Online & Ready` (probes `/api/v1/health` and `/api/v1/ready`).
   - *Active Session*: `None` (Unauthenticated).
   - *Dataset Upload Gate* and *Vultr AI Execution*: `Disabled` (Fail-closed gates visible).
4. **Create Authenticated Synthetic Session**:
   - Click **Start Synthetic Session** on the Dashboard or Settings page.
   - Observe immediate issuance of a 256-bit hashed session credential and non-sliding 1-hour expiration.
5. **Register Synthetic Dataset**:
   - Navigate to the **My Datasets** tab.
   - Note that real uploads are locked (`private_uploads_enabled=False`).
   - Click **Provision Synthetic Demo Dataset Schema** to inspect the 5 columns of `synthetic_quarterly_revenue_v1`.
6. **Submit Analysis Question**:
   - Navigate to the **AI Analysis** tab.
   - Select a preset scenario from the **Quick Synthetic Analysis Scenario** dropdown (e.g. `Grouped Revenue by Department (GROUPED_TABLE + Bar Chart)` or `Quarterly Revenue Line Chart (LINE_CHART)`).
   - Click **Generate Simulated AI Analysis Plan (DEMO / SIMULATED)**.
7. **Display Structured AI Plan**:
   - Under Tab 1 (*Simulated AI Plan*), inspect the `AIPlanningEnvelope`: intent summary, required column bindings, and declarative operations.
8. **Generate Deterministic Python Code Preview**:
   - Switch to Tab 2 (*Deterministic Code Preview & AST Receipt*).
   - Review the compiled `GeneratedCodeCandidate` source code (`def run_analysis(records):`).
9. **Display AST Validation Receipt**:
   - Under Tab 2, inspect the static `ASTValidationReceipt`: node count, tree depth, allowlisted imports, and notice that `execution_authorized=False`.
10. **Compute Trusted Synthetic Expected Results Without Execution**:
    - Switch to Tab 3 (*Synthetic Verification Preview (DEMO)*).
    - Observe status: `SYNTHETIC_EXPECTED_RESULT_COMPUTED`, `candidate_output_verified=False`, `publication_authorized=False`.
11. **Display Analytical Tables & Interactive Charts**:
    - View formatted result tables with human-readable headers (e.g. `department (col_002)`).
    - View interactive charts (`st.bar_chart` for categorical groups or `st.line_chart` for time series).
    - Inspect descriptive statistics and missing-value completeness insights.
12. **Download DEMO CSV / Markdown Report**:
    - Click **Download Demo Markdown Report (.md)** or **Download Formula-Safe Demo CSV (.csv)**.
    - Confirm files are watermarked `DEMO / SYNTHETIC` and formula triggers (`=`, `+`, `-`, `@`, `|`) are prefixed with `'`.
13. **View Analysis History**:
    - Navigate to the **Analysis History** tab.
    - Inspect persisted runs stored in SQLite (`state=AWAIT_CONFIRMATION`, `provider_mode=SIMULATED_MOCK`).
14. **Revoke Session & Verify Access Denied**:
    - Click **Delete My Data Now (Revoke)** in the sidebar or Settings page.
    - Confirm access is revoked instantly (`access_revoked=True`), cached plans and datasets are cleared from memory, and subsequent API calls fail with `401 Unauthenticated`.

---

## 4. Troubleshooting Guide

| Issue | Root Cause | Solution |
| :--- | :--- | :--- |
| **Port 8000 or 8501 Busy** | A prior Python or Streamlit process is lingering. | Run `Get-Process python` in PowerShell and terminate the stale process with `Stop-Process -Id <PID>`. |
| **403 Forbidden (Origin)** | Streamlit origin is not in FastAPI's allowlist. | Ensure `.env.local` contains `SHEETSAFE_ALLOWED_ORIGINS=["http://localhost:8501","http://127.0.0.1:8501","http://127.0.0.1:8000"]`. |
| **401 Unauthorized Cookie** | Insecure cookies disabled over HTTP. | Ensure `SHEETSAFE_ALLOW_INSECURE_LOCAL_COOKIES=true` in `.env.local` for local loopback development. |
| **Planning 422 Disabled** | Synthetic planning flag is off. | Ensure `SHEETSAFE_SYNTHETIC_PLANNING_ENABLED=true` in `.env.local`. |
| **Control Plane "Offline"** | FastAPI process not started. | Run `.\launch_local_demo.ps1 -Component fastapi` in Terminal 1 first. |

