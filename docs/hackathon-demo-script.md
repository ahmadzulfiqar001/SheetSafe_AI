# SheetSafe AI — Two-Minute Hackathon Presentation & Demonstration Script

> **Team Titan** &bull; *Vultr Agent Rush Hackathon* &bull; **Track**: Autonomous AI Agents & Cloud Security  
> **Repository Baseline**: Step 12C (`141e1d3`) &bull; **Status**: Local Synthetic MVP Operational (Offline Mock Planning)

---

## 1. Quick Service Launch & Teardown (Windows PowerShell)

Open two PowerShell terminals in the repository root `c:\Users\AWL\Documents\HackathonProjects\SheetSafe_AI`:

### Terminal 1 — Start FastAPI Control Plane (Port 8000)
```powershell
powershell -ExecutionPolicy Bypass -File .\launch_local_demo.ps1 -Component fastapi
```
*Wait for output:* `Uvicorn running on http://127.0.0.1:8000`

### Terminal 2 — Start Streamlit Interactive UI (Port 8501)
```powershell
powershell -ExecutionPolicy Bypass -File .\launch_local_demo.ps1 -Component streamlit
```
*Wait for output:* `Network URL: http://localhost:8501`

### Health & Readiness Probes (Verification Terminal)
```powershell
# Probe Liveness (Process is running)
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/health"
# Return: {"status":"ok"}

# Probe Readiness (Database WAL initialized, private storage writable, retention worker active)
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/ready"
# Return: {"status":"ready"}
```

### Clean Teardown
Press `Ctrl+C` in Terminal 1 and Terminal 2. Both services terminate cleanly via standard interrupt signals without leaving hanging processes or unfinalized SQLite database connections.

---

## 2. Two-Minute Timed Presentation Script & Walkthrough

| Timestamp | Presenter Action in Browser | Spoken Script (English) | Technical Security Callout |
| :--- | :--- | :--- | :--- |
| **0:00–0:15** | Open `http://localhost:8501` in Chrome or Edge. Point to the hero banner. | *"Hello judges. I'm presenting SheetSafe AI by Team Titan. In enterprise workflows, employees upload confidential financial spreadsheets to LLMs, risking massive data exposure and prompt injection attacks. SheetSafe AI is built on a zero-raw-row privacy guarantee and a fail-closed execution architecture."* | Zero raw spreadsheet rows transmitted to AI models. |
| **0:15–0:30** | Scroll down to the **Subsystem Security Matrix** on the Dashboard. | *"On our dashboard, our FastAPI control plane and SQLite WAL metadata store are online and ready. However, untrusted file parsing and sandboxed container execution are visibly GATED. Real Linux sandbox acceptance has NOT yet passed on this Windows host, so SheetSafe AI fails closed until SEC01 through SEC10 native kernel gates are verified."* | Fail-closed security architecture. Honest gate reporting (`LSM_NOT_ADVERTISED`). |
| **0:30–0:45** | Click **"Start Synthetic Session"** in the sidebar. Navigate to **"My Datasets"** and click **"Provision Synthetic Demo Dataset"**. | *"We bootstrap an ephemeral session using an HttpOnly, SameSite=Strict cookie and an HMAC CSRF token. In 'My Datasets', we provision our server-owned synthetic quarterly revenue fixture. No untrusted user spreadsheet is accepted or parsed on this local machine."* | 256-bit hashed credentials. Ephemeral session state. Server-owned fixture only. |
| **0:45–1:05** | Navigate to **"AI Analysis"**. Choose preset *"Grouped Revenue by Department"*. Click **"Generate Simulated AI Analysis Plan"**. | *"We ask: 'What is total revenue grouped by department?' In this local MVP, planning is powered by a deterministic offline mock that simulates the Vultr Serverless Inference contract, as cloud credits are pending. The model receives only metadata column IDs—never raw rows—and outputs a structured, validated Pydantic analysis plan."* | Simulated offline inference mock. Zero raw rows to model. Structured schema contracts. |
| **1:05–1:25** | Expand **"Deterministic Analysis Code Preview"** and point to the **AST Validation Receipt**. | *"SheetSafe AI deterministically compiles this plan into Python code with an isolated `run_analysis` entrypoint. The AST validator admits only explicitly allowlisted mathematical imports—like pandas, numpy, and math—while strictly blocking unapproved modules, dunder reflection, dynamic eval/exec, and network or disk I/O. Execution remains disabled."* | Static AST admission policy. Allowed imports only. Zero dynamic execution. |
| **1:25–1:45** | Scroll down to the **Synthetic Analytical Results**, **Altair Bar Chart**, and **Download Reports**. | *"Below, our independent numerical verifier computes ground-truth expected results directly over the synthetic fixture—it does NOT execute the generated candidate code. When downloading the CSV or Markdown report, spreadsheet formula triggers like equals, plus, or at-signs are neutralized with leading single quotes."* | Formula injection defense (`=, +, -, @`). Labeled `DEMO / SYNTHETIC`. |
| **1:45–2:00** | Click **"Delete My Data Now (Revoke)"** in the sidebar. Observe immediate session reset. | *"Finally, clicking 'Delete My Data Now' immediately revokes session authentication logically in SQLite, clearing all cached views and locking future API calls with 401. Physical storage erasure is queued for the asynchronous retention worker. Thank you—we welcome your questions."* | Immediate logical revocation (`access_revoked=True`). 5-min physical scrub sweep. |

---

## 3. UI Acceptance & Verification Checklist

| Verification Category | Method / Scope | Evidence / Status |
| :--- | :--- | :--- |
| **Automated AppTest Suite** | Streamlit `AppTest.from_file` and Pytest integration in [`tests/test_step12c_ui_end_to_end.py`](file:///c:/Users/AWL/Documents/HackathonProjects/SheetSafe_AI/tests/test_step12c_ui_end_to_end.py) | **VERIFIED (AUTOMATED)**: 1,513 passed unit/integration tests across full suite, including 7 end-to-end UI and negative regression tests covering the 17-step user flow. |
| **HTTP Socket Probes** | Direct loopback HTTP requests to local daemon listeners | **VERIFIED (AUTOMATED PROBE)**: FastAPI responds on `http://127.0.0.1:8000/api/v1/health` (`status=ok`) and `/api/v1/ready` (`status=ready`). Streamlit responds on `http://127.0.0.1:8501/_stcore/health` (`200 OK`). |
| **Manual Real Browser Walkthrough** | Human interaction in Google Chrome / Microsoft Edge on Windows | **MANUALLY VERIFIED**: Verified that buttons, preset dropdowns, Altair visual chart rendering, and CSV/Markdown file downloads operate cleanly without browser console exceptions. |

---

## 4. Key Security Architecture Explanations for Judges

1. **Zero Raw Rows Transmitted to AI Models**:
   - The AI planning prompt receives column identifiers, data types, and null counts only. Actual numbers, dates, customer records, and financial entries are never serialized into prompts.
2. **Deterministic Offline Planning Mock**:
   - In the local MVP, planning responses are generated by a reviewed offline mock adhering to the Vultr Serverless Inference schema contract. Live Vultr cloud inference remains on hold pending hackathon cloud VM and account credit activation.
3. **Fail-Closed Execution Gate**:
   - `execution_enabled=False` is hardcoded across the local application. No setting, flag, or user query can enable host or container code execution.
4. **AST Static Admission vs. Container Isolation**:
   - Static AST validation permits a curated subset of modules (`math`, `statistics`, `decimal`, `datetime`, `json`, `pandas`, `numpy`, `matplotlib.pyplot`) and enforces strict syntax bounds, but rejects all dynamic code execution (`eval`/`exec`), dunder reflection (`__class__`, `__subclasses__`), filesystem I/O (`read_csv`, `open`), and network calls. Passing AST validation is defense-in-depth only—it does not authorize host execution and does not substitute for kernel-isolated container sandboxing (SEC01–SEC10).
5. **Independent Numerical Verification Limits**:
   - The numerical verifier computes ground-truth analytical outputs over the known synthetic fixture using trusted standard library routines. It does **not** execute the generated candidate Python code and does not assert that candidate code executed successfully (`candidate_output_verified=False`, `publication_authorized=False`).
6. **Logical Revocation vs. Physical Retention Scrubbing**:
   - Calling `DELETE /api/v1/sessions/{id}` immediately sets `revoked_at` in SQLite, invalidating authentication tokens in constant time ($O(1)$) and rejecting subsequent requests with 401. Physical file erasure from private storage is handled asynchronously by the `LifecycleCoordinator` retention worker within a 5-minute target window.
7. **Native Linux Sandbox Acceptance Pending**:
   - Real spreadsheet uploads and sandboxed execution require native Linux Kernel $\ge$ 6.8 with AppArmor in enforce mode, Cgroups v2 controllers, and rootless user namespace mapping (`10001:10001`). Docker Desktop on Windows cannot advertise AppArmor (`LSM_NOT_ADVERTISED`), so all production upload and execution routes remain strictly locked.
