# SheetSafe AI

Team Titan's planned secure spreadsheet analyst for the Vultr Agent Rush
Hackathon. **Current implementation: backend foundation, synthetic use only.**
This repository does not yet provide a working autonomous analysis application.

## Implemented through Step 6

- FastAPI application factory, lifespan initialization, safe JSON errors, liveness
  and database/storage/retention readiness checks.
- SQLite metadata, foreign keys, WAL, explicit transactions and ordered migrations
  1 through 4. Published migrations are preserved.
- Opaque session credentials stored only as hashes, ownership checks, CSRF and
  exact-origin checks, secure cookies, expiry, revocation and bounded admission.
- Durable session cleanup requests, retry/restart recovery, sanitized audit
  retention and aggregate retention. Failed cleanup remains visible.
- Internal private storage with server-generated references, bounded I/O,
  SHA-256 verification, staging/atomic sealing, quarantine and verified scoped
  file cleanup. This is a byte store, not a spreadsheet safety validator.

## Step 7 runner foundation

The separate `runner/` package defines a frozen SEC01-SEC10 target policy, strict
allowlisted `smoke-v1` requests, a digest-pinned Dockerfile and a fixed harmless
fixture. Policy/image contract tests pass. Step 7B built and statically inspected
the pinned image on Docker Desktop's Linux backend without starting a container.
Step 7C adds a stopped-container lifecycle adapter tested only with an in-memory
fake transport: fixed specifications, ownership checks and verified removal.
Step 7D adds a read-only Engine preflight client and typed, fake-tested native
metadata mapping. Local preflight reports missing advertised LSM support and
an image environment mismatch; these blockers have not been bypassed.
Execution stays disabled: no Docker lifecycle transport, runner command or final
policy image digest is configured, and no smoke payload has been executed.
Runtime controls remain unverified. See the
[preflight observations and review proposals](docs/runner-preflight.md),
[lifecycle contract and transport blockers](docs/runner-lifecycle.md) and
[image inspection record](docs/runner-image-inspection.md)
for actual hashes, inherited base assets and limitations, and the
[runner plan](docs/runner-foundation-plan.md) for pending work.

## Not implemented or enabled

Private/customer uploads, upload/download APIs, spreadsheet parsing, real Docker
execution transport, Vultr inference, agent planning, self-healing, independent numerical
validation and Streamlit screens are not implemented. The `validated` storage
category is reserved; result publication is blocked. Installed libraries do not
mean their product features are operational.

No Vultr key is required or configured for the current foundation. Real uploads
remain disabled until encrypted storage, OS access controls, provider privacy,
isolated parsing/execution and independent validation meet their release gates.
Local tests are not a deployment security certification or proof of physical
erasure. A failed cleanup or outage can miss the five-minute target.

## Local setup (Python 3.12 and uv)

From the repository root:

```powershell
uv sync --frozen --python 3.12
if (-not (Test-Path -LiteralPath .env.local)) {
    Copy-Item -LiteralPath .env.example -Destination .env.local
}
uv run --frozen uvicorn backend.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers
```

Health and readiness require no inference credentials:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/v1/health
Invoke-RestMethod http://127.0.0.1:8000/api/v1/ready
```

Successful responses are `{"status":"ok"}` and `{"status":"ready"}`.
Readiness returns 503 when required checks fail. Interactive API docs are off
unless `SHEETSAFE_DOCS_ENABLED=true` is explicitly configured.

The default origin allowlist is empty and cookies require secure transport.
For explicitly local HTTP session testing only, edit the ignored `.env.local`:

```dotenv
SHEETSAFE_ENVIRONMENT=development
SHEETSAFE_ALLOWED_ORIGINS=["http://127.0.0.1:8000","http://localhost:8000"]
SHEETSAFE_ALLOW_INSECURE_LOCAL_COOKIES=true
```

Production requires exact HTTPS origins and rejects insecure-cookie mode. Session
creation also requires the bootstrap header and allowed Origin; deletion requires
the session cookie and CSRF proof. See the session protocol below.

## Files and tests

Default runtime files live under ignored `var/`: `sheetsafe.sqlite3` and private
`storage/`. `.env`, `.env.local`, other secret environment files, virtual
environments and SQLite sidecars are ignored; `.env.example` remains trackable.
A custom storage location must also remain outside Git and public/static roots.
Never place real keys, uploads or runtime receipts in the source tree.

```powershell
uv run --frozen --no-sync python -m pytest -q -rs
uv run --frozen --no-sync python -m compileall -q backend runner tests
git diff --check
```

Tests use isolated temporary roots and synthetic files. Windows storage checks
pin filesystem ancestor handles; restricted tool sandboxes may require approval
to run them. If a different Windows identity cannot access existing pytest temp
or cache directories, use a fresh, dedicated `--basetemp var/<unique-test-name>`
and `-p no:cacheprovider`. Never point pytest's base temp at existing user data.

The Step 7D Windows verification reported 599 passed, 1 skipped and 1
Starlette/httpx deprecation warning. The skipped file-symlink fixture lacked OS
creation privilege; real Windows junction and hardlink rejection were tested.
Linux storage and deployed sandbox acceptance are still required. The follow-up
and proposed next milestone are recorded in the runner plan below.

## Design and next milestone

- [Session security](docs/session-security.md)
- [Lifecycle and retention](docs/session-lifecycle.md)
- [Private storage and release blockers](docs/secure-storage.md)
- [Step 7 runner proposal and Linux follow-up](docs/runner-foundation-plan.md)

The intended architecture keeps Streamlit, FastAPI, SQLite, Vultr Serverless
Inference, a separately privileged restricted runner and an independent validator
separate. Backend/storage foundations, runner policy/image definitions and a
fake-tested lifecycle contract exist; an executing analysis workflow is pending.
