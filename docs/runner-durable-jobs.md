# Step 7K: durable synthetic preparation

Implemented 2026-10-24 against checkpoint `38ec781`, preserving Step 7I/J work.
This is trusted operator infrastructure, not a public API or an executing runner.
Step 7L adds a separate [simulated external-intent contract](runner-external-intents.md).
Once such an intent exists, this harmless-preparation claim/retry path is blocked;
only its bounded inspection/cleanup reconciliation may resolve uncertainty.
No daemon operations, real transport, generated code, uploads, stdin receiver,
collector or external effects are implemented. The PRD transport amendments
remain unapproved. LSM, native Linux and SEC01-SEC10 runtime gates remain.

## Existing persistence and identity mapping

Migration 5 extends existing `runs`; no second job table/queue or cleanup
coordinator is introduced. Published migrations 1-4 are unchanged. `owned_run`
rechecks the session's real stored credential hash and ownership inside each
registration, authorized read and cancellation. Received manifest fields never
create authority. Worker methods are internal to trusted operator infrastructure,
not exposed through FastAPI or Streamlit.

Each eligible QUEUED/POLICY_CHECK run gets one generated UUID runner_job_id,
bound to the run and its immutable session/dataset ownership. Existing attempts
remain candidate/execution records: no fake code reference, candidate version or
execution attempt is created or consumed. A future execution attempt needs its
separately approved binding to this run, policy and resource evidence.

Registration accepts no payload/command/image/path/fixture overrides. It uses
only the inert bytes `SheetSafe synthetic smoke fixture v1\n`, smoke-v1 and
protocol version 1. Expected length and SHA-256 are stored, not payload bytes.
The 256 KiB constraint is a synthetic transport ceiling, not an upload limit.
Repeated registration is a conflict even after terminal failure; callers cannot
replace a run's manifest to obtain a fresh budget.

New columns: runner_job_id, prep_protocol_version, prep_fixture_id,
prep_payload_length, prep_payload_sha256, prep_state, lease_epoch,
prep_claim_started_at, prep_verified_epoch, prep_created_at, prep_updated_at.
Existing lease_owner, lease_expires_at, heartbeat_at, admitted_at, deadline_at
and cancel_requested_at are reused. A unique index protects job identity. STRICT
constraints/triggers enforce coherent metadata, immutable manifests, nondecreasing
epochs, irreversible terminal states and fixed admission/deadline after claim.
Run foreign keys, WAL and existing transactions remain. Readiness probes the
new preparation columns too.

## Claims, renewal and fencing

Every mutation uses a short existing BEGIN IMMEDIATE transaction. Time is read
after obtaining the writer lock; lock waiting cannot mint an already-old lease.
SQLite serializes writers across connections/processes. Conditional updates
check old epoch/expiry or prior state/owner; no in-memory lock is the durable
security boundary. No transaction spans transport receive/close.

First claim installs a generated 256-bit owner token, epoch 1, durable expiry
and heartbeat. It fixes admission and the existing <=180-second run deadline.
Leases last <=10 seconds, capped by run deadline and session expiry. Renewal
requires the exact job/run/session, owner token, epoch, active session, allowed
prior state, no cancellation/cleanup, a live lease and later heartbeat. Renewal
must increase expiry and cannot extend that owner beyond 30 seconds from claim.
No API accepts caller-selected tokens, epochs, durations, deadlines or execution
flags. Tokens are omitted from repr/audit and must stay in trusted worker
memory/SQLite, never guest input or public output.

Validity is now < lease_expires_at. At exact expiry the old owner is stale and a
new claimant can acquire the next epoch atomically. Early reclaim is rejected.
Reclaim resets safe synthetic preparation to CREATED and clears verification,
rotating token/epoch without replacing the job or payload metadata. At most
three claims are permitted in this synthetic profile; this is not permission
for three external executions or a change to candidate/attempt budgets. The
original run deadline never moves.

JobBinding hydration uses a private trusted-record factory, not received claims.
Expected manifests include the current lease epoch, so frame binding digests
change on recovery. Internal PayloadEvidence now includes its validated epoch.
Old frames, evidence, tokens and callbacks cannot advance a new preparation.
The JSON/wire protocol remains v1; evidence is internal, not authentication.

Host UTC is trusted. Tests control both session and DB clocks; production uses
system UTC. Backward time behind the heartbeat/preparation timestamp is refused.
This is not a durable monotonic clock or protection against host time compromise.

## Durable state and fake integration

```text
CREATED -> RECEIVING -> INPUT_VERIFIED -> READY_FOR_EXECUTION
```

Only ordered edges pass, with live ownership and exact prior state. INPUT_VERIFIED
needs trusted FrameValidator evidence matching job, epoch, length and SHA-256.
Readiness requires the persisted verified epoch to equal the active epoch. READY
releases the preparation lease and rejects duplicate claims/acknowledgements.
The analysis run stays QUEUED/POLICY_CHECK; no COMPLETE, execution, independent
validation or cleanup success is claimed.

`runner/durable_preparation.py` links the existing fake harness and JobStore.
It loads the trusted manifest, checks the lease around receive/close and commits
each successful stage before advancing the simulator. Commit/ownership errors
raise sanitized JobCodes; a failed commit cannot produce a successful receipt.
Results remain execution_enabled=false. The standalone harness's persistent-auth,
immutability and cleanup flags stay false; its receipt alone grants no authority.
No concrete production transport or polling loop is supplied.

FAILED, INTERRUPTED, TIMED_OUT, CANCELLED and BLOCKED_EXTERNAL are terminal.
Malformed/duplicate/truncated delivery gets durable failure. Explicit interruption
receipts are terminal. Process interruption propagates, leaving the last committed
active state for bounded expiry-based fresh validation. No partial-frame resume
or automatic retry exists; reclaim clears old verification before reading data.
READY may be cancelled but never prepared again. Cancellation is idempotent for
an authenticated, active session owner.

Callback/evidence APIs are trusted internal code. Untrusted processes must never
invoke JobStore or instantiate their own evidence to attest bytes. Matching the
fixed fixture does not prove input immutability, correctness or execution safety.

## Cleanup, retention and uncertainty

Existing LifecycleCoordinator revocation/enqueue remains atomic. A new trigger
durably cancels active/ready preparations when the run's cancellation flag is
set, clearing the lease in the same transaction. Revocation/expiry blocks worker
transitions immediately through DB checks, before the expiry sweep records
cancellation. Repeated cleanup keeps its original receipt and requested_at+300
deadline. No cleanup deadline or session lifetime is extended.

Cancellation does not claim files/containers were removed. Fake preparation
creates no runtime resource. BLOCKED_EXTERNAL is a terminal uncertainty marker,
with no dispatch method. Cleanup treats it as requiring a runner verifier even
after lease release; a missing adapter cannot certify it. Metadata purge uses
the existing verified cleanup flow. Failed cleanup/restart evidence is preserved.
Audit uses the existing append-only 24-hour path: fixed event types, pseudonym,
run ID and bounded retry count, without tokens, credentials, payloads or content.
Mutation and audit append share a transaction; rejected duplicate acknowledgements
and idempotent cancellation do not duplicate audit events.

Unique DB claims do not prove exactly-once external execution. Safe reclaim here
depends on the absence of external effects. Before any future create/dispatch,
durable intent, uncertain-result states, ownership receipts, watchdog/reconciliation
and verified cleanup need separate review. This schema does not make retrying an
ambiguous future Docker call safe. SQLite/operator access remains trusted; this
is not SQL authorization against a host administrator or execution approval.

## Verification

Actual temporary SQLite files/separate connections, controlled clocks, injected
failures and fake transport are used. No sleeps, containers or real network.

```powershell
uv run --frozen --no-sync python -m pytest tests/test_jobs.py tests/test_transport_protocol.py tests/test_transport_state.py -q -x -p no:cacheprovider --basetemp var/step7k-transport-20261024
# 250 passed in 15.74s: 73 durable-job tests plus existing 177 transport tests
uv run --frozen --no-sync python -m pytest tests/test_database.py tests/test_sessions.py tests/test_retention.py tests/test_storage.py tests/test_lifecycle.py tests/test_host_readiness.py tests/test_runner_policy.py tests/test_runner_image.py tests/test_runner_preflight.py tests/test_runner_lifecycle.py -q -x -rs -p no:cacheprovider --basetemp var/step7k-related-20261024
# 683 passed, 1 skipped, 1 warning in 30.53s
```

Cases include registration/ownership, immutable metadata, ten competing-worker
races (one winner each), five cancellation/renewal races, exact expiry, bounded
renewal/claims/deadline, old epoch/frame/evidence replay, ordered transitions,
restart at each active phase, process-interrupt simulation, late revocation,
session expiry, locked DB, registration/claim/renewal/transition/audit/commit
rollback, cross-job isolation, unresolved cleanup and populated v4-to-v5 migration
with integrity/foreign-key checks. These are thread races on separate SQLite
connections and restart simulations, not actual process-kill experiments,
multiprocess stress certification or production timing evidence.

Complete verification:

```powershell
uv run --frozen --no-sync python -m pytest -q -x -rs -p no:cacheprovider --basetemp var/step7k-full-20261024
# 996 passed, 1 skipped, 1 warning in 51.21s
uv run --frozen --no-sync python -m compileall -q backend runner tests
# exit 0
git diff --check
# exit 0; all ten untracked files checked separately too
```

Windows skip: tests/test_storage.py:176, OS file-symlink creation privilege
unavailable. Native Linux must run that fixture without this skip. The existing
Starlette TestClient/httpx deprecation warning remains. Git LF/CRLF advisories
are separate; no automated test failed. No dependencies were changed.

AST comparison against HEAD confirms migrations 1-4 unchanged. Scope/signature
review covers all 15 accumulated pending files: 5 tracked modifications and 10
untracked source/test/doc files, no unexpected path or credential signature.
Signature scans are heuristic, not a secret-free certification. .env/.env.local
and var/ remain ignored; .env.example is tracked. No staged change, commit,
push, deployment or cloud operation; HEAD remains 38ec781.

New Step 7K files: backend/storage/jobs.py, runner/durable_preparation.py,
tests/test_jobs.py and this document. Updated: backend/storage/schema.py,
backend/storage/database.py, backend/security/lifecycle.py,
runner/transport_protocol.py, runner/transport_state.py, README.md,
docs/runner-transport-validation.md and docs/runner-secure-transport-design.md.
The runner-foundation-plan change and Step 7J tests are preserved from earlier
work. Runtime policy/image/daemon/host admission and session authentication
modules remain unchanged. The lifecycle edit only adds BLOCKED_EXTERNAL to
unresolved-runtime inventory; cancellation itself uses the migration trigger.

Native Linux symlink/deployed sandbox acceptance remains required. Recommended
next milestone: review a fake-only durable external-intent/uncertain-outcome and
reconciliation contract before selecting real transport. That would not itself
approve the pending PRD amendments, a collector/receiver, or execution.
