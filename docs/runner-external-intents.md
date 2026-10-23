# Step 7L: simulated external intent and recovery contract

Implemented on 2026-10-24, after approved checkpoint
`0ce4f29dac6c5c01e573aa6ff37e0c1c2b99e29a` was normally pushed to main. HEAD,
origin/main and remote main matched, and the working tree was clean before this
increment. The checkpoint's exact 15 staged paths/blobs passed signature/scope
review, syntax and staged whitespace checks; tests: 996 passed, 1 skipped,
1 warning in 49.27s. Commit message:
`feat: add secure transport validation and durable job preparation`.

**This is simulation only.** No real container is created, inspected, started,
stopped or removed. No execution approval follows from intent or reconciliation.
No driver, background reaper, Docker socket/API, real input transport, uploads,
stdin receiver, collector, freezer, cloud resource or credentials are added.
The transport PRD amendments remain unapproved. Image/policy/LSM/seccomp and
SEC01-SEC10 runtime gates are unchanged and remain blocking where unverified.

## Persistence and immutable identity

Migration 6 adds one child `external_intents` table to the existing run/job model,
not another job queue or lifecycle coordinator. Published migrations 1-5 remain
unchanged. The existing Database transactions, JobStore ownership/lease checks,
session lifecycle, audit append and retention are reused. Attempts are untouched;
no execution attempt or analysis COMPLETE state is fabricated.

The only allowlisted operation is SIMULATED_CREATE_SMOKE, in immutable SIMULATED
mode. Register takes a trusted current JobLease, never caller image, command,
resource ID, flags, mounts, fixture or privilege arguments. It requires persisted
INPUT_VERIFIED evidence at that epoch, an active authorized synthetic session,
eligible run and no cleanup/cancellation. Job registration already used the
existing credential-hash ownership guard. Public reads additionally use owned_run.
Worker/recovery methods are trusted operator APIs, not public HTTP endpoints.

Each operation has a generated UUID, a distinct generated resource UUID and a
256-bit ownership nonce. Its job/run/session, origin epoch, authorized owner
hash, operation type, scope, image identity and image configuration digest are
immutable. The approved local image is
`sha256:551ae45bad03b4a1856ae503c62c01a8078394a19d3c318b53fc9f2e98f66bc9`;
its separate configuration digest is
`sha256:59f66d35ff913f60851bde600c75680bc0054c04f32ba72ec42ca2ae2ec6d546`.
These are the existing local review identities, not invented registry digests or
runtime-policy verification. The displayed name is always
simulated-sheetsafe-<resource UUID>; name matching alone never proves ownership.

Unique constraints protect operation/resource identity and one fixed operation
per job. Conflicting or duplicate registration is rejected without new side
effects/audit completion. A composite foreign key binds the job/run/session to
the same existing run. STRICT checks and triggers preserve immutable identity,
monotonic recovery epochs and terminal states. Unresolved child records/runs
cannot be deleted, including cascade cleanup or REPLACE. All data remains
session-linked; content-free audit records follow the existing 24-hour policy.

## State and dispatch sequence

| State | Meaning |
| --- | --- |
| No record | No operation registered or authorized |
| INTENT_RECORDED | Persisted approved simulated intention; no dispatch marker |
| DISPATCH_UNCERTAIN | Dispatch authorization committed; a send may or may not have happened |
| RECONCILIATION_REQUIRED | Inspection failed, timed out or lacked quiescence; outcome unknown |
| VERIFIED_PRESENT | Exact intended simulated resource positively observed; cleanup still pending |
| VERIFIED_ABSENT | Quiesced authoritative simulated inspection found the exact target absent |
| CLEANUP_REQUIRED | Scoped fake removal authorized/possibly sent; acknowledgement is insufficient |
| VERIFIED_CLEANED | Independent quiesced inspection after removal found the target absent |
| TERMINAL_FAILURE | Conflicting identity/evidence or exhausted budget; unresolved, needs operator review |

Registration is transactional and has no I/O. begin_dispatch checks the original
live lease, owner hash, epoch, binding and INTENT_RECORDED state. It commits
DISPATCH_UNCERTAIN and changes the run to irreversible BLOCKED_EXTERNAL before
returning the sole fake-create specification. Its preparation lease is released.
Any intent also prevents JobStore from renewing/reclaiming/advancing it as
harmless preparation. Duplicate dispatch never returns another specification.
The Step 7K synthetic retry path cannot repeat ambiguous work.

runner/simulated_external.py calls only injected simulate_create/inspect/remove
methods with a one-second timeout contract and simulation_only=true. There is
no production implementation or fallback. Create/remove acknowledgements and
exception messages are not evidence and do not change durable uncertainty.
Process interrupts propagate, leaving the committed marker intact. Database
errors before/after commit do not trigger a send, automatic retry or success.

The commit-to-send gap intentionally remains uncertain. A worker could pause
there and resume late; lease expiry or a negative name lookup is not proof it
cannot send. The simulation's quiescence evidence is therefore mandatory before
absence or cleanup resolution. It is an explicit fake assertion, not an
implemented Linux fence, cgroup freezer, process kill or broker guarantee.

## Fenced recovery and evidence

Recovery is a separate capability on the same intent, not execution authority.
A server-generated reconciliation token and increasing reconciliation epoch
own one five-second claim, with at most three claims total. The origin epoch
continues to identify the immutable intended resource; the current reconciliation
epoch fences the inspector callback. No in-memory lock is authoritative.
Transactions are short BEGIN IMMEDIATE operations; no transaction spans I/O.

Before dispatch, recovery waits for the original live preparation owner to
expire or be cancelled. After uncertainty is recorded, that preparation owner
cannot mutate/retry it. Fresh operator instances can reconcile after session
revocation/expiry or run deadline; these claims grant inspection/scoped cleanup
only and never alter session expiry, admitted_at, run deadline or cleanup SLA.
The original requested_at+300 cleanup target remains fixed, even if missed.

Inspection must bind the exact operation/resource UUID, ownership nonce,
job/session/run, origin epoch, current inspection epoch, approved local image and
configuration digest. Strict booleans and compatible lifecycle states are
required. Same-name foreign ownership, unknown identity, running/unexpected
lifecycle and contradictory evidence terminate unresolved without removal.
Timeout/transport failure is sanitized RECONCILIATION_REQUIRED; at the bounded
limit it remains TERMINAL_FAILURE, not absence. Duplicate/stale callbacks cannot
append another completion or clear a newer owner's state. Crash-expired claims
consume the same finite budget, without sleeps or automatic retry loops.

Positive presence can authorize one scoped simulated removal only while the
same inspection claim is live and actions_quiesced=true. Removal first commits
CLEANUP_REQUIRED and consumes that claim. A fresh claim/inspection is required
to establish absence. A false successful acknowledgement leaves the resource
unresolved. No broad orphan enumeration/deletion exists. Even positive simulated
results keep execution_enabled=false and real_resource_cleanup_verified=false.

Exactly-once external execution is **not** proved. These APIs are trusted and
receipts are synthetic; callers must never treat them as Docker evidence.
A future real implementation needs external dispatch fencing/quiescence, native
resource identity receipts, interruptible I/O, independent watchdog/reaper,
permissions and reconciliation proof. A caller-set simulation attribute is not
a security boundary against a malicious trusted transport. No such transport
should ever be connected to real Engine operations under this contract.

## Existing cleanup integration

Unresolved intents are included in LifecycleCoordinator runtime inventory.
Revocation remains immediate; cancellation preserves external uncertainty.
Unknown records block metadata deletion independently of a cleanup adapter's
claimed success, preventing false COMPLETE. Resolved synthetic-only intents can
stop blocking synthetic inventory, while unrelated real attempts/receipts and
legacy BLOCKED_EXTERNAL runs without intents still require their verifiers.
There is no claim that any real file/container was cleaned.

Failure state, retry budget and original cleanup deadlines survive restart.
Terminal unresolved intents intentionally have no reset/delete API here; further
operator remediation requires review. That fail-closed choice can miss retention
targets and pauses existing admissions; it must not discard uncertainty just
to report timely deletion. Independent output validation remains separate.
Audit mutations share each state transaction, using fixed event types, pseudonym,
run ID and bounded claim count, without owner tokens/nonces or content.

## Verification record

New files: backend/storage/external_intents.py, runner/external_contract.py,
runner/simulated_external.py, tests/test_external_intents.py and this document.
Updated schema/database/jobs/lifecycle modules add the child migration, readiness,
audit types, preparation guard and cleanup inventory. tests/test_jobs.py changes
only its final migration-version assertion to current SCHEMA_VERSION while
keeping populated-data/integrity checks. README and related architecture docs
record this increment. Policy, image, daemon/host/LSM and auth modules are untouched.

Tests use real temporary SQLite files, independent connections, fresh repository
instances, controlled clocks, transactional failure injection and in-memory fake
resources. Subprocess/network entry points are blocked in the new suite. Thread
races and process-interrupt simulations are not actual OS process-kill tests,
cross-machine stress evidence or Vultr/Linux certification.

Observed focused/related commands:

```powershell
uv run --frozen --no-sync python -m pytest tests/test_external_intents.py tests/test_jobs.py tests/test_transport_protocol.py tests/test_transport_state.py -q -x -p no:cacheprovider --basetemp var/step7l-combined-20261024
# 333 passed in 24.18s: 83 new intent tests plus 250 job/transport tests
uv run --frozen --no-sync python -m pytest tests/test_database.py tests/test_sessions.py tests/test_retention.py tests/test_storage.py tests/test_lifecycle.py tests/test_host_readiness.py tests/test_runner_policy.py tests/test_runner_image.py tests/test_runner_preflight.py tests/test_runner_lifecycle.py -q -x -rs -p no:cacheprovider --basetemp var/step7l-related-20261024
# 683 passed, 1 skipped, 1 warning in 24.20s
```

Coverage includes five registration, five dispatch, five reconciliation and
five cancellation/reconciliation races; one registration/dispatch/recovery
authorization wins where exclusive ownership is required. Pre/post-dispatch
interruptions, lost acknowledgement, exact lease expiry, stale callbacks,
same-name foreign resources, wrong image/config/owner, contradictory evidence,
quiescence failure, locked acknowledgements, before/after-commit errors, expiry,
revocation, independent cleanup inspection, restart, retry exhaustion, composite
foreign keys and populated migration/rollback are covered. No test weakens a
security assertion; the prior final-version test follows current SCHEMA_VERSION.

Complete project verification:

```powershell
uv run --frozen --no-sync python -m pytest -q -x -rs -p no:cacheprovider --basetemp var/step7l-full-20261024
# 1079 passed, 1 skipped, 1 warning in 70.12s (0:01:10)
uv run --frozen --no-sync python -m compileall -q backend runner tests
# exit 0
git diff --check
# exit 0; five untracked files separately whitespace-checked
```

The Windows skip at tests/test_storage.py:176 remains an unavailable OS
file-symlink creation privilege. The existing Starlette TestClient/httpx
deprecation warning remains. Git LF/CRLF advisories are separate. No automated
test failed in checkpoint or implementation verification.

AST comparison against the new checkpoint confirms published migrations 1-5
unchanged, only migration 6 added. Final scope/signature audit: 13 expected files,
8 tracked modifications, 5 new untracked files, no unexpected path or credential
signature. Scans are heuristic, not certification. .env/.env.local and runtime
var/ remain ignored; .env.example is tracked. All staged lists are empty. Step
7L is uncommitted/unpushed; HEAD/origin-main remain 0ce4f29, whose remote hash was
independently verified after the approved Phase A push. No cloud/deployment or
real Docker action occurred.

Native Linux still needs the skipped symlink fixture, LSM/seccomp evidence and
effective SEC01-SEC10 acceptance. Recommended next smallest milestone: native
Linux host acceptance and a reviewed late-dispatch fencing/quiescence design,
alongside the pending transport architecture decision. Do not connect a concrete
adapter or run a smoke container until those prerequisites and approval exist.
