# Step 7M — admission, quiescence aur PRD decision

Date: 2026-10-24. Status: **CONDITIONAL / implementation approval pending**.
Yeh bounded design review hai. Koi application code, schema, image, daemon setting,
container, collector, freezer ya VM change nahi hua. Execution disabled hai.

## 1. Verified checkpoint aur review scope

Step 7L commit `18662e33be1e4e251389ef1ab56bc6f906b938fa` normal push se main
par gaya. Local HEAD, origin/main aur independently queried remote main match
hue; Phase B se pehle working tree clean thi. Message:
`feat: add durable external intents and simulated reconciliation`.
Exact 13 staged paths/blobs reviewed thay; signature hits zero, migrations 1-5
unchanged, migration 6 forward-only. Checkpoint suite: 1079 passed, 1 skipped,
1 warning in 60.69s. Syntax aur staged whitespace checks passed.

jobs.py ke claims/epochs, external_intents.py ki immutable identities/recovery,
simulated_external.py, Docker lifecycle contract, session coordinator, framing,
host readiness, existing tests aur original 26-page PRD review kiye gaye.
PRD v1.0 dated 19 October 2026: SHA-256
`999d923deb24960418fc94afbaaab4ce195636be25d0f05dd384129ef077d889`.
Original PDF unchanged hai. Neeche page/paragraph references proposed edits ko
identify karti hain; woh PDF ki instructions execute karne ki authorization nahi.

Current real baseline: operator-only fake operations; no concrete Docker
create/start transport. LSM_NOT_ADVERTISED last observed Desktop blocker hai,
native Linux acceptance pending aur SEC01-SEC10 UNVERIFIED hain. Is review mein
real Engine/container inspection bhi nahi ki gayi.

## 2. Faisla: DB fence aur external execution alag boundaries hain

SQLite transaction stale worker ko state badalne se rok sakti hai. Woh Docker ko
already sent request revoke nahi kar sakti. Intent send ka proof nahi; create ack
execution ka proof nahi; remove ack cleanup ka proof nahi. Lost response ka
matlab absent resource nahi. No exactly-once external-execution claim.

Reviewed [Engine API 1.56 start contract](https://docs.docker.com/reference/api/engine/version/v1.56/)
mein application lease epoch/expiry ya cancellation predicate ka atomic parameter
nahi hai. Is se design inference yeh hai: unknown JSON fields/labels bhejna
daemon-side fencing nahi banata. Client timeout ko rollback samajhna bhi galat hai.

Required future authority: ek dedicated host par ek narrow runner admission
broker. API/UI/orchestrator ko daemon access nahi; unke requests authenticated
local typed RPC par aayen. Broker current persisted ownership, cancellation,
source/image/policy, epoch aur remaining budget check kare; no caller flags.
One active broker incarnation ke siwa kisi worker ko create/start/exec/resume
access na mile. OS socket permissions, live groups/ACLs aur service credentials
is boundary ko enforce karein. Daemon authority host-level trusted privilege hai.
[Docker authorization model](https://docs.docker.com/engine/extend/plugins_authorization/)
granular request admission support karta hai, lekin pre-request plugin bhi
DB commit aur actual process activation ko ek atomic transaction nahi banata.
Plugin/proxy add karna is milestone mein approved ya implemented nahi.

Broker writes durable intent before side effects and handles each operation once.
Create is stopped-only; start is a distinct authority decision. No daemon restart
policy, exec, unpause/resume, healthcheck or alternate socket may bypass it.
Old epoch never gets a fresh GO; revoked/expired sessions cannot regain authority.

**Strict late-start guarantee abhi unresolved hai.** DB cancellation commit,
broker observation, Engine accepting start aur candidate's first instruction
different events hain. A final check followed by a stalled call still has a gap.
Single-thread serialization, flock, short token expiry, AuthZ precheck, socket
close ya cancellation callback alone is gap ko eliminate nahi karte.
Authorization-before-cancellation ordering ko zero post-cancellation execution
ka naam nahi dena. Access revocation immediate rahe; existing candidate ko PRD's
bounded cancellation/kill path se terminate karna alag obligation hai.

Real dynamic execution HOLD rahe jab tak an activation-side fence/private launch
gate ki enforcement, expiry, crash behavior aur old-incarnation exclusion native
tests se prove na hon. Bootstrap time check alone bhi sufficient proof nahi:
check aur exec ke darmiyan process stall ho sakta hai. Exact activation mechanism
aur its limits ko separately approve karna hoga; revocation promise silently
weaken nahi hogi. Broker crash par admissions default CLOSED hon, replacement
broker only cleanup/reconciliation kare. Old authority ki death/access revocation
aur all in-flight daemon work ki quiescence prove hone se pehle takeover nahi.
Stock Docker mein reviewed application-level flush/cancel barrier established
nahi hai; daemon restart ko bhi automatic barrier certificate na samjhein.
No automatic HA lease takeover on a shared daemon.

## 3. Das late-dispatch cases

| Case | Prevention/detection owner aur remaining gap |
| --- | --- |
| 1. Check ke baad worker stalls | Worker cannot own daemon access; broker rechecks on receipt. Broker itself stalls after its final check to gap remains; activation fence/native proof required. DB epoch only stale DB write stops. |
| 2. Expired request late arrives | Admission broker denies new dispatch at expiry; already accepted Engine request is uncertain. No new start/GO; independent watchdog/reconciler detects late resources. It does not prove zero late activation. |
| 3. Create succeeds, ack lost | Persisted operation/native resource binding + broker reconciliation locate exact stopped resource. Never retry create as a fresh execution authorization; unknown identity blocks. |
| 4. Cancel before start | API immediately revokes access; broker denies any new start/GO after observing current cancellation. Request already in flight needs activation-side fence; it cannot be called safely absent from a negative lookup alone. |
| 5. Cancel races start | One authority must order admissions/cancellation, but DB and Engine transitions remain separate. Record uncertainty, withdraw admission, kill/verify within cancellation budget; strict no-late-start acceptance stays blocked until proved. |
| 6. Old owner resumes | Existing epoch rejects stale mutations; old worker has no socket. Broker refuses old incarnation. No reclaim of an intent as safe preparation; delayed broker/daemon calls still require real quiescence proof. |
| 7. Broker crashes before/after call | Durable marker covers both possibilities. Replacement stays cleanup-only, fences prior authority out of band and reconciles; no blind start/create replay. Missing fence means host quarantined. |
| 8. DB unavailable after intent | No new admission based on cached authorization. Issued requests remain unknown. Independent watchdog uses already fixed monotonic deadline; preserve inventory outside lost connection and recover DB truth before new work. |
| 9. Engine answers after timeout | Timeout is communication failure, not cancellation. Bind late reply to original operation/epoch; do not let it update a new owner or launch a repair. Reconcile exact resource after all possible late effects are fenced. |
| 10. Existing runtime has old epoch | No execute/relabel/adopt-as-current. Record stale resource; authenticated broker inventory must establish native ID/nonce/image/cgroup ownership. Only positively owned, fenced runtime is eligible for scoped kill/remove; mismatched or foreign resource needs operator review. |

External deadline supervision must survive the request worker and broker failing.
It cannot require a functioning API/DB to stop already-authorized work. Dedicated
watchdog permissions, identity, resource inventory and monotonic deadlines remain
unimplemented release gates. A whole host/kernel failure cannot promise bounded
teardown; report incident/cleanup uncertainty, never a successful result.

## 4. Input, bootstrap aur collection decision

| Alternative | Security assessment / decision |
| --- | --- |
| Original stopped archive | Closest PRD wording. Runtime-visible immutable inputs and live tmpfs output access remain unverified under current read-only-root policy. Keep as contract until amendment approved; no writable-root/bind-mount shortcut. |
| Trusted stdin + framed output from same bootstrap | Bounded transport is useful, but guest frames/keys do not establish trusted post-candidate control. Same UID lets a compromised supervisor stay compromised even after candidate exits. Reject as current authoritative collector. |
| Bounded stdin + externally quiesced host collection | Conditional preferred dynamic transport. Preserves no host mounts in guest, but adds a powerful host helper and kernel identity dependencies; native proof and explicit amendments required. |
| Narrow fixed-image fixture, no dynamic inputs/artifact publication | First real containment target after native prerequisites/approval. Existing smoke-v1 needs no stopped input transfer. It can test policy/teardown without waiting for production collector approval, but cannot claim parsing/analysis or collected artifacts. |
| Separate protected supervisor/OCI preparation | Possible fallback if archive wording must stay. Different UID/namespace/cgroup or runtime preparation changes need their own SEC01/image/architecture review; not an implemented shortcut. |

Answers to the collection questions:

1. Host-local peer credentials/permissions authenticate service RPC. Resolve owner,
   job/run/source and fence from trusted storage, not received claims. Bounded
   versioned manifest/frame checks independently measure length/SHA-256. Hashes
   alone authenticate neither sender nor current session. No credential enters
   guest; transport's 256 KiB synthetic profile is not a dataset-upload allowance.
2. Conditional receiver accepts opaque bytes before candidate launch, creates
   sealable memfds, seals write/grow/shrink/seal and verifies bits/length; no
   writable mappings/unrelated FDs inherited. Retest accounting/seccomp and library
   FD access. [memfd sealing](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
   supplies a primitive, not evidence our proposed integration works. Root-owned
   input semantics need amendment; same-UID chmod must not make bytes writable.
3. A fixed receiver's pre-launch channel can be trusted only during the verified
   pre-candidate window. After GO, all guest stdout, DONE/READY text, claimed hash
   and exit status are untrusted. Host receipts stay on a guest-inaccessible
   control channel. No embedded guest HMAC secret is accepted as a boundary.
4. Broker/watchdog requests whole-runtime termination on timeout/cancellation;
   no artifact salvage may delay the kill target. Successful collection may
   instead require whole-runtime freeze while tmpfs is alive, within run budget.
5. A freeze write is a request. Require bound runtime/cgroup identity and
   kernel-confirmed cgroup.events frozen=1; termination additionally needs the
   intended subtree empty. Parent/descendant membership and migration permissions
   must be controlled, not inferred from one PID exit or Docker Paused=true.
   [Kernel cgroup v2 contract](https://docs.kernel.org/admin-guide/cgroup-v2.html).
6. Whole-container freeze also freezes bootstrap, so it cannot frame output while
   frozen. Proposed host helper pins the actual live mount/workspace through
   reviewed native references; no host bind mounts, guest exec or arbitrary
   namespace command. Required OS privileges are not yet measured/approved.
7. Pin native runtime ID, init/candidate pidfds, namespace and mount identities;
   numeric PID/start string alone is insufficient. Trusted task-root acquisition
   is a separately reviewed magic-link boundary. Then descend only under a pinned
   work directory with no-follow/beneath resolution, regular-file/nlink=1 checks
   and stable descriptor metadata. Reject traversal, links, special files and
   unexpected mounts. [openat2 boundaries](https://man7.org/linux/man-pages/man2/openat2.2.html)
   help resolve paths but do not identify the correct namespace for us.
8. Reject entry 11 before collecting it; precheck <=10 MiB/file, track remaining
   <=20 MiB total during <=64 KiB reads, and independently hash actual bytes.
   Reject size drift, sparse/special encodings and trailing content. Quarantine
   STAGING until complete; 64 KiB/stream logs have a separate bound. No privileged
   PNG/CSV decoding; format/numeric validation happens independently in sandbox.
9. Collector crash invalidates incomplete output; close/purge scoped staged refs,
   reconcile pinned descriptors/runtime and keep admissions blocked if unsure.
   Daemon outage does not erase inventory. No resume of paused jobs or unbounded
   retry; watchdog must still enforce deadline. Lost FDs/tasks/data remain a failure.
10. Before cleanup success: fence old/in-flight creates/starts, close streams and
    mount/input FDs, verify exact owned runtime absent, job cgroup/tasks gone and
    registered app copies removed. Reconcile owned inventory, not global prune;
    preserve foreign resources. Only then storage/WAL verification and coordinator
    completion. Force-remove ack or 404 without late-action quiescence is not enough.

**Could bootstrap collect after candidate termination?** Only with a demonstrated
independent protection boundary, all descendants stopped, and uncompromised
collector/control channel. Current UID 10001 for both roles supplies no such
post-launch trust. Killing descendants cannot undo earlier supervisor tampering.
A separately protected receiver/exporter would need explicit identity/LSM/cgroup
design changes. We do not recommend adding that second complex design now.

## 5. Formal amendment package — draft only

Original page 12 paragraph 1 requires stopped-container archive copy and
root-owned read-only inputs. Docker documents cp for stopped containers but that
does not prove compatibility with this policy. Tmpfs hides underlying files and
does not survive stop. Earlier Step 7I Moby source review found writable-path and
private-tmpfs-view constraints; it reviewed master, not the deployed revision.
No local experiment in this milestone confirms or refutes matching-build behavior.
[Docker cp](https://docs.docker.com/reference/cli/docker/container/cp/),
[tmpfs lifecycle](https://docs.docker.com/engine/storage/tmpfs/).

Proposed replacement wording, **not changes to the original PDF**:

| Amendment | Exact PRD location and proposed normative replacement |
| --- | --- |
| AM01 transport/immutability | p12, first paragraph, stopped archive/root-owned input sentences: "The broker shall deliver only server-selected bounded input objects to the fixed trusted receiver through an authenticated host-controlled transport. Before untrusted code can run, actual lengths and hashes shall match the immutable job manifest and immutable input capabilities shall be independently verified. The initial approved implementation may use sealed memory-backed descriptors, without root ownership, only after seal, mapping, accounting, descriptor and launch-gate acceptance tests pass. No host bind mount, secret-bearing per-job image or writable-root seeding is permitted." |
| AM02 provision/execute order | p12 Lifecycle, Provision and Execute bullets, plus p8 execution-plane description: "A fresh stopped runtime is created and its effective policy verified. Only a fixed trusted receiver may start before bounded input preparation. Starting that receiver is not authorization to execute candidate code. The sole admission authority shall issue no new launch authorization for a cancelled, expired or stale-fenced job; the activation boundary and all in-flight-request failure cases must pass native acceptance before candidate execution is enabled. Transfer remains inside the original run budget." |
| AM03 collection/descendants | p12 second paragraph and Collect bullet: "While the runtime's ephemeral output remains available, an external scoped collector shall obtain exact resource and kernel identity evidence, independently confirm all untrusted writers are quiescent, and read only bounded allowlisted regular files into quarantine. A freeze request, guest completion message or leader exit is insufficient. If proof or collection fails, abandon output and terminate within the original deadline; do not depend on tmpfs surviving shutdown." |
| AM04 retained lifecycle guarantees | p11 SEC10 and p12 Destroy/Failure recovery: add "Cleanup verification shall additionally establish old dispatch authority and in-flight operations quiescent, all registered runtime/process/descriptor/storage resources absent, and unresolved outcomes durably retained. No repair or publication is admitted while that proof is missing." Existing teardown/reaper duties remain. |

Unchanged: SEC01 identity 10001, dropped caps/NNP, no network/socket/host mounts,
read-only root and bounded /work /tmp, exact CPU/RAM/PID/time/output budgets,
independent validator, fresh runtimes, ownership, encrypted private storage and
one-hour/5-minute/24-hour/30-day retention policies. SEC03 gains a proposed immutable
input representation, not a writable-root exception. SEC08 still excludes secrets.
No amendment here permits late activation or relaxes cancellation/kill deadlines.

Additional threats: pre-candidate receiver attack surface, stdin/backpressure
DoS, FD leaks/seal/accounting mistakes, same-UID tampering, privileged collector
confused deputy, PID/mount reuse, unfreezing/migration races and broker split-brain.
Acceptance must prove bounded authenticated framing; immutable input under
adversarial same-UID probes; no spoofed control; activation/cancellation races;
kernel-bound freeze and actual tmpfs visibility; path/link/size canaries; cleanup
after DB/daemon/helper/broker loss; independent validator/publication and retention.
The linked Linux plan specifies evidence and SEC pass/fail criteria.

Reasons to approve a future amendment: consistent no-mount design, immutable
input goal preserved, host-derived output evidence, existing durable ledger reused.
Reasons to reject/hold: activation fence, helper privilege minimum, mount/FD
identity, resource accounting and crash cleanup are not yet demonstrated. Formal
architecture approval alone would authorize implementation, not declare tests
passed. If declined, revisit narrowly reviewed OCI preparation; never silently
retain archive labels while executing a different transport.

## 6. Delivery priorities — stop expanding simulation

1. Next: operator supplies an existing native Linux host; run the linked read-only
   acceptance phase, resolve LSM/API/image evidence and approve a bounded fixed
   smoke experiment. No additional generic simulated subsystem is recommended.
2. Implement only a fixed-fixture, operator-only real adapter after that approval;
   test policy, deadline and verified teardown with no uploaded input or result
   publication. This is a useful containment increment independent of AM01/03.
3. Decide amendments and activation-fence design; prove minimal native receiver/
   collector experiment. Then isolated secure CSV/XLSX ingestion, including ZIP,
   signature, dimensional and expansion limits. Never parse uploaded spreadsheets
   inside FastAPI/Streamlit. If xlsx is dropped, PRD scope change is explicit.
4. Vultr client: bounded schemas/timeouts/budgets/redaction and honest failures;
   real account/model/API options verified before an explicitly approved live
   credentialed call. Mock HTTP tests do not count as an inference demo.
5. One deterministic orchestrator, capped repair attempts, independent fresh-runtime
   numerical checks and quarantine-to-publication gate. No model validation oracle.
6. Streamlit follows actual APIs/states and exposes exclusions/limits; it gets no
   daemon, inference key or dataset parser. No fake successful analysis screens.
7. HTTPS deployment, concurrency/privacy/retention acceptance, Vultr live inference
   demonstration and reproducible synthetic demo evidence; provision/spend only
   with separate approval. No fixed delivery dates promised before native gates.

Step 8 can begin in parallel after approval: Vultr provider configuration/request
schema, total timeout/retry/token-budget enforcement and fake HTTP failure tests
without keys or network calls. Trusted numeric golden fixtures/result-schema
contracts can also be prepared. Real uploads, parsing, generated execution and
production-readiness claims stay disabled until their own gates pass. This work
builds delivery features rather than another broad simulated runner.

## 7. Evidence and links

Native checklist: [Linux sandbox acceptance](linux-sandbox-acceptance.md).
Original proposal: [Step 7I transport](runner-secure-transport-design.md).
Current implementation: [Step 7L synthetic contract](runner-external-intents.md).
Official primary references above checked 2026-10-24; facts, source inferences
and proposed requirements are explicitly separated. No real acceptance evidence
was fabricated. Post-review tests/Git checks are recorded below.

## 8. Step 7M-A concurrency investigation and final review

Date 2026-10-24; Python 3.12.13, frozen existing uv environment. Historical
post-review result **135 passed, 1 failed** tha; failing case
`test_cancellation_racing_renewal_is_irreversible[0]` raised `JOB_DATABASE_BUSY`.
Us failure mein native SQLite code/stage trace nahi thi, is liye us ke exact
thread order ya native extended code ka claim nahi hai.

**Confirmed classification B: test ki transient writer-contention assumption
galat thi.** Original test ne simultaneous renewal/cancellation start ki aur
100ms fixture busy timeout ke bawajood cancellation ka lazmi commit assume kiya.
WAL mein bhi ek waqt mein ek writer hota hai; busy timeout success guarantee
nahi deta. Default production timeout 5000ms unchanged hai. Official references:
[transactions](https://www.sqlite.org/lang_transaction.html),
[busy timeout](https://www.sqlite.org/c3ref/busy_timeout.html),
[native result codes](https://www.sqlite.org/rescode.html).

Actual diagnostic observations, separate real SQLite connections:

| Schedule | Observed result |
| --- | --- |
| Original isolated case, instrumented | 1 passed in 0.33s. Cancellation writer committed first; renewal acquired afterward and was blocked by committed cancellation. 13 opened / 13 closed connections, no native SQL error. |
| Renewal writer held before commit using Events | Cancellation connection 8 failed at `BEGIN IMMEDIATE`: native 5 `SQLITE_BUSY`, not 517 `SQLITE_BUSY_SNAPSHOT` or 6 `SQLITE_LOCKED`. No transaction began; rollback returned and connection closed. After renewal commit, cancellation flag remained NULL and lease remained valid. Exactly one explicit authorized cancellation after writer completion committed. |
| Cancellation writer held before commit using Events | Renewal connection 24 failed at `BEGIN IMMEDIATE`, native 5 `SQLITE_BUSY`, then rollback/close. Cancellation committed after release; subsequent renewal and transition were rejected. |

Controlled diagnostic run: 2 passed in 0.90s, 31 opened / 31 closed connections,
zero unclosed. Observed busy-call elapsed times 173.066ms and 230.626ms include
scheduling; configured busy timeout is not a hard wall-time bound. Separate WAL
snapshot during each held write saw pre-commit state. No arbitrary sleep used.
These controlled schedules reproduce the public error and demonstrate its
mechanism; they do not reconstruct the untraced historical schedule.

Minimal correction sirf `tests/test_jobs.py` mein hai:

- Original five race cases accept only a surfaced `DATABASE_BUSY` cancellation
  failure, wait for both competing workers to finish, prove cancellation was not
  persisted, then make **one** fresh authorized cancellation attempt. Unexpected
  errors still fail. No retry loop, timeout increase or busy-as-success path.
- Two Event-controlled schedules assert native BEGIN error, rollback/close,
  visibility before commit, bounded recovery, durable CANCELLED/cleared lease,
  blocked renewal/advance and idempotent audit count.
- A test connection injects `OperationalError` directly in `connection.commit()`.
  It verifies the still-active transaction is rolled back and closed, row/audit
  remain unchanged, renewal remains valid, and a later explicit cancellation
  succeeds. This is fault injection, not a claim of real disk failure.
- A real held writer blocks synthetic preparation before input reads; failure
  does not report READY, mutate the record/audit or enable execution.

Production database/jobs/session/lifecycle/runner modules, migrations, deadlines,
WAL/checkpoint verification, policy and dependencies unchanged hain. BUSY maps
through JobStore's low-byte SQLite classification to `JOB_DATABASE_BUSY`; no
internal SQL or credentials leave that boundary. JobStore does not automatically
retry cancellation and has no public job-cancellation endpoint. A trusted caller
must retain failure and retry/reconcile within existing authorization/budgets;
the test's recovery is not a newly implemented application retry service.
Existing session revocation reports sanitized HTTP 503 on DB failure and only
returns its deletion receipt/removes the cookie after service success. Failed
persistence is never durable cancellation; an otherwise-valid lease can remain
valid until a cancellation actually commits. Committed cancellation clears the
lease atomically and blocks further renewals/transitions. No real dispatch is
permitted from uncertain authorization; future admission remains an open gate.

Actual executed commands/results:

| Command | Observed result |
| --- | --- |
| `uv run --frozen --no-sync python var/cancellation_probe.py original` | Instrumented original: 1 passed, 0.33s |
| `uv run --frozen --no-sync python var/cancellation_probe.py controlled` | Controlled native traces: 2 passed, 0.90s; diagnostic module subsequently renamed to avoid automatic discovery |
| `uv run --frozen --no-sync python var/repeat_cancellation.py` | 30/30 fresh subprocesses, 5 original race parameters each: 150 passed, 44.94s; unique fresh basetemp per process; stops on any failure |
| `uv run --frozen --no-sync python -m pytest tests/test_jobs.py tests/test_external_intents.py tests/test_sessions.py tests/test_database.py tests/test_retention.py tests/test_lifecycle.py -q -x -rs -p no:cacheprovider --basetemp var/step7ma-related-20261024` | 282 passed, 1 existing warning, 39.61s |
| Focused final pytest node IDs below, `-vv -x -p no:cacheprovider --basetemp var/step7ma-final-focused-20261024` | 9 passed, 1.95s |
| `uv run --frozen --no-sync python -m pytest -q -x -rs -p no:cacheprovider --basetemp var/step7ma-final-full-20261024` | **1083 passed, 1 skipped, 1 warning, 66.37s** |

Focused nodes (same uv/python pytest prefix):
`tests/test_jobs.py::test_cancellation_racing_renewal_is_irreversible`,
`tests/test_jobs.py::test_cancel_renewal_real_busy_schedules_preserve_commit_contract`,
`tests/test_jobs.py::test_cancellation_commit_failure_is_not_durable_success`,
`tests/test_jobs.py::test_busy_preparation_cannot_consume_input_or_report_ready`.

First full discovery run returned 1085 passed / 1 skipped / 1 warning in 64.20s:
it included two ignored temporary diagnostic cases under var/. That diagnostic
module was renamed so it no longer matches pytest discovery; final 1083 is the
repository-suite total after the direct commit-method fault test was verified.
Diagnostics, native traces, repetition helper/results and temp DBs remain ignored,
not proposed checkpoint files. Initial sandbox invocation could not open uv's
existing cache; the test command was rerun with approved required permissions.

Remaining skip: `tests/test_storage.py:176`, OS symlink privilege unavailable.
Mandatory native Linux symlink case must pass without that privilege skip.
Remaining warning: Starlette TestClient's httpx deprecation; no dependency change
was made to hide it. Existing stale owner/epoch, external-intent reconciliation,
session isolation, cleanup rollback/checkpoint and audit tests are in final suite.

Step 7M design review is complete as a **proposal**, not native acceptance:
original PRD hash matches, SEC01-SEC10 budgets and separate service boundaries
remain intact; AM01-AM04 are unapproved, stopped-archive policy unchanged.
Late activation/in-flight dispatch fencing, old authority quiescence, live tmpfs
visibility and independent same-UID-safe collection remain unresolved gates.
Native Linux LSM/seccomp/effective runtime acceptance remains NOT RUN; Desktop
LSM_NOT_ADVERTISED is not waived. No collector/freezer/transport implemented,
no VM provisioned and no Engine call or real container execution performed.

Next recommendation: review an existing native Linux host's read-only evidence
under separate approval, then a separately approved fixed-fixture containment
increment. Dynamic input/collection awaits explicit amendment and native proof.
Final checks executed:

- `uv run --frozen --no-sync python -m compileall -q backend runner tests`:
  exit 0, no syntax errors.
- `git diff --check`: exit 0. Both new documents separately passed untracked
  whitespace checks (`git diff --no-index --check`); Git's LF-to-CRLF notices
  are line-ending conversion notices, not whitespace/test failures.
- Local scope/Markdown/signature audit: six expected paths only, all local links
  and fences valid, zero known secret-signature hits. Production code,
  migrations, dependencies, .gitignore and .env.example match HEAD. .env,
  .env.local and var/ remain ignored; .env.example remains tracked. Signature
  scanning is bounded evidence, not a guarantee against every possible secret.
- Git: four modified paths (README.md, docs/runner-foundation-plan.md,
  docs/runner-secure-transport-design.md, tests/test_jobs.py); two untracked
  documents (this decision and linux-sandbox-acceptance.md); zero staged paths.
  HEAD/origin-main remain `18662e3`. No commit/push/deployment performed.
