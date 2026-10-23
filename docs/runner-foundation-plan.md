# Step 7: restricted sandbox runner foundation

Status: policy, image definition, fixed fixture and unit tests implemented.
Step 7B built and statically inspected the image on Docker Desktop's Linux
backend without starting a container. Step 7C adds an injectable stopped-container
lifecycle adapter tested only against a fake transport. Step 7D adds a read-only
Docker metadata client and typed inspection mapping. No Docker lifecycle transport,
operator execution command, broker or container execution is implemented. Every SEC01-SEC10 runtime control
remains UNVERIFIED. Actual build/inspection evidence and digest distinctions are
recorded in [runner-image-inspection.md](runner-image-inspection.md).
Step 7C states, tests and input-transport blockers are recorded in
[runner-lifecycle.md](runner-lifecycle.md).
Step 7D's actual blocked preflight, metadata rules, image-hardening proposal and
input-transport conflict are recorded in [runner-preflight.md](runner-preflight.md).
Step 7E prepares a two-stage environment-isolating Dockerfile and static tests.
Step 7F built the separate review image and verified its exact image environment,
saved-layer hashes, bootstrap and static runtime dependency files. Neither build
executes the fixture. Step 7G approves that local identity pair for static
selection only, checks the fixed tag for reassignment and rejects old/substituted
images. Current read-only preflight reports only `LSM_NOT_ADVERTISED`; the image
environment matches policy. See [runner-image-environment.md](runner-image-environment.md)
for definition tradeoffs and [runner-image-rebuild.md](runner-image-rebuild.md)
for actual Step 7F evidence, identities, tests and remaining runtime gates.

The [Step 7G record](runner-preflight.md#step-7g-local-static-image-admission)
contains exact identity pins, observations and rejection tests. No locally
reported RepoDigest is promoted to a verified registry digest. Next smallest
proposed increment is a read-only supported Linux-host prerequisite review,
especially effective LSM/profile availability, with execution still disabled.
Input transport and runtime acceptance remain separate blocking work.

Step 7H implements that read-only host assessment with fixed bounded Linux
interfaces and separate AppArmor/SELinux enforcement evidence. Synthetic host
tests pass; real Windows/Desktop preflight still reports `LSM_NOT_ADVERTISED`
and native Linux acceptance is PENDING. No Linux deployment or runtime has been
verified. See [host readiness, Linux commands and checkpoint proposal](runner-host-readiness.md).
The next review is the stopped-input/collector architecture decision and future
native-host evidence, with no automatic VM provisioning or container execution.

Steps 7E-H were checkpointed and pushed as `38ec781`. Step 7I's
[transport design comparison](runner-secure-transport-design.md) recommends bounded
pre-candidate stdin input with a scoped host-side collector only conditionally:
stopped-archive/root-owned-input and quiescence semantics need explicit PRD
amendment approval first. No transport or runtime is implemented or enabled.

Verification on 2026-10-22: the unchanged checkpoint baseline passed 225 tests
(one Windows symlink skip and one existing deprecation warning). The new focused
runner tests passed 99 cases; Docker BuildKit check-only validation had no warnings.
The initial combined suite reported 323 passed, one failed, one skipped and one
warning. Work stopped for review before any further runner implementation.

### Concurrency investigation and regression outcome (2026-10-22)

The original isolated test passed 30 diagnostic runs; tracked connection opens
and closes balanced, with no connections left open. Controlled real WAL reader
contention reproduced the failure: the job remained in `CHECKPOINT`/`RETRY`, with
the next attempt scheduled two controlled seconds later. The old test swept again
without advancing its frozen clock and incorrectly demanded immediate completion.
At the stored due time, one sweep completed with one completion event and an
unchanged deadline. The historical failing run's exact lock holder was not
recorded; this reproduction confirms the incorrect test timing assumption.

Stress testing also exposed native SQLITE_BUSY (5) on the writer path: a waiting
checkpointer can block metadata purge or even persistence of the retry record.
The existing durable retry or 30-second fenced-lease recovery handles those cases.
An initial test revision failed seven of 30 rounds because it assumed only the
checkpoint phase could contend. The final regression observes/re-raises native
errors and permits only the verified SQLITE_BUSY family in this scenario. It
exercises both competing coordinators and a real pinned reader, rejects early
reclaim/completion, advances only to stored retry/lease eligibility, then requires
bounded recovery, final COMPLETE, exactly one completion event/metric, retired
stale ownership and the unchanged five-minute deadline. No backend implementation,
security restriction, busy timeout, attempt budget or deadline was changed.

Final observed verification using uv and Python 3.12.13:

- Repeated isolated regression: 30 fresh processes, two cases each; 60 passed,
  zero failed rounds.
- Related database/lifecycle/retention/storage suite: 122 passed, one skipped,
  one existing warning.
- Complete suite: 325 passed, one skipped, one existing warning in 23.58 seconds.
- Existing runner policy/image suite: 99 passed. Syntax and diff checks passed.

The remaining skip is the Windows file-symlink privilege limitation documented
below; the warning is the existing Starlette/httpx deprecation. No Docker image
was built or run during this investigation. Runtime SEC controls remain
UNVERIFIED despite passing host-side unit tests.

## First increment boundary and evidence

`runner/policy.py` contains frozen, slot-based canonical policy and an exact
fixture request parser. Requests accept only `{"fixture_id":"smoke-v1"}`; unknown
keys, commands, image names, mounts, privilege changes, environment and runtime
overrides are rejected with a sanitized error. Policy fields cannot be passed
to its constructor or replaced through ordinary dataclass operations. The module
does not load `.env`/host settings, import the backend or contact Docker.
Python freezing prevents accidental mutation, not compromise of the trusted
runner process. Operator authentication/OS separation requires the later broker.

Execution is explicitly disabled. No final runner image digest is configured,
and `require_execution_ready()` always raises until an adapter and effective
runtime validation are implemented. There is no new FastAPI endpoint or Docker
access in the web service. Existing backend/configuration/migrations are unchanged.

The Dockerfile uses the official Python 3.12 slim-bookworm base pinned to index
digest `sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70`.
Registry metadata was read on 2026-10-22 and identified Python 3.12.15. This is a
base digest, not a built/approved SheetSafe image digest. No base-image layers or
fixture runtime have been executed by these unit tests. The local project remains
on its existing Python 3.12 environment.

The image definition selects UID/GID 10001, an exec-form Python entrypoint with
isolation/no-site/no-bytecode flags, and a root-owned 0444 fixture. Its tiny build
context excludes everything except the Dockerfile, ignore file and bootstrap.
There is no build argument, remote ADD, installer, RUN command, published port,
volume or caller-selected entrypoint. Step 7B inventoried inherited packages and
environment: shell, pip, Python headers and three public build metadata variables
remain. Hardening, vulnerability review and alignment with the runtime environment
allowlist are pending; the Debian slim base is not a certified final sandbox image.

The fixed fixture has no code dispatch. It refuses unsupported arguments and
checks Linux UID/GID, read-only root, no-new-privileges and effective capabilities
before touching `/work`. It creates a new synthetic marker with no-follow,
exclusive file access and probes only a fixed harmless protected-root filename.
Its stdout explicitly marks runtime verification UNVERIFIED; the future broker
must use external inspection/measurements and verified teardown, not stdout.
Do not invoke this fixture directly on the host. Unit tests exercise dispatch
validation, compile the fixture and inspect the image contract without executing
the smoke payload. BuildKit `docker build --check --network=none runner/image`
completed with no warnings; this check does not build the image or run the payload.

## Approved overall Step 7A design (execution adapter still pending)

Build an operator-only, standalone runner harness for one fixed, reviewed smoke
fixture. Its input selects only an allowlisted fixture ID and opaque job ID; it
cannot accept Python source, shell commands, image names, mounts or runtime flags.
Keep FastAPI and Streamlit without Docker access. A distinct runner identity owns
the runtime connection; an eventual access-controlled local broker will expose a
typed job protocol to the orchestrator, not the daemon socket to the web service.

The first fixture creates a disposable synthetic marker in `/work/output`, checks
that a fixed protected-root write is denied, and exits. An immutable bootstrap is
baked into a minimal Python 3.12 image. Pin the base and final image digests after
actual build/review; do not invent a digest or pull an arbitrary image at job time.
Use Docker CLI argument arrays with `shell=False` and bounded subprocess I/O and
timeouts, avoiding a new SDK dependency unless the transport needs it later.

Create a fresh stopped container; inspect the effective profile before starting
the fixed fixture. Start an external watchdog, collect bounded logs and runtime
measurements, and force-remove the exact container in `finally`. Verify its
absence before issuing a cleanup receipt. A printed success message is not
runtime or teardown evidence. Failed inspection or uncertain removal blocks the
harness; it must never offer a weaker fallback.

Reserve server-generated job labels, policy version, image digest and deadline
for restart discovery. Reap only exact owned container IDs that satisfy the fixed
application/identity labels; never use a global prune or caller-provided target.
Reap at startup and every 30 seconds while the harness runs. Record interrupted
fixed jobs truthfully rather than replaying them as a successful execution.
The smoke job's deadline is bounded even though the full durable worker/lease
integration is deferred. A process crash cannot execute a `finally` block, so
startup recovery and a later independent supervisor are separate requirements.

## Files and remaining increments

| File | Purpose |
| --- | --- |
| `runner/__init__.py` | Implemented: separate package, import has no execution side effects |
| `runner/policy.py` | Implemented: frozen target profile and strict fixture IDs; runtime receipts pending |
| `runner/docker_backend.py` | Implemented: fake-tested stopped create/inspect/remove contract; real transport/start/watchdog/reaper pending |
| `runner/engine_metadata.py` | Implemented: typed Engine/image facts and strict native inspection mapping; fake-tested, not runtime enforcement |
| `runner/preflight.py` | Implemented: fixed read-only local metadata queries; cannot create or execute containers |
| `runner/__main__.py` | Pending: operator-only fixed-fixture command |
| `runner/image/Dockerfile` | Step 7F built and statically inspected the pinned source/scratch definition; Step 7G pins its local identity for static selection only |
| `runner/image/.dockerignore` | Implemented: build context whitelist |
| `runner/image/bootstrap.py` | Implemented: fixed harmless payload; runtime supervision pending |
| `tests/test_runner_policy.py` | Implemented: overrides, immutability, import safety, fail-closed state |
| `tests/test_runner_image.py` | Implemented: static image/context checks and payload dispatch checks |
| `tests/test_runner_lifecycle.py` | Implemented: fake transport, specification, ownership, failure/cancellation and cleanup verification |
| `tests/test_runner_preflight.py` | Implemented: Engine/image prerequisites, native metadata and bounded read-only CLI tests |
| `tests/integration/test_runner_smoke.py` | Pending: real isolated execution and teardown |

Update this plan/README with further actual evidence after implementation. Backend API,
session storage, database migrations and inference configuration need no changes
for the first harness. Add a small image-context `.dockerignore` if required and
build only from `runner/image/`, never the repository or user home directory.
Do not create all files in one unverified change: policy tests first, then fixed
image, then the container lifecycle adapter and its real smoke test.

Step 7B complete-suite verification: 325 passed, one Windows symlink skip and
one existing Starlette/httpx warning in 44.25 seconds. The focused policy/image
suite passed 99 tests in 0.16 seconds. Syntax and diff checks passed. No runtime
payload ran, no runner registry push occurred and policy remains fail-closed
with `execution_enabled=False` and `final_image_digest=None`.

Step 7C now implements that fake-transport slice. Observed verification:
101 new lifecycle tests passed; all runner tests: 200 passed; complete suite:
426 passed, one Windows symlink skip and one existing warning in 22.32 seconds.
No real Docker operation ran. The strict inspection projection rejects unknown
metadata and only verifies modeled configuration, not effective SEC enforcement.
The Step 7B local image identity is fixed inside the job specification; it does
not populate the policy's final registry digest or enable execution.

Step 7D completes that metadata slice: 173 new tests and 373 runner tests passed;
the complete suite passed 599 tests with the existing one Windows skip and one
warning in 23.80 seconds. Read-only local preflight completed with explicit
`LSM_NOT_ADVERTISED` and `IMAGE_ENVIRONMENT_MISMATCH` blockers. API 1.56, Linux/amd64,
cgroup v2 and builtin seccomp are advertised; no effective protection is certified.

Step 7E prepares that definition/static-test slice. The full suite passed 626
tests, with the existing Windows symlink skip and Starlette/httpx warning, in
35.13 seconds. Focused image/policy tests passed 100 cases; preflight/lifecycle
tests passed 300 cases. The environment allowlist, old image identity pins,
bootstrap and LSM prerequisites remain unchanged. Fresh read-only preflight still
reported both blockers during Step 7E; no new image existed at that stage.

Step 7F completed that separate review build and offline inspection, without
container execution: 100 image/policy and 300 preflight/lifecycle tests passed;
the complete suite reported 626 passed, 1 skipped, 1 warning in 24.18 seconds.
Syntax and whitespace checks passed. New image metadata matches the environment
policy; its filesystem/dependency evidence and identity pair are recorded in
[runner-image-rebuild.md](runner-image-rebuild.md). Final read-only preflight
still reported both blockers against the old pin at Step 7F. Step 7G now admits
only the reviewed new local identity for static selection: the current preflight
has no image issues, remains blocked by missing LSM and cannot enable execution.
Select an LSM-capable Linux
verification host separately. Docker-generated process environment, archive
transport and durable lifecycle recovery remain separate gates.

## Mandatory profile: PRD SEC01-SEC10

Every row is required before any untrusted/generated candidate or parser input
is admitted. Step 7A establishes the profile and basic evidence; it does not
certify the entire security acceptance suite.

| PRD | Required control and evidence |
| --- | --- |
| SEC01 | UID/GID 10001, drop all Linux capabilities, no-new-privileges, no privileged mode. Inspect configuration and effective identity/capability state. |
| SEC02 | Network `none`, no published ports, host network, caller DNS configuration or mounted sockets. Later fixed listener/DNS/metadata denial probes use controlled destinations. |
| SEC03 | Read-only root; only bounded `/work` and `/tmp` tmpfs workspaces; no host binds or shared volumes. Set workspace UID/GID explicitly and verify actual writable locations. Runtime pseudo-filesystems also need inspection; a requested read-only flag alone is insufficient. |
| SEC04 | One vCPU quota; 10 CPU seconds per candidate; 1 GiB total memory including tmpfs; memory-plus-swap limit equals memory. Verify cgroups and effective enforcement. CPU quota alone does not enforce total CPU-time budget; aggregate container CPU accounting/watchdog is required, with per-process limits as extra defense. |
| SEC05 | 20-second wall deadline, 32 PIDs, external whole-runtime kill within two further seconds. Cancellation must meet the separate five-second PRD target. |
| SEC06 | `/work` 256 MiB, `/tmp` 64 MiB; collected output 10 MiB/file, 20 MiB total, at most 10 files; stdout/stderr 64 KiB each. Bound collection independently of filesystem capacity and cap Docker daemon logging as well as the host reader. |
| SEC07 | Effective tested seccomp; enforce available AppArmor/SELinux confinement; private PID/IPC namespaces. Start from Docker's reviewed default seccomp profile, record engine/policy versions and denial evidence; never use `unconfined` as a compatibility fix. |
| SEC08 | Explicit environment allowlist, no inherited inference/cloud/session credentials, application DB, host home or Docker socket. Use only synthetic external canaries for tests. |
| SEC09 | A new runtime and fresh writable state for every parse, attempt and validator job. A second fixed job must not see the first marker. |
| SEC10 | Verified teardown on success, exception, cancellation and restart; scoped orphan recovery. Failed removal quarantines the worker and stops admissions. Retain measured receipts, not stdout assertions. |

Read-only root/tmpfs, non-root UID and rootless Docker are different controls.
Rootless or user namespace remapping is defense in depth, subject to tested cgroup
delegation; it must not silently disable memory, swap or PID enforcement.
Tmpfs can reach host swap, so deployment swap policy remains a privacy gate.

## Follow-on slices within Step 7

After the smoke slice passes review, add fixed timeout, bounded allocation/PID,
log/output overflow, network denial, secret-canary, fresh-state and crash/reaper
fixtures. No arbitrary user code or uncontrolled stress fixture is exposed.
Verify the backend is responsive before and after each probe.

Then add the restricted broker protocol, existing durable run leases/cancellation
and the lifecycle runner adapter. Only a verified, matching runtime receipt can
unblock session cleanup. API access must use a local authenticated/OS-controlled
channel and a distinct identity. Do not give FastAPI the Docker socket or group.

Data transport and collector remain separate, blocked increments: selected bytes
must enter a stopped runtime through validated archive transport, never a host
bind mount. Copying into `/work` before startup cannot be assumed to survive its
tmpfs mount. The reviewed Moby archive path also refuses extraction into read-only
rootfs, so moving staging elsewhere is not sufficient by itself. The safe gated
design and unresolved Docker capability are detailed in
[runner-lifecycle.md](runner-lifecycle.md#stopped-container-input-transport-investigation).
Validate members, reject links/devices/traversal, and install root-owned read-only
inputs. Collect bounded allowlisted bytes while the runtime is alive, because
tmpfs does not survive stop; stop candidate descendants before collecting.
Use the existing quarantine registry. Independent validation and verified
teardown remain prerequisites for publication. No spreadsheet parsing is enabled
until these isolation/transport gates pass.

## Windows Desktop versus the Linux Vultr VM

Docker Desktop Linux containers run behind a Linux backend (for example WSL 2 or
Hyper-V); the exact installed backend must be measured. Windows container mode
does not satisfy this Linux policy. Local Docker tests can check lifecycle and
many controls, but cannot certify the target VM's kernel, LSM profiles, cgroup
delegation, swap, daemon permissions or separate service identities.

On the actual Linux VM, repeat the fixed probes, examine effective cgroups and
seccomp/LSM state, test the supervisor/reaper after process death, and record the
image digest, policy version, daemon/kernel versions, limits, observed timings,
cleanup receipts and service health. Check encrypted file/SQLite storage, host
permissions and disabled content snapshots/backups separately. No deployment or
cloud expenditure is authorized by this proposal.

## Required Linux follow-up for the skipped Windows storage test

The Windows Step 6 test
`tests/test_storage.py::test_symlink_read_cleanup_and_ancestor_rejected` skips
when the OS refuses creation of a file symlink. This is a missing local test
capability, not a successful symlink test. Real hardlink and Windows directory
junction rejection were exercised separately.

On native Linux storage outside Windows shared mounts, run:

```bash
uv run --frozen --no-sync python -m pytest -q -rs \
  tests/test_storage.py::test_symlink_read_cleanup_and_ancestor_rejected
uv run --frozen --no-sync python -m pytest -q -rs
```

The first command must **pass without skipping**. Verify linked-file reads and
ancestor traversal are rejected, cleanup remains blocked, and the synthetic
outside target is unchanged. Re-run POSIX no-follow descriptor, flock, fsync,
hardlink, rollback and restart tests on the deployment filesystem. The explicitly
Windows-only junction test may skip on Linux; record platform-specific skips
separately from mandatory Linux coverage. Do not accept a passing Linux-container
probe as proof of the Windows host storage implementation, or vice versa.

## Limits and evidence boundaries

Containers share a kernel and the runtime broker holds substantial authority.
Pinned images require scanning/review and updates require replaying acceptance
tests. A blocked Docker daemon can prevent timely forced removal; failed cleanup
must remain visible and stop admissions. A smoke fixture passing is not proof
that all SEC/SC gates passed, that arbitrary code is safe, or that results are
numerically correct. Real uploads and all inference remain disabled; no key or
placeholder inference success is needed for Step 7.

Official Docker references checked for this proposal:

- [Engine trust boundaries](https://docs.docker.com/engine/security/)
- [Memory, swap and CPU controls](https://docs.docker.com/engine/containers/resource_constraints/)
- [Default seccomp behavior](https://docs.docker.com/engine/security/seccomp/)
- [Tmpfs behavior and swap caveat](https://docs.docker.com/engine/storage/tmpfs/)
- [Windows Desktop Linux backends](https://docs.docker.com/desktop/setup/install/windows-install/)
- [Rootless prerequisites](https://docs.docker.com/engine/security/rootless/)
