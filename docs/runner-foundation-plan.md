# Step 7 proposal: restricted sandbox runner foundation

Status: proposal for approval, not implemented. No Docker image, runner process,
container execution, upload parsing or inference is added by this review.

## Smallest next implementation: Step 7A

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

## Proposed files (create incrementally after approval)

| File | Purpose |
| --- | --- |
| `runner/__init__.py` | Separate runner package |
| `runner/policy.py` | Frozen security profile, fixture IDs and typed receipt |
| `runner/docker_backend.py` | Create/inspect/start/watchdog/remove/reaper; no general command interface |
| `runner/__main__.py` | Operator-only fixed-fixture command |
| `runner/image/Dockerfile` | Minimal, reviewed Python image and non-root identity |
| `runner/image/bootstrap.py` | Immutable fixed smoke fixture and supervision |
| `tests/test_runner_policy.py` | Reject overrides and invalid targets; failure-path tests |
| `tests/integration/test_runner_smoke.py` | Explicitly invoked real Docker smoke and verified teardown |

Update this plan/README with actual evidence after implementation. Backend API,
session storage, database migrations and inference configuration need no changes
for the first harness. Add a small image-context `.dockerignore` if required and
build only from `runner/image/`, never the repository or user home directory.
Do not create all files in one unverified change: policy tests first, then fixed
image, then the container lifecycle adapter and its real smoke test.

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

Data transport and collector remain separate increments: selected bytes enter a
stopped container through validated archive transport, never a host bind mount.
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
