# Native Linux sandbox acceptance — Step 7M plan

Date 2026-10-24. **PLAN / NOT RUN**. Is file se VM provisioning, package install,
Docker settings, image load ya container execution approved nahi hoti. Current
Windows client par koi native evidence collect nahi ki gayi. All SEC01-SEC10
runtime results abhi UNVERIFIED hain. Admission/amendment decision:
[runner-admission-decision.md](runner-admission-decision.md).

## 1. Host aur capacity proposal

Recommended baseline: patched **Ubuntu Server 24.04 LTS x86_64**, native host aur
local Docker CE, AppArmor enforcing, systemd-managed cgroup v2, runc. Docker's
[supported Ubuntu list](https://docs.docker.com/engine/install/ubuntu/) currently
includes 24.04 LTS; newest distribution choose karna zaroori nahi. Ubuntu 26.04
could be a separate reviewed choice, not automatic migration. No Docker Desktop,
WSL client or remote context ko native daemon-host acceptance samjhein.

PRD p9 se initial sizing: **4 vCPU, 8 GiB RAM**. Proposed storage minimum **40 GiB
SSD, >=20 GiB free** after OS/image; **host swap disabled**, no content snapshots/
backups or core dumps. Yeh design capacity assumptions hain, measured guarantee
ya Vultr plan/price nahi. Maximum two one-vCPU/1-GiB jobs ke saath API, broker,
collector buffers aur OS headroom measure karein; CPU/memory/disk pressure par
admissions stop. No GPU required; inference is serverless, not a local model.
Smaller host ya swap exception needs separate privacy/limit review. Private data
requires encrypted local storage and keys outside guest; synthetic default stays.

Engine configuration: pin a supported, security-reviewed stable Linux package
revision exposing API 1.56 and compatible with current strict metadata mapping.
Record Engine/containerd/runc/kernel builds and their source revisions; do not
install latest blindly or assume the Desktop build is a native package pin.
Unix socket only, no unauthenticated TCP listener; no automatic container restart,
swarm scheduling or alternate path to start/exec. Keep builtin seccomp and an
enforcing reviewed AppArmor profile. Existing SELinux-only mapping stays blocked
until separately implemented/tested; global enforcing mode is not a waiver.
No daemon/user-group/profile changes are made by this plan.

## 2. Operator evidence package

Use an existing disposable host, reviewed checkout, Python 3.12 and frozen uv
environment prepared under separate approval. Reserve an unused ignored var/
directory for evidence; pytest basetemp must never point at user data or an old
artifact directory. Every record contains build/commit, UTC time, host fingerprint,
operator identity, policy/image identities, fixture version, expected/actual
result and exit status. Raw host details stay restricted and out of Git; no keys,
session credentials, uploads, environment dumps or process command-line dumps.
Unknown/denied/malformed evidence is BLOCKED, never an inferred pass.

Phase A — read-only host checks (future native host; not run here):

```bash
uname -srmo
cat /etc/os-release
uv run --frozen --no-sync python --version
timeout 10s docker context inspect default --format '{{json .Endpoints.docker}}'
timeout 10s docker --context default version --format '{{json .}}'
timeout 10s docker --context default info --format '{{json .}}'
findmnt -n -o TARGET,FSTYPE,OPTIONS /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/kernel/security/lsm
cat /sys/module/apparmor/parameters/enabled
aa-status
cat /proc/swaps
df -h /
id sheetsafe-api
id sheetsafe-ui
id sheetsafe-runner
id sheetsafe-validator
getent group docker
stat -c '%F %U %G %a %n' /var/run/docker.sock /var/lib/sheetsafe/api /var/lib/sheetsafe/runner
```

Also review socket ACLs, live supplementary groups/capabilities, service units,
sudo rights, parent-directory traversal, mount/encryption configuration and
daemon endpoints. Missing accounts/tools/permissions are unmet prerequisites;
do not create accounts or weaken permissions to make the probe green. Native
operator must prove host/daemon co-location, not merely matching kernel strings.

Current existing read-only probe and storage tests:

```bash
timeout 60s uv run --frozen --no-sync python -m runner.host_readiness --context default
uv run --frozen --no-sync python -m pytest tests/test_host_readiness.py -q -rs -p no:cacheprovider
uv run --frozen --no-sync python -m pytest tests/test_storage.py::test_symlink_read_cleanup_and_ancestor_rejected -q -rs -p no:cacheprovider
uv run --frozen --no-sync python -m pytest tests/test_storage.py -q -rs -p no:cacheprovider
```

Host probe intentionally exits **2** because it cannot grant native execution
acceptance. Inspect its structured checks; exit 2 is not a runtime pass, timeout
124/traceback is not success. The mandatory symlink test must execute and pass
on Linux with **zero privilege skip**. It verifies outside canary preservation
and rejects linked storage ancestors. Other platform-specific skips, if any,
must be individually recorded, never hidden with no-skip summary wording.

AppArmor pass requires loaded/enforcing intended rules plus later actual task
attachment, not merely a profile name. [Docker AppArmor](https://docs.docker.com/engine/security/apparmor/)
distinguishes container profile from daemon confinement. Seccomp needs compiled
kernel/runtime support and later effective filter/denial evidence; an advertised
option alone is insufficient. Keep default filtering; no unconfined override.
[Docker seccomp reference](https://docs.docker.com/engine/security/seccomp/).

The worker's actual cgroup subtree must expose and enforce cpu/memory/pids;
root controller names alone do not prove delegation or limits. Swap control is
part of memory, not a separate controller name. Do not guess child cgroup paths
from a guest label. Bind them using native runtime identity before later reads.
[Kernel cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html).

## 3. Service and image acceptance

| Identity | Required boundary |
| --- | --- |
| API | Non-root private metadata/storage access; no daemon group/socket, broker administration or inference key from guest |
| UI | Authenticated API only; no app DB/private files, daemon or provider key |
| Orchestrator/provider client | Server-held inference key only under separate service policy; no raw workbook prompt, no direct daemon |
| Runner admission broker | Sole application daemon authority, typed authenticated local channel, dedicated private state, bounded allowlist; rootful socket access remains high host privilege |
| Validator | Fresh reviewed validation jobs through broker; no direct daemon privilege or generated validator logic |
| Candidate | UID/GID 10001 inside fresh sandbox; no host service identity, secrets, runtime socket or host mounts |

Host service UIDs must differ from each other and from guest 10001. Check actual
credentials/ACLs, not only /etc/group. API/UI must be unable to open any runtime
socket or broker administration path under their real service credentials.
Broker crash/startup defaults closed; native takeover/late-action fencing is
still a separate release gate. No competing authority gains a socket on expiry.

Phase B — image transfer/load needs separate operator approval. Use only a
reviewed offline archive from Step 7F, with recorded archive checksum and safe
provenance; never export a user-specific container. Archive checksum is not the
image ID. After approved loading, use existing static preflight to compare:

- local reviewed identity:
  `sha256:551ae45bad03b4a1856ae503c62c01a8078394a19d3c318b53fc9f2e98f66bc9`;
- separate config digest:
  `sha256:59f66d35ff913f60851bde600c75680bc0054c04f32ba72ec42ca2ae2ec6d546`;
- linux/amd64, user 10001:10001, fixed entrypoint, smoke-v1-only command,
  minimal reviewed environment, no unexpected volumes/healthcheck/assets;
- fixed diagnostic tag resolves to the same identity; no pull/fallback.

Native classic/containerd image stores may expose identity differently. Missing
descriptor/config annotations or changed local identity is a blocker, not a
reason to substitute a config digest or invent a RepoDigest. Any representation
adaptation needs explicit code review/tests. Current final image policy remains
execution-unapproved even if static identity matches.

## 4. Phase C — separately approved fixed-fixture containment

No runnable native execution CLI exists yet; do not invent a command or bypass
require_execution_ready(). After host evidence is reviewed, implement one small
operator-only fixed smoke adapter under explicit approval. It must persist its
resource identity, enforce policy, use a watchdog and verify teardown. First
experiment has no dynamic inputs, generated code, private uploads or artifact
publication. Its untrusted log line is not containment evidence. This makes
real progress without requiring the production stdin/collector amendment first.

Broader containment fixtures below are future reviewed fixed code, not arbitrary
caller Python or a permission to run stress probes now. Use a disposable host,
bounded fixture sizes and external host-health supervision. No network capability
is added for a test: an operator-owned known reachable destination is probed from
inside network-none, with availability confirmed outside the guest.

| Control | Exact required evidence / pass criterion | Fail/block criterion |
| --- | --- | --- |
| SEC01 | Native task UID/GID=10001, effective capabilities=0, NNP=1, privileged=false; inspect plus fixed denial probes | Root/extra caps, wrong UID, missing NNP or requested-only proof |
| SEC02 | Network none, no ports/host networking/DNS/socket mounts; known reachable external destination and metadata endpoints unreachable from fixture | Unexpected interface route/socket access, successful reachability, or unavailable outside control probe making result inconclusive |
| SEC03 | Read-only root; only /work 256 MiB and /tmp 64 MiB writable tmpfs; no bind/shared mounts; protected-root writes denied and permitted tmpfs writes succeed | Extra writable mount, hidden host data, unbounded tmpfs or inability to prove actual mount identity |
| SEC04 | cpu.max equivalent to 1 vCPU; memory.max=1 GiB and memory.swap.max=0; include tmpfs/input memory. Independent CPU accounting kills candidate by 10 cumulative CPU seconds; bounded allocation fixture cannot pressure host | Quota mistaken for total CPU budget, ignored limit, accounting gap, host OOM/pressure or swap leakage |
| SEC05 | pids.max=32 including supervisor; <=20s candidate wall deadline, whole runtime/descendants gone <=2s after deadline; cancellation <=5s. Independent watchdog records monotonic timestamps | Leader-only kill, surviving descendant, delayed kill, non-independent timer or silent deadline extension |
| SEC06 | Enforce /work 256 MiB, /tmp 64 MiB; <=10 artifacts, <=10 MiB each, <=20 MiB total during collection; separate logs <=64 KiB/stream with explicit overflow event | Overflow accepted, unbounded buffering, special/sparse entries bypass, or truncation silently treated as a valid result |
| SEC07 | Actual task seccomp filtering plus syscall denial fixture; intended enforcing AppArmor attachment/rules; private PID/IPC namespaces; approved fixed Python still works | unconfined/complain, advertisement-only proof, shared host namespace or forbidden operation succeeds |
| SEC08 | Exact minimal environment, closed unrelated FDs; no DB, tokens, provider/cloud keys, host files or daemon socket. Outside synthetic secret canary remains inaccessible | Any canary value/secret path exposed, inherited ambient environment/FD, or missing negative probe |
| SEC09 | New native runtime ID and empty writable state per parse/attempt/validator; second fixed job cannot read previous marker | Reused runtime/tmpfs, cached private data or shared writable volume |
| SEC10 | Success/error/cancel/watchdog/broker crash/daemon loss/restart tests preserve ledger; exact owned runtimes/tasks/FDs/app copies absent before completion; independent scoped inventory and healthy host recorded | Remove ack/404 alone, unresolved in-flight action, false COMPLETE, unsafe foreign deletion, reaper absent or cleanup uncertainty discarded |

CPU quota limits rate, not total CPU time: the watchdog must measure both.
No delayed collection may extend candidate/run deadlines. Limits should be
observed at boundaries and boundary+1, with host headroom measured before/after.
[Docker resource controls](https://docs.docker.com/engine/containers/resource_constraints/).
SEC06 artifact collection and SEC10 general late-dispatch recovery cannot be
certified by the first smoke alone. Mark partial evidence explicitly, not PASS.

## 5. Phase D — quiescence/transport/restart experiments

Only after architecture approval, use matching-build native tests for:

1. Read-only-root archive write checks and actual live /work visibility, without
   relaxing policy. A successful cp command is not proof it reached runtime tmpfs.
2. Pre-start attach/half-close, bounded framing/backpressure and sealed-input
   tampering/accounting; no candidate before validated immutable input/admission.
3. Controlled worker/broker stalls before send/start/GO, expiry/cancellation at
   every boundary, old incarnation resuming, DB outage and late Engine responses.
   Prove activation-side fencing or retain dynamic execution HOLD.
4. Freeze request and separately observed kernel frozen state on the exact
   intended hierarchy; deny migration/unfreeze by guest. Killing must verify
   descendant absence, not just one PID. No freeze-to-collect assumption from
   Docker pause response. Evidence stays independent of guest output.
5. Collector target pinning, live tmpfs visibility, symlink/hardlink/path/mount/PID
   reuse canaries, entry/byte overflow and crash-held FD cleanup. Privileges must
   be measured/minimized; no generic root namespace/host path RPC.
6. Lost create/remove replies, same-name foreign resource, scoped restart reaper,
   late resource appearance after negative lookup and watchdog loss. No global
   prune or automatic re-execution. Unknown state quarantines worker/admissions.

Container teardown receipt must bind operation, native ID, job/fence and image,
plus authority-quiescence and independently checked tasks/resources/inventory.
Close pinned FDs before ephemeral-data cleanup can be confirmed. Minimal audit
can remain for 24 hours; detailed private records follow one-hour/5-minute policy.
Forensic/retention target misses must be visible, never relabeled successful.

## 6. Desktop versus native Linux

| Current Windows/Desktop | Requires actual Linux daemon host |
| --- | --- |
| Existing Python/SQLite/fake tests, syntax, docs, approved image static review | Host identities/socket DAC+ACLs, encryption, actual LSM rules/attachment, kernel/namespace/cgroup identities |
| Historical image/preflight observations, not rerun in 7M | Deployed Engine/API/source match, image-store compatibility, effective limits and denial probes |
| Symlink fixture currently skipped for OS privilege | Mandatory symlink fixture without that skip; namespace/mount/PID/freeze/collector evidence |
| No claimed real lifecycle or containment evidence | Fixed-fixture execution, watchdog/CPU budget, crash/late-start/reaper and verified teardown campaign |

Read-only host facts never enable execution automatically. Unknown/missing evidence
is a stop, with no LSM bypass. Acceptance signer records each SEC result and
remaining limits; a failed P0 fixture stops release. No VM provisioned, no credits
spent and no synthetic test receipt presented as native acceptance in Step 7M.
