# Step 7H: read-only Linux host security readiness

Implemented and observed on 2026-10-23 at HEAD `169effb`, preserving uncommitted
Steps 7E-G. This is operator evidence collection, not execution admission. No
Linux distribution, VM, service account, profile or container was created; no
Docker/system configuration, permissions or execution gate changed. No new
dependencies, inference credentials, commit or push.

## Architecture and evidence boundaries

`runner/host_readiness.py` combines the existing read-only Engine preflight with
a fixed-path `LocalHostReader`. Frozen reports contain bounded kernel facts,
named check states, scoped AppArmor/SELinux classifications and the unchanged
preflight result. All SEC01-SEC10 controls remain UNVERIFIED. `execution_enabled`
is always false and `native_linux_acceptance` is always PENDING in this milestone.
Even complete host observations cannot authorize runtime execution.

The CLI accepts only the existing context enum (`default` or `desktop-linux`),
not commands, paths, identities, image names or policy overrides. On non-Linux
clients it makes no Linux filesystem, identity or namespace observations. Docker
may describe a different Linux backend; that is reported separately from the
client OS. No installed WSL distribution or remote host is entered automatically.

Linux files are limited to fixed `/proc`, `/sys`, local passwd/group and proposed
service storage/socket paths. Text reads use O_RDONLY/O_NOFOLLOW/O_NONBLOCK,
require a regular file, close descriptors and cap each result at 256 KiB. A
large profiles/account listing fails unknown rather than truncating into success.
Invalid UTF-8, unreadable evidence and malformed values are unknown; permission
denial is never proof of absence. Only fixed namespace links are inspected.
Nothing reads `/etc/shadow`, environment secrets, policy binaries or dataset
contents. Metadata checks use stat without following the final symlink.
The host reader launches no subprocesses. Existing Docker CLI calls retain
bounded time/output, argument arrays and a minimal environment; no lifecycle API
is added. An external timeout is recommended for native Linux collection because
kernel/filesystem stalls cannot be given an absolute Python-level deadline.

| Area | Collected observation | Still pending |
| --- | --- | --- |
| Kernel/architecture | Local kernel release and x86_64/amd64; sanitized daemon kernel separately | Supported deployment host, patch posture, actual co-location |
| Cgroup v2 | Fixed cgroup.controllers readability and cpu/memory/pids names; Engine support flags | Correct worker subtree/delegation and effective limits |
| Swap | Host swap inventory, optional root memory.swap.max interface, Engine SwapLimit | Target child-cgroup swap enforcement and tmpfs privacy |
| LSM | Active LSM list, AppArmor enable flag/profile mode; SELinux enforce flag/policy-node metadata | Actual container confinement, profile content/policy review |
| Seccomp | Existing Engine builtin-default advertisement and mandatory blocker | Kernel/OCI effective filter and denial probes |
| Namespaces | Fixed pid/net/mnt/ipc/uts/user/cgroup namespace links | Fresh, effective container namespaces and host distinction |
| Identities/storage | Local named accounts, UID separation, rootful socket DAC, storage leaf owner/mode | NSS/ACLs/capabilities/live groups, ancestors, encryption/mount options |
| Monitoring/cleanup | Readability of root accounting interfaces, optional cgroup.kill metadata, Python pidfd API presence | Real child-cgroup interfaces, syscall capability, watchdog/CPU budget, durable reaper/teardown |

There is no separate cgroup v2 `swap` controller name: swap controls belong to
the memory controller. `memory.swap.max`, pids.current, memory.events and
cgroup.kill are not all available at the hierarchy root; absence there is not
proof that child-cgroup support is missing. These observations remain unknown or
pending until the worker scope exists. Presence of a Python pidfd API is not a
successful pidfd/kill test. No signals or resource-limit changes are made.
See the [kernel cgroup v2 interfaces](https://docs.kernel.org/admin-guide/cgroup-v2.html).

Matching kernel strings is only a consistency hint. A client inside a container,
WSL or another namespace can share that string without being the daemon host.
`HOST_DAEMON_COLOCATION_REVIEW` is always pending. Collection must later occur on
the actual supported native host under a reviewed operator identity.

## LSM classification

| Classification | Meaning |
| --- | --- |
| AVAILABLE_AND_ENFORCING | AppArmor: active list includes apparmor, enable flag Y, exactly one docker-default (enforce), no conflicting mode. SELinux: active list includes selinux, enforce=1 and policy-node metadata present; **global mode only**, intended container domain still pending. |
| SUPPORTED_BUT_NOT_ENFORCING | Explicit disabled/permissive flag, or enabled AppArmor with a readable profile list lacking the intended enforcing profile (including complain mode). |
| NOT_ADVERTISED | Engine does not advertise the LSM and the local platform cannot provide native evidence. This describes advertisement, not kernel compilation. |
| UNSUPPORTED | A readable active-LSM list excludes that framework for this boot, without contradictory Engine advertisement. This does not prove build-time support is absent. |
| UNKNOWN_OR_UNVERIFIED | Missing, denied, malformed, contradictory or incomplete evidence. Docker advertisement alone cannot attest enforcement. |

`docker_advertised`, `enforcement_scope` and `intended_profile` are separate
fields. Global SELinux enforcing mode does not prove an enforcing container type
or domain; current native mapping remains AppArmor-specific and still reports
`LSM_MAPPING_UNSUPPORTED` on SELinux-only hosts. No automatic SELinux fallback or
LSM exemption is introduced. A host-level AppArmor observation also cannot clear
an existing `LSM_NOT_ADVERTISED` Engine blocker.

The intended AppArmor profile can be absent before Docker has loaded it; the
probe reports the missing evidence and never starts a container or loads a
profile to make the check pass. A name in the profiles list does not prove its
rules are adequate or that the future runtime attaches it. See
[Docker AppArmor profile behavior](https://docs.docker.com/engine/security/apparmor/),
[Docker seccomp prerequisites](https://docs.docker.com/engine/security/seccomp/) and
[libselinux's read-only enforce query](https://github.com/SELinuxProject/selinux/blob/main/libselinux/src/getenforce.c).

## Proposed Linux privilege separation (not configured)

| Identity | Proposed access |
| --- | --- |
| sheetsafe-api | FastAPI, its own private metadata/storage only; no Docker socket/group, runner internals or administrative capabilities |
| sheetsafe-ui | Streamlit; authenticated application API only; no Docker socket/group, application DB or direct private dataset storage |
| sheetsafe-runner | Separate trusted operator/broker service; narrowly authenticated broker channel and dedicated runner state; sole application identity allowed to control the daemon |
| sheetsafe-validator | Independent validator service; only scoped inputs/quarantined results and authenticated broker requests when needed; no direct daemon access |
| Docker daemon | Separate protected rootful daemon identity for the initial inspected layout; Unix socket only, no unauthenticated TCP exposure |
| Sandbox candidate | Fixed UID/GID 10001 inside each isolated runtime; no socket, host mounts, host service permissions or inference keys |

Host service UIDs must be distinct, non-root and different from container UID
10001. The probe checks local accounts only, not a live service credential audit.
Proposed fixed leaves `/var/lib/sheetsafe/api` and `/var/lib/sheetsafe/runner`
must be owned by their service, mode 0700, under separately reviewed ancestors.
These are proposed deployment roots, not changes to current backend configuration.

For the initial rootful layout, `/var/run/docker.sock` must be a root-owned socket
without other-user permissions. Only the broker may obtain DAC write access;
API/UI/validator accounts must not gain it through primary/supplementary groups
or privileged groups. The probe checks these local DAC hints. ACLs, NSS, existing
process groups, service unit capabilities, sudo rules, socket activation, alternate
endpoints and parent-directory access remain explicit review gates. Permission
failures are unknown; the probe does not request sudo or change membership.
Rootless/custom socket layouts need a separate reviewed access/delegation mapping;
the fixed rootful DAC probe cannot certify them automatically.

Daemon access is a high-privilege capability even for a non-root broker account;
it can permit operations with host-level consequences. Service separation needs
OS permissions and a narrow broker protocol, not only Python imports. API/UI
code does not import the Docker client or lifecycle adapter; existing backend
cleanup hooks remain protocols, not daemon clients. See
[Docker daemon trust boundary](https://docs.docker.com/engine/security/).

## Actual Windows/Docker Desktop observation

```powershell
uv run --frozen --no-sync python -m runner.host_readiness --context desktop-linux
```

The CLI deliberately exits **2** for pending acceptance. Exact native exit 2 was
also captured with `$LASTEXITCODE`; collection completed normally. A generic
PowerShell wrapper may map a nonzero native result to 1, so do not read that as
a passing readiness status. Sanitized evidence is under ignored
`var/step7h-host-readiness.json`.

- Client: Windows/AMD64; native Linux kernel/identity/profile checks not performed.
- Daemon-reported kernel: `6.18.54.1-microsoft-standard-WSL2`.
- Engine 29.9.1/API 1.56, Linux x86_64, cgroup v2/cgroupfs; builtin seccomp and
  memory/swap/CPU/PID support advertised, not effectively tested.
- AppArmor and SELinux: NOT_ADVERTISED; intended profiles PENDING.
- Image/tag verification passes with the Step 7G pinned identity; no image issues.
- Current preflight blocker: `LSM_NOT_ADVERTISED`. Execution false; native Linux
  acceptance PENDING; all ten SEC controls UNVERIFIED.

No supported native Linux daemon host was supplied/verified. Desktop/WSL evidence
does not certify a Vultr host. No distribution installation, WSL entry, VM
provisioning, service restart, profile loading, chmod or Docker setting change.

## Exact future Linux commands and acceptance criteria

Use a separately reviewed existing native Linux host and prepared Python 3.12/uv
checkout, under the intended runner operator identity. The local context must
point to that host's reviewed Unix socket. The exact reviewed image/descriptor
schema and diagnostic tag must already be present via a separately approved
transfer/review; absence or a different local image representation stays blocked.
No tag or image substitution is approved by these commands.

```bash
timeout 60s uv run --frozen --no-sync python -m runner.host_readiness --context default
uv run --frozen --no-sync python -m pytest -q -rs tests/test_host_readiness.py
uv run --frozen --no-sync python -m pytest -q -rs tests/test_storage.py::test_symlink_read_cleanup_and_ancestor_rejected
uv run --frozen --no-sync python -m pytest -q -rs
```

Probe exit 2 remains expected until separate effective acceptance work is done;
timeout 124, a traceback, communication failure or unknown evidence is not a pass.
Operators must review the structured checks, not only an exit code. There is no
`--allow-unverified`/`--force` flag. These commands do not install dependencies,
provision a host, mutate configuration or run real containers.

Required evidence before requesting any runtime experiment:

1. Native x86_64 Linux host/daemon co-location and supported Engine/API/schema;
   image/config pins and tag consistency verified without pulling/fallback.
2. Cgroup v2 cpu/memory/pids and target delegation, memory/swap controls and
   accounting capabilities reviewed; no hidden rootless limit degradation.
3. AppArmor docker-default loaded/enforcing with reviewed rules and Docker
   advertisement; SELinux-only support needs separate native mapper approval.
   Unknown or missing evidence remains blocking, never an automatic profile load.
4. Namespace and seccomp prerequisites, reviewed root/socket/service identity
   permissions, no web-service daemon access or exposed daemon endpoint.
5. Storage ancestors/ACLs, encryption, swap, no content backups/snapshots and
   separate service identities reviewed. Symlink test must pass **without skip**
   on native Linux storage; repeat POSIX no-follow/flock/fsync/recovery coverage.
6. Watchdog/cancellation/CPU accounting, scoped durable orphan cleanup and bounded
   input/artifact design implemented and reviewed before claiming effective
   SEC01-SEC10 acceptance. Probe observations are not those runtime proofs.

Potential later Vultr blockers include missing LSM/profile access, unsupported
daemon identity schema, unavailable reviewed image, incompatible cgroup/swap
delegation, absent service identities/storage controls, and the still-unimplemented
broker/watchdog/reaper. None is bypassed by this milestone.

## Verification and known test setup issue

```powershell
uv run --frozen --no-sync python -m pytest tests/test_host_readiness.py -q -p no:cacheprovider
# 64 passed in 0.21s
uv run --frozen --no-sync python -m pytest tests/test_host_readiness.py tests/test_runner_policy.py tests/test_runner_image.py tests/test_runner_preflight.py tests/test_runner_lifecycle.py -q -p no:cacheprovider
# 520 passed in 0.97s
uv run --frozen --no-sync python -m pytest -q -rs -p no:cacheprovider --basetemp var/step7h-tests-20261023
# 746 passed, 1 skipped, 1 warning in 33.01s
uv run --frozen --no-sync python -m compileall -q backend runner tests
# exit 0
git diff --check
# exit 0
```

The first new-test run reported 63 passed and two setup/teardown errors for one
oversized-input case: pytest embedded the 256 KiB payload in its auto-generated
test name, exceeding Windows' 32767-character environment-variable limit.
Detailed short-trace reproduction confirmed this before the test body ran.
Explicit short parameter IDs fixed only the test label; payload and assertions
are unchanged. The corrected focused and full runs above passed. No existing
test failed. Diagnostics are ignored under `var/`.

The skip remains `tests/test_storage.py:176` (Windows file-symlink creation
privilege); real Windows junction/hardlink tests pass. The warning remains
Starlette TestClient/httpx deprecation. Git LF/CRLF advisories are separate.

## Proposed Steps 7E-H checkpoint (not staged)

Proposed message:
`feat: harden runner image admission and assess Linux host readiness`

Exact proposed source/test/documentation list:

```text
README.md
docs/runner-foundation-plan.md
docs/runner-host-readiness.md
docs/runner-image-environment.md
docs/runner-image-inspection.md
docs/runner-image-rebuild.md
docs/runner-lifecycle.md
docs/runner-preflight.md
runner/docker_backend.py
runner/engine_metadata.py
runner/host_readiness.py
runner/image/Dockerfile
runner/policy.py
runner/preflight.py
tests/test_host_readiness.py
tests/test_runner_image.py
tests/test_runner_lifecycle.py
tests/test_runner_preflight.py
```

This includes environment-isolating build definitions/static evidence, reviewed
local selection pins and negative tests, plus the new host-only assessment.
Published migrations, backend/authentication, dependencies and bootstrap are
unchanged. The Step 7H changes are the new host module/tests/guide and README,
runner-plan/preflight documentation updates; earlier work remains preserved.
Review covers tracked diffs and all untracked candidates. No deletion/rename or
unrelated overwrite is proposed. Archives, raw reports, diagnostic logs, SQLite,
uploads, caches, virtual environments and secret env files are excluded by Git
ignores. `.env`/`.env.local` remain ignored; `.env.example` stays tracked. Secret
signature checks are heuristic, not proof that arbitrary secrets cannot exist.
Nothing is staged, committed or pushed; obtain separate approval for checkpoint.

Final observed inventory: **13 modified tracked files and 5 untracked candidates**,
exactly the 18 paths above; staged files 0, deletion/rename entries 0, credential
signature hits 0. The read-only audit scanned tracked files and all untracked
candidates, checked unchanged backend/dependency/migration paths, and checked
whitespace in all five untracked files. It exited 0:

```powershell
uv run --frozen --no-sync python var/step7h-checkpoint-review.py
```

The audit helper and JSON evidence are ignored local artifacts, not staging
candidates. HEAD remains `169effb`.

## Next smallest transport decision

Keep stopped-container input, read-only root and bounded tmpfs as required. The
current Docker archive path cannot safely be assumed to populate a read-only
root, and pre-start `/work` contents are hidden by tmpfs. Do not relax rootfs,
mount host paths, bake private data into images or switch to post-start uploads.

Next review should compare the existing stopped OCI/snapshot preparation proposal
with PRD constraints, define the privileged broker boundary and choose an approved
transport before implementing a driver. A bounded archive parser can then be
tested with synthetic bytes independently of Docker: fixed relative targets,
member/byte limits, no traversal, links, special files, duplicate or sparse
entries, and verified hashes. Parser success alone cannot resolve transport.
Artifacts require a separate trusted, bounded pre-stop collector after externally
verified candidate quiescence; tmpfs data cannot be assumed to survive stop.
See [the unresolved transport design](runner-preflight.md#input-and-artifact-transport-unresolved-compatibility-gate).
