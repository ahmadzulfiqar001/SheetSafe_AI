# SheetSafe AI — Native Linux Sandbox Acceptance Checklist (SEC01–SEC10)

This checklist provides the exact operational verification steps required before deploying SheetSafe AI on native Linux and unlocking untrusted spreadsheet parsing and sandboxed code execution.

---

## 1. Prerequisites (Host Environment)
- **Target OS**: Ubuntu 24.04 LTS (Noble Numbat) or Debian 12 (Bookworm) 64-bit x86_64.
- **Kernel Version**: Linux Kernel >= 6.8 with unprivileged user namespace support.
- **Container Engine**: Docker Engine 27+ or containerd (Native Linux runtime; **Docker Desktop on Windows/Mac is strictly prohibited** due to `LSM_NOT_ADVERTISED`).

---

## 2. SEC01–SEC10 Verification Matrix

| Gate ID | Security Constraint | Repository Policy Reference | Verification Command / Target | Pass Criteria |
| :--- | :--- | :--- | :--- | :--- |
| **SEC01** | **Cgroups v2 Active** | `runner/host_readiness.py` | `cat /sys/fs/cgroup/cgroup.controllers` | Must list `cpu`, `memory`, `pids`. Legacy Cgroups v1 fails closed. |
| **SEC02** | **Native Linux Engine** | `runner/engine_metadata.py` | `docker info --format '{{.OSType}} / {{.OperatingSystem}}'` | Must report `linux` on native Linux host (not WSL2 or hypervisor emulation). |
| **SEC03** | **LSM Advertised & Enforced** | `runner/policy.py` (`require_available_lsm=True`) | `apparmor_status` & `docker info --format '{{.SecurityOptions}}'` | Must list `name=apparmor`. Container AppArmor profile must be `docker-default` (or host-loaded `sheetsafe-runner` in enforce mode). Unconfined execution or unapproved profiles are strictly forbidden. |
| **SEC04** | **Non-Root Guest & User Namespace** | `runner/policy.py` (`uid=10001, gid=10001`) | `docker inspect --format '{{.Config.User}}'` & `{{.SecurityOptions}}` | Container user is explicitly `10001:10001` (`sheetsafe-runner`). In rootless / userns setups, maps to unprivileged host subordinate UID (`subuid`/`subgid`). |
| **SEC05** | **Strict Network Isolation** | `runner/policy.py` (`network_mode="none"`) | `docker run --network none ...` | Container network namespace has loopback `lo` down or no external routing. |
| **SEC06** | **Read-Only Root Filesystem** | `runner/policy.py` (`read_only_root=True`) | `docker run --read-only ...` | Host filesystem write attempts fail with `Read-only file system` (EROFS). |
| **SEC07** | **Dropped Capabilities** | `runner/policy.py` (`cap_drop=("ALL",)`) | `capsh --print` inside container | Zero effective or permitted capabilities. `no_new_privileges=True` enforced. |
| **SEC08** | **Strict Resource Quotas** | `runner/policy.py` | `--memory=1073741824 --memory-swap=1073741824 --pids-limit=32 --cpus=1` | CPU limit 1 core (10s CPU limit, 20s wall clock); memory allocations exceeding 1 GiB trigger OOM kill; process creation capped at 32 PIDs. |
| **SEC09** | **Ephemeral Scoped Storage** | `runner/policy.py` (`TmpfsTarget`) | `tmpfs` mounts: `/work` (256M, 0700, 10001:10001), `/tmp` (64M, 0700, 10001:10001) | Quarantined directories unmounted and scrubbed asynchronously within 5 minutes by retention coordinator. |
| **SEC10** | **Independent Validator Gate** | `validator/numerical_verifier.py` | Independent verification receipt | Candidate output cannot be published or authorized without independent stdlib verification and matching SHA-256 digests. |

---

## 3. Step-by-Step Linux Host Acceptance Commands

Execute the following commands sequentially on the prospective Linux deployment host:

### Step 1: Kernel & Cgroups v2 Check
```bash
# Verify kernel release
uname -r
# Expected: >= 6.8.0

# Verify Cgroups v2 hierarchy
stat -fc %T /sys/fs/cgroup/
# Expected: cgroup2fs

cat /sys/fs/cgroup/cgroup.controllers
# Expected: contains cpu memory pids
```

### Step 2: AppArmor LSM Status Check
```bash
# Verify AppArmor module is loaded
cat /sys/module/apparmor/parameters/enabled
# Expected: Y

# Check profile status
sudo apparmor_status
# Expected: docker-default profile loaded and active in enforce mode
```

### Step 3: Idempotent Host Identity & Protected Ledger Setup (Operator Review Only)
Before running the native operator smoke adapter, provision the four distinct non-login service accounts (`sheetsafe-api`, `sheetsafe-ui`, `sheetsafe-runner`, `sheetsafe-validator`), grant Docker socket access **only** to `sheetsafe-runner`, and create the protected `0700` state directories:

```bash
# 1. Create four dedicated system accounts with distinct UIDs/GIDs (!= 0 and != 10001)
for svc in sheetsafe-api sheetsafe-ui sheetsafe-runner sheetsafe-validator; do
    if ! id -u "${svc}" >/dev/null 2>&1; then
        sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin "${svc}"
    fi
done

# 2. Verify none of the four accounts uses UID/GID 0 or container guest UID/GID 10001
for svc in sheetsafe-api sheetsafe-ui sheetsafe-runner sheetsafe-validator; do
    uid="$(id -u "${svc}")"
    gid="$(id -g "${svc}")"
    echo "${svc}: uid=${uid} gid=${gid}"
    test "${uid}" -ne 0 && test "${uid}" -ne 10001
    test "${gid}" -ne 0 && test "${gid}" -ne 10001
done

# 3. Grant Docker socket group membership ONLY to sheetsafe-runner
#    (Ensure sheetsafe-api, sheetsafe-ui, and sheetsafe-validator are NOT in root, docker, sudo, or wheel)
sudo usermod -aG docker sheetsafe-runner
for forbidden in sheetsafe-api sheetsafe-ui sheetsafe-validator; do
    for grp in root docker sudo wheel; do
        sudo gpasswd -d "${forbidden}" "${grp}" >/dev/null 2>&1 || true
    done
done

# 4. Provision protected storage directories with strict ancestor and leaf permissions
sudo install -d -m 0755 -o root -g root /var/lib/sheetsafe
sudo install -d -m 0700 -o sheetsafe-api -g sheetsafe-api /var/lib/sheetsafe/api
sudo install -d -m 0700 -o sheetsafe-runner -g sheetsafe-runner /var/lib/sheetsafe/runner

# 5. Idempotently initialize the protected smoke state ledger (/var/lib/sheetsafe/runner/smoke_state.json)
sudo -u sheetsafe-runner -- ./scripts/run_operator_smoke.sh --init-ledger
```

### Step 4: Run SheetSafe AI Preflight & Host Readiness Probes
```bash
# Run read-only preflight and host readiness evidence probes as sheetsafe-runner:
sudo -u sheetsafe-runner -- python3 -m runner.preflight --context default
sudo -u sheetsafe-runner -- python3 -m runner.host_readiness --context default
```
*Pass condition:* `runner.preflight` reports `"metadata_prerequisites_met": true` and `"issues": []`. `runner.host_readiness` reports `DISTINCT_SERVICE_IDENTITIES`, `API_STORAGE_OWNER_MODE`, `RUNNER_STORAGE_OWNER_MODE`, `RUNNER_PROBE_SERVICE_UID`, and `DOCKER_SOCKET_LOCAL_DAC` as `OBSERVED`.

### Step 5: Run Operator Smoke Adapter (Single Fixed Fixture: smoke-v1)
```bash
# 1. Safe dry-run admission and deployment boundary verification (read-only):
sudo -u sheetsafe-runner -- ./scripts/run_operator_smoke.sh --dry-run
# Pass condition: exits 0, reports DRY_RUN_PASSED, zero containers created.

# 2. Operator-authorized native container smoke test (on verified Linux host ONLY):
sudo -u sheetsafe-runner -- ./scripts/run_operator_smoke.sh --execute-approved-native-smoke
# Pass condition: exits 0, reports COMPLETED, exit_code=0, cleanup_confirmed=true,
#                 execution_enabled=false, production_authorized=false.
```
*Important note:* The smoke adapter strictly executes the reviewed `smoke-v1` diagnostic fixture under `/var/lib/sheetsafe/runner/smoke_state.json`. It does NOT enable arbitrary Python execution, user uploads, or production authorization (`execution_enabled=False`, `production_authorized=False`).

---

## 4. Acceptance Sign-Off Criteria

Before toggling `SHEETSAFE_SYNTHETIC_PLANNING_ENABLED=false` or accepting user uploads:
1. All 10 SEC criteria must be formally verified on the target instance.
2. The pinned parser worker image (`sheetsafe-parser:sha256:...`) and runner image (`sheetsafe-runner:sha256:...`) must match published digests.
3. Non-root user `10001:10001` and `docker-default` AppArmor profile must be verified in active runtime inspect data.
4. PRD transport amendments AM01–AM04 must be signed off by Team Titan.
5. If any gate fails, the system must remain fail-closed with real uploads disabled.
