# Step 7D: read-only Engine preflight and metadata verification

Implemented on 2026-10-22 in the existing Python 3.12.13/uv environment. No new
dependencies. Work began from clean commit `4a13b0f`; the attachment's `407ad08`
and uncommitted-Step-7 assumptions were stale after the approved GitHub push.
This milestone does not authorize another commit/push or any container execution.

## Implementation and boundaries

`runner/preflight.py` implements four fixed read-only queries: local context
inspection, Engine version, Engine info and inspection of the exact reviewed
local runner image. There are no create/start/stop/remove/build/pull/exec methods.
Even its private capture helper rejects commands outside the exact allowlist.
No existing container, Docker Desktop setting or host security setting is changed.
FastAPI and Streamlit do not import this client or receive daemon access.

Context selection is an operator-only enum: `desktop-linux` or Linux `default`.
Only the reviewed local Desktop Linux named pipe or standard/rootless Unix socket
locations are accepted. TCP/SSH endpoints and TLS bypasses fail closed before
Engine queries. Context is rechecked before each Engine query. Context-file
ownership and daemon permissions still require deployment review; this is not
an authenticated application broker or a race-proof host permission boundary.

The CLI uses argument arrays, `shell=False`, no stdin, a minimal environment and
explicit API `1.56`. Cloud/session secrets, `DOCKER_HOST`, custom Docker config
and caller API overrides are not inherited. The trusted operator's standard home
configuration is used to resolve the fixed context. Each local CLI process has
a five-second wait bound and two separately capped 1 MiB output streams with
bounded reader cleanup. Only that CLI process may be killed on timeout; the
daemon/containers are not targeted. Nonzero exits, stderr diagnostics, excessive
output, duplicate JSON keys, non-finite JSON values, malformed data and timeouts
are sanitized failures. No raw diagnostics or image environment values are
included in public reports.

`runner/engine_metadata.py` is pure conversion/validation code. Frozen Engine,
image and container structures retain reviewed facts and sanitized issue codes.
The JSON inspection API schema starts at pinned `1.56`; the reported server's
minimum/maximum and client's API must accommodate it. Older schemas and cgroup v1
are unsupported pending explicit review. Advertised support is not enforcement.

The existing fake lifecycle transport, coordinator, cleanup semantics, policy,
Dockerfile and bootstrap are unchanged. No native lifecycle transport is supplied.

## Actual local observations

The implemented client was run using only read-only Docker queries:

```powershell
uv run --frozen --no-sync python -c "from dataclasses import asdict; import json; from runner.preflight import DockerReadOnlyClient, LocalContext, run_preflight; report = run_preflight(DockerReadOnlyClient(LocalContext.DESKTOP_LINUX)); print(json.dumps(asdict(report), indent=2))"
```

| Observation | Actual result |
| --- | --- |
| Client / Engine | 29.9.1 / 29.9.1 |
| API / server minimum | 1.56 / 1.40 |
| Desktop / backend kernel | Docker Desktop 4.96.0; `6.18.54.1-microsoft-standard-WSL2` |
| Container platform | Linux, `x86_64` (image `amd64`) |
| Cgroups | v2, `cgroupfs` |
| Advertised resource support | Memory, swap, CFS period/quota and PID limits all true |
| Advertised seccomp | `name=seccomp,profile=builtin` |
| Other advertised security | `name=cgroupns` |
| AppArmor / SELinux | Neither advertised by Engine info |
| Rootless / user namespaces | Neither advertised; not evidence of an enabled/delegated configuration |
| Runtime | Default `runc`; runc 1.5.2 and containerd 2.4.2 reported |
| Control channel | Reviewed local Linux-Desktop named pipe; read queries succeeded |

Preflight completed with **blocked metadata prerequisites**:

- `LSM_NOT_ADVERTISED`
- `IMAGE_ENVIRONMENT_MISMATCH`

The diagnostic Python command completed normally; that exit is not an execution
readiness signal. `metadata_prerequisites_met=False`, `execution_enabled=False`,
and all ten SEC controls remain UNVERIFIED. Runc's embedded features list mentions
compiled AppArmor/SELinux support, but it does not prove the daemon enabled an LSM
or that a profile is enforced. No settings were weakened to obtain a green result.

## Image identity and hardening review

The inspected image is still the Step 7B image:

- Local manifest/image ID: `sha256:4f6d2d12fcecf7c70e7923186c698785cfdf0b370a89c5cee186896207f01756`.
- Bound configuration digest: `sha256:0d78a20a59527cde284674316413b4d1bd5ba66ac95a7639be6b4823fdba1965`.
- Linux/amd64; configured UID/GID `10001:10001`; fixed isolated Python entrypoint
  and `smoke-v1`; `/work`; stop signal `SIGTERM`.
- Reported local RepoDigest matches the local manifest ID, but no registry lookup
  verifies a published runner image. `verified_registry_digest` and
  `final_approved_identity` remain `None`; policy's final digest is still absent.

Actual environment names are `PATH`, `LANG`, `HOME`, `GPG_KEY`, `PYTHON_VERSION`
and `PYTHON_SHA256`. The latter three are public base-image build/release metadata,
not private secrets; they still violate the exact policy environment allowlist.
Setting them to empty strings would leave the unwanted names and is insufficient.

The unchanged immutable identity ties this inspection to Step 7B's saved-layer
inventory: shell/dash, pip 25.0.1, Python headers and 105 Debian packages remain.
Bootstrap bytes were root-owned `0:0`, mode `0444`, with the documented SHA-256.
Those permissions/tools are prior static archive evidence, not fresh container
execution or a filesystem field returned by `docker image inspect`. Python version
3.12.15 and dependency versions were established from static package/header
metadata. No package was installed, removed or executed for this review.

Minimum next hardening proposal, **for approval only**:

1. Produce a new final image configuration with exactly LANG/HOME/PATH, preserving
   reviewed runtime files, bootstrap permissions, user and exec-form startup.
   One Dockerfile design is a pinned source stage and an independent `FROM scratch`
   final stage that copies its reviewed filesystem and declares only approved
   metadata. This retains existing libraries/tools initially and avoids blind
   deletion while removing inherited configuration. It needs explicit Dockerfile
   test-contract changes, a separately approved build, static reinspection and a
   newly reviewed immutable identity; the current reference must not be reused.
2. Inventory dynamic libraries and required Python imports before selectively
   excluding pip, headers, shells/package tooling in a later reviewed image.
   The fixed smoke uses standard-library modules, but broader execution/parsing
   dependencies are not operational. Removal must pass future approved isolated
   tests rather than rely on assumptions about ELF/library requirements.
3. Review security updates/package surface and replay acceptance tests after any
   image change. Image minimization is defense in depth; it does not enforce
   networking, seccomp, LSM, cgroups, time limits or teardown.

No Dockerfile change or additional image build was performed. Build-stage
environment inheritance and independent-stage behavior are documented in
[Dockerfile ENV](https://docs.docker.com/reference/dockerfile/#env) and
[multi-stage builds](https://docs.docker.com/build/building/multi-stage/).

## Native container metadata mapping

No actual container was created or inspected. Focused tests use synthetic native
Engine responses, including default/null collections and reordered environment
entries. Positive synthetic metadata models the target contract; the live image
and missing LSM do not currently satisfy those prerequisites.

The mapper validates the existing policy plus mandatory masks/read-only paths,
full ID/name/ownership labels, platform, fixed user/entrypoint/command/environment,
capabilities, security options, namespaces, resource limits, restart/log policy,
fresh stopped state, no devices/mounts/socket and no network attachments/addresses.
Booleans and integers have distinct types. Unknown native security fields and
nondefault values are rejected rather than silently dropped. Only explicit
nil-to-empty collection encodings, the equivalent no-new-privileges spelling,
environment ordering and reviewed path ordering are normalized. Additional
thermal-throttle masks are accepted only under the exact reviewed CPU path pattern.

Only the two hashes already bound by reviewed image metadata may identify the
native container image: the local manifest ID or its exact configuration digest.
This conversion records the native hash and emits the established lifecycle
identity; it does not accept tags, arbitrary hashes or invent a registry digest.
The frozen result exposes a fresh lifecycle projection compatible with the
existing validator, always with execution disabled and all SEC controls unverified.

The initial native schema is deliberately conservative. AppArmor `docker-default`
is the currently mapped LSM; SELinux-only hosts report unsupported mapping.
Unreviewed GraphDriver/namespace/mount shapes fail closed. Native tmpfs visibility
and actual kernel mounts require later experiments; the mapper currently accepts
no extra mount entries. Daemon-advertised seccomp/default flags are prerequisites,
not proof of effective filters. A real driver must not add permissive fallbacks.

Source for native namespace fields and masks:
[Moby HostConfig](https://github.com/moby/moby/blob/master/api/types/container/hostconfig.go),
[Moby OCI defaults](https://github.com/moby/moby/blob/master/daemon/pkg/oci/defaults.go).

## Input and artifact transport: unresolved compatibility gate

The earlier conflict remains: stopped-container archive extraction into a
read-only root is rejected by the reviewed Moby implementation. Copying to `/work`
also cannot be assumed to survive the subsequent tmpfs mount; stopping destroys
tmpfs data. `docker cp` documents limitations for tmpfs/mounted resources, so
artifact recovery cannot be assumed to work after stop or through that API.
Sources: [Moby archive](https://github.com/moby/moby/blob/master/daemon/archive_unix.go),
[tmpfs semantics](https://docs.docker.com/engine/storage/tmpfs/),
[Docker copy limitations](https://docs.docker.com/reference/cli/docker/container/cp/).

No safe Docker Engine create/archive/update-only sequence has been demonstrated
under all current constraints. Do not temporarily weaken read-only root, mount
host paths, create private-data image layers or switch to post-start uploads.

A PRD-compatible **semantic design option for review** is an operator-owned
stopped OCI runtime/snapshot preparation service: allocate a new snapshot from the
fixed image, install bounded validated archive bytes into a separate `/input`
region while no candidate exists, seal root/input read-only, then admit only a
fresh fully restricted runtime with empty `/work` and `/tmp` tmpfs. Use documented
snapshot/runtime interfaces, not direct writes into Docker's private storage.
An independent OCI/containerd executor would require explicit architecture and
privilege-boundary approval; it is not implemented by this Docker adapter.

Input archive validation must precede daemon transport: strict member/expanded
byte counts, fixed relative destinations, no absolute paths, traversal, duplicate
members, symlinks/hardlinks, devices/FIFOs, sparse expansion or caller ownership.
Bounded re-read/hash verification and encryption/retention controls are required.

Artifacts must be collected **before stop** while tmpfs is alive, after candidate
descendants are frozen/terminated with externally verified quiescence. A separate
trusted collector/channel must read only server-owned workspace references with
no-follow descriptor-relative traversal, reject links/special files, bound file
count/size/total bytes, and hand bytes to quarantine/independent validation. Guest
stdout is not an attestation. Snapshot/runtime cleanup needs verified absence and
durable recovery. That collector/channel and quiescence mechanism are also
unimplemented and require review; no current artifact transport success is claimed.

## Observed tests and checkpoint review

```powershell
uv run --frozen --no-sync python -m pytest tests/test_runner_preflight.py -q -p no:cacheprovider
# 173 passed in 0.36s
uv run --frozen --no-sync python -m pytest tests/test_runner_policy.py tests/test_runner_image.py tests/test_runner_lifecycle.py tests/test_runner_preflight.py -q -p no:cacheprovider
# 373 passed in 0.85s
uv run --frozen --no-sync python -m pytest -q -rs -p no:cacheprovider --basetemp var/step7d-tests-20261022
# 599 passed, 1 skipped, 1 warning in 23.80s
uv run --frozen --no-sync python -m compileall -q backend runner tests
# exit 0
git diff --check
# exit 0
```

Tests cover mandatory field omissions, unsupported security/resource capabilities,
immutable identity, privileges, mounts/namespaces, seccomp/LSM failures, invalid
channels, communication failures, command overrides, bounded output/timeout and
absence of mutating command methods. No new-test failure occurred. The existing
Windows symlink privilege skip and Starlette/httpx warning remain; the mandatory
native Linux follow-up is unchanged in the runner plan. These tests certify no
Vultr kernel/cgroup/LSM configuration or effective runtime enforcement.

The proposed checkpoint contains only these new modules/tests and reviewed
documentation updates. Raw metadata/test files are under ignored `var/`; no
image archive, database, virtual environment, upload or secret environment file
belongs in staging. `.env`/`.env.local` remain ignored and `.env.example` tracked.
No staging, commit or push is part of Step 7D.

Next smallest task after review: approved image-environment definition/static
test changes, without an automatic build or execution. Host LSM verification and
the input/collector architecture decision remain separate gates. All SEC01-SEC10
controls, cumulative CPU accounting/watchdog, cancellation, effective isolation,
durable orphan recovery and result validation remain UNVERIFIED at runtime.
