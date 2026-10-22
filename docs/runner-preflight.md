# Read-only Engine preflight and metadata verification

Step 7H adds a separate [read-only host assessment](runner-host-readiness.md).
It reuses this preflight unchanged, distinguishes advertised LSM support from
host enforcement evidence and leaves all execution/runtime gates intact.
Current Windows/Desktop native Linux acceptance remains PENDING.

## Step 7G: local static image admission

Observed on 2026-10-22 at HEAD `169effb`, with uncommitted Step 7E/F changes
preserved. Read-only real Engine inspection and fake negative/lifecycle tests
only. No image was built/pulled/retagged/pushed, and no container was created,
started or executed. No commit, deployment or cloud expenditure occurred.

### Reviewed identity and verification design

| Identity | Exact value / status |
| --- | --- |
| Approved local manifest/image ID for static selection | `sha256:551ae45bad03b4a1856ae503c62c01a8078394a19d3c318b53fc9f2e98f66bc9` |
| Bound local configuration blob digest | `sha256:59f66d35ff913f60851bde600c75680bc0054c04f32ba72ec42ca2ae2ec6d546` |
| Source/base registry index digest, separately recorded in Dockerfile | `sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70` |
| Fixed diagnostic tag | `sheetsafe-runner:environment-review` |
| Remotely verified final runner registry digest | None |
| Final identity approved for execution | None |

`LOCAL_IMAGE_ID` in docker_backend.py and `LOCAL_CONFIG_DIGEST` in
engine_metadata.py are updated explicitly from Step 7F's reviewed archive/build
evidence, never from whichever image a tag currently selects. The source/base
digest remains a separate build input. Docker locally reports a RepoDigest
matching this local manifest ID; no registry lookup or push verifies publication.

The read-only client first inspects the exact immutable ID. It requires the
manifest descriptor and configuration annotation to match the reviewed pair,
Linux/amd64, UID/GID 10001, exact startup/working directory/stop signal, labels,
ArgsEscaped and the approved environment. All required image Config fields must
exist; unknown configuration keys are rejected. Only absent/null/empty
Volumes/ExposedPorts/OnBuild encodings are allowed. Validly parsed environment
drift remains an explicit `IMAGE_ENVIRONMENT_MISMATCH` blocking issue.

The client then independently inspects the fixed diagnostic tag, checks its ID
against the approved immutable ID and validates its metadata too. Reassignment
reports `IMAGE_TAG_MISMATCH`. Missing/malformed metadata, unavailable images,
timeouts and inspection errors fail closed with `IMAGE_METADATA_UNAVAILABLE`;
no raw error, private value, pull or old-image fallback is used. Failure of
immutable-ID inspection prevents any tag-based fallback lookup.

The command allowlist adds only that exact tag inspection. There are now five
read-only query shapes (context/version/info/image-ID/image-tag), with the same
local-channel checks, bounded time/output, API pin and minimal environment.
No caller image argument, environment setting or policy override is accepted.

A tag check is a point-in-time consistency observation, not a lock on Docker's
tag map. Even if it changes immediately afterwards, the frozen job specification
contains only the reviewed immutable ID, never that tag. A future real driver
must repeat image/preflight verification before creating anything, use the exact
ID without pulls or fallbacks, and satisfy the separately approved runtime gates.
There is still no concrete lifecycle transport or approved creation path. The
existing injectable lifecycle contract is exercised with fakes only.

The old `4f6d2d...` manifest and `0d78a20...` configuration identities are no
longer accepted. A build, download or retag cannot change these source-controlled
pins automatically. Frozen Python values guard routine mutation; they do not
defend against a compromised operator process, local daemon or image store.
Image-store/context ownership and host service permissions remain deployment
trust prerequisites. This local containerd OCI descriptor schema is deliberately
specific; different Engine identity representations require another review.

Official read-only inspection and tag semantics:
[Docker image inspect](https://docs.docker.com/reference/cli/docker/image/inspect/),
[Docker image tag](https://docs.docker.com/reference/cli/docker/image/tag/).

### Real inspection and current preflight outcome

```powershell
docker --context desktop-linux image inspect sha256:551ae45bad03b4a1856ae503c62c01a8078394a19d3c318b53fc9f2e98f66bc9 --format '{{json .}}'
uv run --frozen --no-sync python -m var.step7g-inspection.verify_selection
```

Both exited 0. The one-off local host audit uses the production read-only client,
verifies both resolutions and compares the selected pair to Step 7F's saved
summary. Raw metadata/summary and helper remain under ignored
`var/step7g-inspection`; they are audit artifacts, not production modules.

Observed: Linux/amd64; user `10001:10001`; workdir `/work`; stop signal SIGTERM;
entrypoint `["/usr/local/bin/python", "-I", "-S", "-B", "-u", "/opt/sheetsafe/bootstrap.py"]`;
command `["smoke-v1"]`; exactly this environment:

```text
PATH=/usr/local/bin:/usr/bin:/bin
LANG=C.UTF-8
HOME=/nonexistent
```

Image issues: empty. Tag consistency: verified at inspection time. Current
preflight issues: **`LSM_NOT_ADVERTISED` only**. Engine 29.9.1/API 1.56 reports
Linux x86_64, cgroup v2/cgroupfs, resource support and builtin seccomp. It still
does not advertise AppArmor or SELinux; compiled runc support is not enforcement.
`metadata_prerequisites_met=False`, `execution_enabled=False`, and SEC01-SEC10
remain UNVERIFIED. The always-failing execution gate was explicitly checked.
`SandboxPolicy.final_image_digest`, `ImageFacts.final_approved_identity` and
`verified_registry_digest` remain None. They are not static-selection permits.

Static image approval removes the image-selection blocker, not the host/runtime
release gates. Seccomp, non-root execution/capabilities, network denial,
read-only root/tmpfs, CPU/memory/PID limits, watchdog, cancellation, fresh state,
scoped cleanup and durable orphan recovery still need effective acceptance tests.
Actual process ENV (including daemon-added HOSTNAME) remains unmeasured.
Stopped-container archive extraction conflicts with read-only root; tmpfs hides
pre-start files and disappears on stop. Secure input preparation and pre-stop
artifact collection remain unresolved; no bind-mount or post-start-upload
workaround was added. Private uploads stay disabled.

### Changes, negative tests and next review

Step 7G modifies runner/docker_backend.py, runner/engine_metadata.py,
runner/preflight.py and the explanatory docstring in runner/policy.py; tests are
in tests/test_runner_preflight.py and tests/test_runner_lifecycle.py. Documentation
updates are README.md, runner-foundation-plan.md, runner-preflight.md,
runner-image-rebuild.md and runner-lifecycle.md. No dependencies, migrations,
backend/authentication files, Dockerfile instructions or bootstrap changed here.
Earlier uncommitted image-definition/test/environment-document changes remain.

New fake cases cover the exact pin pair, old/crossed/wrong IDs, tag reassignment,
missing/malformed metadata, inspection errors, wrong OS/architecture/user/startup,
unexpected environment/configuration, caller image overrides and execution staying
disabled. A passing-image preflight still reports missing LSM; native mapping
still rejects that host. Existing seccomp/resource/filesystem/cleanup rejection
tests remain in the suite. No real Docker tag was reassigned to test rejection.

Actual uv/Python 3.12 verification:

```powershell
uv run --frozen --no-sync python -m pytest tests/test_runner_image.py tests/test_runner_policy.py -q -p no:cacheprovider
# 100 passed in 0.31s
uv run --frozen --no-sync python -m pytest tests/test_runner_preflight.py tests/test_runner_lifecycle.py -q -p no:cacheprovider
# 356 passed in 1.32s
uv run --frozen --no-sync python -m pytest -q -rs -p no:cacheprovider --basetemp var/step7g-tests-20261022
# 682 passed, 1 skipped, 1 warning in 35.79s
uv run --frozen --no-sync python -m compileall -q backend runner tests
# exit 0
git diff --check
# exit 0
```

All tests passed. The existing Windows symlink-creation privilege skip at
`tests/test_storage.py:176` and Starlette TestClient/httpx deprecation warning
remain visible. Git LF/CRLF advisories are separate. HEAD stays `169effb`;
all Step 7E-G changes remain unstaged. Image archives/raw metadata, SQLite,
virtual environments and secret environment files stay ignored; `.env.example`
is tracked. No source-controlled secret or runtime file was added. Pattern scans
are heuristic, not a credential-absence certification.

Next smallest proposed milestone: read-only preflight of a supported operator-owned
Linux verification host, explicitly measuring LSM/profile prerequisites and
service/context permissions. Do not provision a VM or spend credits implicitly.
Desktop results cannot certify the Vultr kernel, LSM, cgroups, swap/storage or
runtime behavior. Repeat the mandatory native-Linux storage symlink test without
skipping, then obtain separate approval for any fixed-code runtime experiment.
Resolve stopped-input/archive and collector design gates before spreadsheet
parsing. Do not bypass missing LSM or enable execution in the meantime.

## Historical Step 7D evidence

Historical Step 7D evidence. Step 7E's definition/static tests are recorded in
[runner-image-environment.md](runner-image-environment.md). Step 7F's separate
review build is recorded in [runner-image-rebuild.md](runner-image-rebuild.md).
Step 7G updates static identity pins as documented above; the historical hashes
and next-step proposals below describe Step 7D only. Runtime gates remain intact.

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

Historical Step 7D observations below apply to the unchanged pinned old image.
Step 7F has since built and statically inspected a separate environment-corrected
review image; see [runner-image-rebuild.md](runner-image-rebuild.md). The preflight
still uses its original identity pins and remains blocked. Neither review admits
the new image for execution or bypasses `LSM_NOT_ADVERTISED`.

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
