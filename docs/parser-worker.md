# Dedicated parser worker: Step 8B foundation and Step 8C build review

**Current Step 8C-R status (2026-10-25): BUILD AND STATIC IMAGE AUDIT PASSED.**
The Linux Engine is reachable, eight exact wheels are hash-verified and the
network-disabled build succeeds. See [the recovery and inspection record](#step-8c-r-engine-availability-offline-wheels-and-final-image).
Image execution approval remains unset; all SEC01-SEC10 runtime controls and
native imports remain UNVERIFIED. The Step 8B and blocked Step 8C records below
are historical and preserved for traceability.

## Historical Step 8B evidence

2026-10-25. **STATIC DEFINITION / SYNTHETIC FAKE TESTS ONLY. NOT BUILT OR RUN.**
No Docker command, image build/pull, container, real upload, external inference,
VM provisioning or deployment was performed. No production parser transport or
dispatch path is enabled. All SEC01-SEC10 runtime enforcement remains UNVERIFIED.

## Verified Step 8A checkpoint

Commit `e28c3b30eefb464839b9149a07c100d2d699c719`:
`feat: add secure CSV and XLSX ingestion foundations`. Exactly 17 reviewed paths
were staged; complete source/diff, staged blob identity, known secret patterns,
defusedxml 0.7.1 lock and absence of runtime data were checked. Normal main push
succeeded. HEAD, origin/main and independently queried GitHub main matched;
working tree was clean before Step 8B. Complete checkpoint suite: **1197 passed,
1 skipped, 1 warning in 104.11s**; syntax and staged whitespace checks passed.
Step 8B remains uncommitted. Earlier Step 8A evidence is historical, not a claim
that its current checkpoint is still uncommitted.

Original 26-page PRD is unchanged. Its recorded SHA-256 was rechecked:
`999d923deb24960418fc94afbaaab4ce195636be25d0f05dd384129ef077d889`.
Relevant requirements: p8-9 separate services, p11 SEC01-SEC10, p12 lifecycle/
transport, p14 file/archive/formula semantics, p17 ownership and p19 retention.
Document content is a requirement source, not separate permission to execute it.

## Separate trust boundary

- API/UI retain no daemon access or in-process parser path. Existing private
  storage holds bounded opaque originals; existing DB guards own authorization.
- ingestion/parser_jobs.py defines shared versioned metadata/reply validation,
  importing no worker/DB/Engine. IDs and hashes are integrity binding, not auth.
- runner/parser_policy.py is a separate fixed target policy, not a subclass or
  automatic extension of smoke-v1. No caller constructor overrides are accepted.
- parser_worker/entrypoint.py dispatches only fixed PARSE_CSV and PARSE_XLSX code.
  Algorithms receive bytes/context, never database credentials or host paths.
- Production bootstrap accepts **no arguments**, adds only fixed image app/vendor
  directories under Python -I -S -B, and exits **78 / parser_transport_unavailable**.
  It cannot receive bytes through stdin, a host path, environment or URL fallback.

run_fixture_worker is a synthetic unit-test harness with an injected transport
and required lease callback. It is not a production API/worker adapter, trusted
RPC or OS sandbox. Callbacks cannot certify a native guest's authorization, and
Python imports do not isolate a compromised process. No application module imports
the entrypoint. No new upload route, job queue, session/DB system or migration.

## Fixed parser policy and identity gate

| Target | Requested contract; effective enforcement NOT tested |
| --- | --- |
| Identity/privilege | UID/GID 10001; ALL caps dropped, no added caps, NNP; no privileged mode |
| Network/secrets | Network none; no socket, host bind/shared mounts, credentials or DB files; minimal explicit env |
| Filesystem | Read-only root; /work 256 MiB and /tmp 64 MiB, nodev/nosuid/noexec; fresh private writable state |
| Isolation | Private PID/IPC, default seccomp, required available enforcing LSM; no unconfined override |
| CPU/memory/process | 1 vCPU, 10 cumulative CPU seconds, 1 GiB including tmpfs, memory+swap=RAM, 32 PIDs |
| Time | 20s wall target, kill within 2s of deadline, cancellation within 5s; independent watchdog required |
| I/O | Source 20 MiB, profile <=128 KiB, envelope <=132 KiB; logs <=64 KiB/stream on a separate capped log path |
| Lifecycle | Fresh parser runtime, verified independent teardown before approval/retry, daemon logs disabled |

These conservative parser targets reuse the PRD's numeric isolation envelope,
not smoke's fixture identity or transport. PRD states candidate-specific CPU/wall
limits; applying these caps to the parser is the proposed separate profile,
not a native capacity claim. No larger parser budget is requested/approved.
Worst-case XLSX may exceed memory/CPU and fail; measure on Linux before enabling
the advertised dataset range. No error may silently raise a limit/deadline.

Source/base image is the existing previously reviewed registry pin:
`docker.io/library/python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70`.
This is a source index digest, not a new final parser image ID. It was reused from
reviewed repository evidence, not freshly fetched in this step. Parser final
approved_image_id is **None**. No digest is invented, no mutable tag trusted, no
smoke image fallback. require_parser_execution_ready always rejects. A later
build must inspect actual local manifest/config identity, architecture, user,
entrypoint, command, environment and layers before separately recording approval.
Even matching final identity cannot clear runtime or transport gates.

## Versioned job/reply contract

ParserJob version 1 contains server-generated job ID, owned run ID, positive lease
epoch and the existing IngestionRequest (dataset/session/object IDs, version,
PENDING state, SHA-256, source size, CSV/XLSX declaration, bounded display name,
explicit XLSX worksheet or approved CSV delimiter). No token/lease-owner secret
enters the guest. The trusted for_request factory creates a new job UUID; wire
decoding is compared against the entire expected job. A matching manifest alone
cannot authenticate session or prove a current lease.

Only PARSE_CSV/PARSE_XLSX; operation must match format. Unknown JSON fields,
duplicate keys, nonfinite values, wrong context, bool-as-version/epoch, unsupported
format, path/URL/command/import/executable/image/runtime flags fail. Metadata is
bounded to 8 KiB. The 20 MiB source limit is distinct from the unchanged 256 KiB
smoke framing demonstration. No real frame or stdin transport was implemented.

WorkerReply binds protocol/job/run/epoch, status and exactly one result/failure.
Successful fixture results use existing bounded DatasetProfile, including stable
columns, shape, missingness, formula/cache statistics, limited preview and source
hash/size. Shared structural validation rechecks dataset/session/hash/worksheet
and count/type consistency. Raw output stays untrusted. Status is
PROFILED_SYNTHETIC/NEEDS_CLARIFICATION or FAILED/CANCELLED/TIMED_OUT/INTERRUPTED;
never READY, validated-publication or cleanup-complete evidence. Output strings
are inert text, never code/HTML to execute. No CSV export is introduced; future
exports must neutralize formula-like text without corrupting numeric values.

Closed worker errors: INVALID_JOB, BINDING_MISMATCH, STALE_LEASE, CANCELLED,
TIMED_OUT, INTERRUPTED, WORKER_FAILED, TRANSPORT_FAILED, INVALID_REPLY, plus existing
ingestion failure codes. Exception text, cell contents, paths and traces do not
enter failure replies/logs. Native fatal crash/OOM/unresponsive library handling
still requires a trusted external supervisor; Python exception tests do not prove it.

## Fake I/O and uncertainty

ParserTransport defines bounded receive_job, receive_source, send_reply and close.
No implementation opens a stream or contacts an Engine. Tests use reviewed local
synthetic bytes; receive_source uses <=64 KiB chunks, EOF None, <=4096 reads and
1s cooperative per-call timeout. Actual length/hash, trailing/truncated/empty or
nonbyte chunks and timeout/cancel/lease checks reject before a successful result.
Twenty-second monotonic checks surround parsing and I/O but cannot preempt a
blocking transport/native library. Real watchdog and authenticated cancel channel
are still mandatory.

No retry is performed. Send failure is **UNCERTAIN**, even if bytes may already
have arrived; a returned send is only a call return, not publication. close return
is only stream-close evidence, never resource/file/container removal. Fake receipt
runtime_verified, cleanup_verified and publication_allowed are always false.
The remaining check-to-activation/publication gaps cannot be solved by a Python
callback; the Step 7M late-dispatch/quiescence blockers remain unchanged.

## Image packaging (definition only)

Dockerfile is parser_worker/image/Dockerfile with its Dockerfile.dockerignore,
using repository root as a **future** context. Deny-all rules reopen only 14 exact
source/build files; explicit COPY statements cannot copy a repository directory.
Backend, runner, tests, uv environment, databases, uploads, private fixtures,
archives and env files are excluded. Static canary tests approximate this narrow
ignore grammar; actual Engine context/layers must be inspected after approved build.

Build stage installs a hashed wheel-only --no-deps --no-compile requirements
subset. Final FROM scratch inherits no source image ENV and copies:

- Python 3.12 executable/stdlib with site-packages, pip/ensurepip, tests, GUI and
  venv assets excluded; fixed loader and libpython search paths.
- Conservative pinned Debian amd64 native-library closure. It is broader than
  a measured minimal linkage set; no native minimality/security scan is claimed.
- Only eight pinned third-party parser dependencies, in an explicit vendor path.
- ingestion contract modules, fixed parser modules, and root-owned immutable
  bootstrap. No application service, shell executable or package installer is
  intentionally copied. Actual final filesystem absence remains a build check.

stage_runtime.py is fixed build-stage code, never host/job code; no user path or
subprocess interface. It was not executed here. Full native compatibility remains
unverified: executable loader/libpython, extension linkage, UTF-8 locale, pydantic
Rust wheel, zlib/expat and library licenses/scans need post-build inspection.
There is no runtime dependency installation or guest network allowance.

| Locked parser dependency | Version |
| --- | --- |
| annotated-types | 0.8.0 |
| defusedxml | 0.7.1 |
| et-xmlfile | 2.0.0 |
| openpyxl | 3.1.5 |
| pydantic | 2.14.1 |
| pydantic-core | 2.50.1 |
| typing-extensions | 4.16.0 |
| typing-inspection | 0.4.4 |

requirements.lock hashes are checked against unchanged uv.lock, including the
CPython 3.12 manylinux x86_64 pydantic-core wheel; pure wheels for other packages.
No pandas/numpy, FastAPI/Streamlit, Docker client or inference SDK copied. No new
project dependency or lock resolution was needed for Step 8B. Hashes constrain
artifacts, not vulnerabilities; future build/download needs separate approval.

## XLSX/CSV risk review

| Threat | Existing parser check / remaining runtime obligation |
| --- | --- |
| ZIP expansion | <=1000 entries, <=100 MiB declared/actual expansion, <=100:1 per entry; CPU/memory still require cgroups/watchdog |
| Path/type tricks | No extraction, traversal/absolute/backslash/duplicate/case/link/special entry rejection; transport must separately enforce no host mount/path exposure |
| XML | Defused DTD/entities/external references, depth/string bounds; oversized native tokens/allocation still need OS containment |
| External/embedded content | Reject external relationships/link parts, macros/ActiveX/OLE/query/unsupported types; network-none denial must be tested natively |
| Formula semantics | Never evaluate; warn for cached values, missing cache needs values-only export; stale caches are not independently validated data |
| Dimensions/strings/profile | Actual coordinates/order/extents checked, row/column/nonempty/cell/profile bounds; shared strings/styles can still pressure memory |
| CPU/crash | Cooperative checks are not hard preemption; independent supervisor must terminate full runtime/descendants and retain uncertain outcomes |
| Export/privacy | Preview is inert untrusted text, not an export; later rendering/CSV-neutralization required. No row/preview/workbook sent to Vultr |

## Future durable dispatch (not implemented)

Reuse existing Database transactions, session guards, owned_dataset/owned_run,
JobStore lease/epoch semantics, durable external-intent uncertainty and lifecycle
cleanup. Do not start a second authorization/DB/queue system. Before actual
dispatch, trusted broker must recheck session credentials/expiry/revocation,
dataset/source/version/run ownership, current owner token/epoch, cancellation,
remaining deadline and separately approved image/policy. Lease secrets stay in
trusted services. Do not rely on fields delivered by a guest.

Current JobStore/schema are deliberately still smoke-v1 preparation only and
cannot dispatch these parser envelopes. Ingestion precedes analysis; linking a
profiling job to an appropriate durable parent/run lifecycle needs an explicit
versioned extension/design review. The required run_id in these static contracts
is a binding slot, NOT evidence that a parser run was registered. Test UUIDs are
synthetic. No fake persisted parser lease/run or migration was created.

Future flow: owned opaque original -> scoped durable parser claim -> intent
before external side effect -> verified restricted runtime -> approved input
transport -> bounded quarantined reply -> trusted structural validation ->
independent teardown/quiescence proof -> atomic current-authorized dataset state.
Preserve unknown external outcomes; no blind replay or ambiguous retry. Keep
result quarantined and parent PENDING/failed until all gates succeed. Failure
cannot be marked clean because this fake closed a stream. Retention remains
1h session / 5min deletion target / 24h minimal audit / 30d aggregate metrics.

## Native release gates and next increment

LSM_NOT_ADVERTISED remains the recorded Desktop blocker; no fresh Engine probe
or bypass here. Native Linux acceptance, actual seccomp/LSM attachment, cgroup
CPU/memory/swap/PID, read-only mounts, no-network/socket/secret probes, watchdog,
crash/restart/reaper and verified teardown must pass on the daemon host. Test
maximum/saturation/XLSX memory cases without raising budgets. Existing Windows
symlink privilege skip must be rerun without that skip on native storage.

Next smallest step: separately approved parser image build and static inspection
only, with actual dependency installation, filesystem/linkage/SBOM checks and
local image identity recorded. Do not run its payload or configure that identity
as execution-approved automatically. Actual runtime acceptance and transport
approval precede fixed-fixture execution, then real upload/API integration.
Unapproved stdin receiver/host collector alternatives remain conditional under
[the admission decision](runner-admission-decision.md) and
[native Linux plan](linux-sandbox-acceptance.md).

## Actual tests

Combined worker/profile/static-image and existing ingestion fixtures:

```powershell
uv run --frozen --no-sync python -m pytest tests/test_parser_policy.py tests/test_parser_jobs.py tests/test_parser_entrypoint.py tests/test_parser_image.py tests/test_csv_parser.py tests/test_xlsx_parser.py tests/test_ingestion_contracts.py tests/test_ingestion_boundary.py -q -x -rs -p no:cacheprovider --basetemp var/step8b-focused-20261025
```

Observed **241 passed, 1 existing warning, 11.40s**. Includes 127 new tests and
114 unchanged ingestion cases. Static tests never build/run the image or stage
the native runtime.

Existing regression command:

```powershell
uv run --frozen --no-sync python -m pytest tests/test_storage.py tests/test_sessions.py tests/test_runner_policy.py tests/test_runner_image.py tests/test_runner_lifecycle.py tests/test_runner_preflight.py tests/test_host_readiness.py tests/test_transport_protocol.py tests/test_transport_state.py -q -x -rs -p no:cacheprovider --basetemp var/step8b-related-20261025
```

Observed **779 passed, 1 skipped, 1 warning in 14.88s**.

Complete suite and syntax/whitespace commands:

```powershell
uv run --frozen --no-sync python -m pytest -q -x -rs -p no:cacheprovider --basetemp var/step8b-full-20261025
uv run --frozen --no-sync python -m compileall -q backend runner ingestion parser_worker tests
git diff --check
```

Observed **1324 passed, 1 skipped, 1 warning in 71.84s**. All 1197 checkpoint
tests plus 127 new cases passed. No failed test was hidden or existing security
assertion changed. Syntax exit 0, whitespace exit 0. Remaining skip:
tests/test_storage.py:176, Windows OS symlink creation privilege unavailable;
native Linux must execute that case without the privilege skip. Remaining warning:
Starlette TestClient/httpx deprecation. Git LF-to-CRLF notices are separate
conversion notices, not failed whitespace checks.

Final scope audit: 16 expected paths (3 modified / 13 new), zero staged, HEAD and
origin/main remain e28c3b3. No Step 8B commit/push. Existing backend/auth/storage,
published migrations, old runner policy/lifecycle/framing, ingestion algorithms
and project dependency files unchanged. Only new text source/tests/docs/image
definitions; no image archive, binary spreadsheet, DB, upload or runtime artifact
is proposed for tracking. Known secret-signature hits zero; env/runtime ignores,
Markdown links/fences and tracked/untracked whitespace checks passed. Signature
scanning is bounded evidence, not a guarantee against every possible secret.

Primary references checked: [pip hashed wheel-only installs](https://pip.pypa.io/en/stable/topics/secure-installs/),
[Docker context/ignore semantics](https://docs.docker.com/build/concepts/context/),
[Python isolated startup](https://docs.python.org/3.12/using/cmdline.html#cmdoption-I).
Related parser semantics/limits: [Step 8A](dataset-ingestion.md).

## Step 8C build attempt and static source review

2026-10-25, HEAD `e28c3b30eefb464839b9149a07c100d2d699c719` plus the preserved
uncommitted Step 8B files. **BUILD BLOCKED; IMAGE INSPECTION NOT PERFORMED.**
Only README.md and this document were edited in Step 8C. No packaging, dependency,
policy, transport, dispatch or application change was made to work around failure.
No container create/start or production parser payload command was issued. No dependency
download, image pull/push, cloud action, commit or Git push was performed.

### Exact attempt and observed blocker

Existing Step 7F build procedure, adapted only for the parser Dockerfile, root
context, separate tag and ignored audit paths:

```powershell
docker --context desktop-linux build --network=none --platform=linux/amd64 --pull=false --provenance=false --load --progress=plain --tag sheetsafe-parser:static-review --iidfile var/step8c-inspection/image-id.txt --file parser_worker/image/Dockerfile .
```

**Actual exit: 1.** Engine connection failed:

```text
failed to connect to the docker API at npipe:////./pipe/dockerDesktopLinuxEngine
open //./pipe/dockerDesktopLinuxEngine: The system cannot find the file specified.
```

The build never reached context transfer, base resolution or either build-stage
RUN instruction. No iidfile was created. Ignored evidence: build.log,
build-exit.txt and prebuild-evidence.json under var/step8c-inspection/.
Read-only docker context ls identified desktop-linux, but docker version and
the pinned-base image inspect failed with the same missing Engine pipe even
outside the tool sandbox. Initial sandbox probes also could not read Docker
configuration; unrestricted probes confirmed that the Engine failure was real.
No Docker configuration contents were displayed. Docker Desktop was not started
automatically after the independent offline-input blocker was established.

`--network=none` restricts build RUN networking, not registry metadata resolution;
`--pull=false` does not guarantee that a missing base cannot be fetched. Before a
retry, verify the exact base is locally available and establish builder-level
offline registry access controls/cache. Do not describe this failed invocation
as a successful offline base/dependency resolution check.

### Source checks versus actual image properties

The 14 explicit allowed context files were read, checked as regular files without
symlink/reparse ancestors below the project root, and SHA-256 recorded in the
ignored prebuild evidence. Known credential-signature hits were zero. Existing
static context canaries reject env files, backend/runner/tests, virtual
environments, data, archives and arbitrary added files. These are source checks;
actual BuildKit transfer and final layers remain UNVERIFIED.

The immutable source pin is unchanged:
`docker.io/library/python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70`.
Historical Step 7B/7F registry evidence records its linux/amd64 manifest as
`sha256:57d96f71de145a98e7ceca18ee4ade77bba4103a33a72dfaea026b23625c6bf0`.
That evidence is not a fresh Step 8C registry/local-base verification. Do not
substitute the smoke image or assume the base remains cached while Engine is down.

| Property | Reviewed source intent | Step 8C actual image observation |
| --- | --- | --- |
| Local parser image ID | Record only after successful build/inspection | None produced; not verified |
| Remote parser registry digest | Separate identity, no registry push | None verified |
| OS/architecture | Linux/amd64 | UNVERIFIED |
| User/group | 10001:10001 | UNVERIFIED |
| Entrypoint | /usr/local/bin/python3.12 -I -S -B -u /opt/sheetsafe/bootstrap.py | UNVERIFIED |
| Default command | Empty list | UNVERIFIED |
| Environment | LANG=C.UTF-8; HOME=/nonexistent; PATH=/usr/local/bin | UNVERIFIED |
| Workdir/stop signal | /work; SIGTERM | UNVERIFIED |
| Bootstrap | Root-owned 0:0, mode 0444, fixed imports; main closed with exit 78 | UNVERIFIED in image |
| Layers/size/source hashes | Bounded offline export audit after build | Not available |
| Installed packages/native libraries | Eight locked packages and staged Python/native closure | Not inspected |
| Shell/pip/devtools/secret absence | Explicit source exclusions and scratch stage | Not verified in image |
| Imports/linkage/locale/ABI | Separate later native verification | UNVERIFIED |

No arbitrary command/import/path interface or runtime installer was introduced.
CSV remains fixed synthetic parsing; XLSX still calls the bounded archive scan,
defused XML parser with DTD/entity/external-reference denial and read-only
openpyxl. Source staging still retains a conservative native-library set rather
than a measured minimum. No SBOM, CVE/license or native compatibility claim can
be made from this failed build.

### Exact offline inputs missing and preparation plan

No .whl archives were found in the searched local uv cache, pip cache or ignored
project var tree; a project wheels directory did not exist. This is a filename
inventory, not proof about opaque pip HTTP caches or unavailable BuildKit cache.
Neither kind of cache is supplied to the reviewed build. The current context has
no wheelhouse COPY and pip has no --no-index/--find-links input; --no-cache-dir
prevents relying on pip's wheel cache. Thus merely starting Desktop would not
provide a clean, reproducible offline dependency installation.

All eight required artifact records below match the unchanged uv.lock, including
the Linux native wheel. **The actual wheel bytes/hashes were not verified: those
archives are absent from the reviewed offline inputs.** Windows installed package
metadata corroborates closure: openpyxl -> et-xmlfile; pydantic -> annotated-types,
pydantic-core, typing-extensions and typing-inspection; core/inspection ->
typing-extensions. Unselected email/timezone extras are not runtime requirements.
Linux wheel METADATA must still be checked after preparation. No pandas, numpy,
FastAPI, Streamlit, Docker client or inference SDK is in the parser lock.

| Required wheel archive | Expected SHA-256 |
| --- | --- |
| annotated_types-0.8.0-py3-none-any.whl | f072f4d804ea359e4eaf198b1af7a8b0943881a87f31bb764f8bf219bb9419e0 |
| defusedxml-0.7.1-py2.py3-none-any.whl | a352e7e428770286cc899e2542b6cdaedb2b4953ff269a210103ec58f6198a61 |
| et_xmlfile-2.0.0-py3-none-any.whl | 7a91720bc756843502c3b7504c77b8fe44217c85c537d85037f0f536151b2caa |
| openpyxl-3.1.5-py2.py3-none-any.whl | 5282c12b107bffeef825f4617dc029afaf41d0ea60823bbb665ef3079dc79de2 |
| pydantic-2.14.1-py3-none-any.whl | 9195d967ec791692a04438115466764fb8b9a27b31f14a760437694f40d6b454 |
| pydantic_core-2.50.1-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl | 93ba4e9d8210d941c200431a56b2c0400b131865947903937ed3ec5404307d2e |
| typing_extensions-4.16.0-py3-none-any.whl | 481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8 |
| typing_inspection-0.4.4-py3-none-any.whl | 65b8397ba37ccbce054456aaccddfc91e6e3083c92824df348d96ca832f3f147 |

Preparation proposal, **not executed and requiring review before downloads or
changing the context**:

1. Enable the existing local Linux Engine and inspect/cache the exact source
   index/amd64 manifest above. If absent, obtain only that verified base through
   an explicitly approved preparation step. Do not change its tag/digest.
2. On an approved connected preparation machine, select exactly these wheel
   URLs, sizes and SHA-256 values from uv.lock; the ignored prebuild evidence
   records the matching URLs/sizes. Fetch these fixed artifacts over HTTPS
   without resolving/upgrading packages, accepting source distributions or
   installing them. Stop for any unavailable URL or mismatched bytes.
3. Recompute SHA-256 (for example Get-FileHash -Algorithm SHA256) and exact size
   for every archive against that manifest before and after offline transfer.
   Require exactly the eight filenames; reject missing/extra artifacts, links
   and unexpected types. Keep archives in ignored audit storage. Inspect bounded
   wheel METADATA/WHEEL/RECORD without extracting unsafe paths or executing code;
   verify Linux tags, versions and complete non-extra dependency closure.
4. Review a minimal offline-input amendment to the **same** multi-stage
   Dockerfile, context whitelist and static tests: explicitly enumerate only the
   eight verified wheel inputs into the build stage and use pip --no-index
   --find-links with existing --require-hashes --only-binary=:all: --no-deps.
   Do not whitelist an arbitrary wheel directory or copy wheel archives into
   the final scratch image. No such amendment has been applied in Step 8C.
5. Repeat the same network-disabled build with a fresh audit path, verified
   local base and offline builder registry access. Then compare iidfile to
   immutable image inspect output. Export image layers without a container;
   bounded archive inspection must verify manifest/config/layer hashes, merged
   paths, source hashes/ownership, exact dependencies, ELF linkage and absence
   of secrets/tools/data. No unsafe archive extraction or guest binary invocation.

This preserves the existing packaging architecture and dependency versions.
Even a successful retry will not guarantee bit-identical rebuilds: builder
version, source timestamps, wheel bytes and packaging metadata must be recorded.
Do not claim successful runtime imports from file/ELF presence alone.

### Gates and next delivery priority

Parser approved_image_id remains None; execution_enabled remains false and
require_parser_execution_ready rejects. Production entrypoint is still closed
with exit 78. All SEC01-SEC10 effective controls remain UNVERIFIED. The historical
LSM_NOT_ADVERTISED blocker was not remeasured because Engine is unavailable;
native Linux host/LSM/seccomp/cgroup evidence is still required. Stopped-container
archive versus read-only root/tmpfs transport compatibility, unapproved PRD
transport amendment, late dispatch/quiescence and verified teardown remain open.

Resume this build/inspection milestone only after offline inputs and Engine are
available. Then prioritize native Linux host prerequisite evidence and an explicit
transport decision, followed by a separately approved bounded synthetic fixture
run with measured effective restrictions and verified teardown. Durable parser
dispatch/upload integration follows that evidence, not another broad fake-only
subsystem. No cloud provisioning or execution permission is implied.

### Actual Step 8C automated checks and Git review

Existing uv environment / Python 3.12; no dependency installation or new tests.
The image-definition tests inspect source, not a built image. Parser tests use
the existing host synthetic fixtures/fake transport; none launch a container.

```powershell
uv run --frozen --no-sync python -m pytest tests/test_parser_image.py tests/test_parser_policy.py tests/test_parser_jobs.py tests/test_parser_entrypoint.py tests/test_csv_parser.py tests/test_xlsx_parser.py tests/test_ingestion_contracts.py tests/test_ingestion_boundary.py -q -x -rs -p no:cacheprovider --basetemp var/step8c-focused-20261025
# 241 passed, 1 warning in 11.63s; exit 0
uv run --frozen --no-sync python -m pytest tests/test_runner_policy.py tests/test_runner_image.py tests/test_runner_preflight.py tests/test_runner_lifecycle.py tests/test_host_readiness.py tests/test_transport_protocol.py tests/test_transport_state.py -q -x -rs -p no:cacheprovider --basetemp var/step8c-runner-20261025
# 697 passed in 1.74s; exit 0
uv run --frozen --no-sync python -m pytest -q -x -rs -p no:cacheprovider --basetemp var/step8c-full-20261025
# 1324 passed, 1 skipped, 1 warning in 87.44s; exit 0
uv run --frozen --no-sync python -m compileall -q backend runner ingestion parser_worker tests
# exit 0
git diff --check
# exit 0
```

Remaining skip: tests/test_storage.py:176, OS symlink privilege unavailable on
Windows. It must execute without that skip on native Linux storage. Remaining
warning: Starlette TestClient/httpx deprecation; no dependency was changed or
warning suppressed. Git LF-to-CRLF advisories are separate conversion notices.

The ignored source audit verified the eight lock artifact records and hashed all
14 allowed context inputs; it did not invoke bootstrap, stage_runtime or Engine.
The final scope audit checked all 16 expected modified/untracked text paths,
known secret signatures (zero hits), local Markdown links/fences, Python parsing,
tracked/untracked whitespace, env/runtime ignores and zero staged files.
Heuristic signature scans cannot certify absence of every possible secret.

Combined inherited Step 8B plus Step 8C working tree remains **3 modified /
13 new / zero staged**. Step 8C changes only README.md and docs/parser-worker.md
(the latter was already untracked from Step 8B). The 13 other Step 8B source/test/
image files and docs/dataset-ingestion.md are preserved. New audit helper/log/
JSON evidence and test directories stay under ignored var/; no image archive,
wheel, database, uploaded spreadsheet or runtime artifact is proposed for Git.
HEAD and local origin/main remain e28c3b3; no remote refresh/push was attempted.
Existing backend/auth/storage/schema, old runner policy/lifecycle/framing and
project dependency files remain unchanged. .env and .env.local remain ignored;
.env.example remains tracked.

**Result: source regressions pass, but Step 8C build and actual static image
verification remain blocked.** No final parser image identity or execution
approval was recorded.

## Step 8C-R Engine availability, offline wheels and final image

2026-10-25. The approved build/static inspection scope is complete; runtime
execution remains disabled. Original PRD is unchanged. No parser container was
created/started, no production parser payload ran, and no upload, dispatch,
inference, VM provisioning, security-setting change, commit or push occurred.
Synthetic host unit tests are distinct from a sandboxed parser execution.

### Engine diagnosis and recovery actions

Actual supported read-only diagnostics:

```powershell
docker desktop status
docker context ls
docker --context desktop-linux version
docker --context desktop-linux info
wsl --status
```

Desktop was already **running** on the first Step 8C-R probe. The same
desktop-linux named pipe now returned actual version/info responses: Engine
29.9.1 / API 1.56, Docker Desktop 4.96.0 (243774), linux/amd64; containerd 2.4.2,
runc 1.5.2; WSL2 kernel 6.18.54.1-microsoft-standard-WSL2; cgroup v2.
Initial inventory was zero containers and three images. WSL status reported
docker-desktop as default distribution, version 2; its WSL1-disabled notice did
not prevent the successful Linux Engine API calls. No WSL setting was changed.

The historical failure was an unavailable Engine named-pipe endpoint, not a
successful GUI-only check. Current successful communication rules out a continuing
context/permission failure. Evidence does **not** establish whether Desktop was
stopped or its Engine was still starting at the earlier failure; no historical
process record confirms that distinction. Availability had recovered before
these diagnostics. No start/restart, factory reset, reinstall, prune, service
restart, WSL shutdown or image/container removal was required/performed.

### Exact offline dependency preparation

Fresh cache checks again found no .whl archives in the checked uv/pip cache or
project var tree. As before, this is not a claim about opaque HTTP cache entries.
Project venv had no installed pip, and the system launcher had no registered
Python 3.12. Used the **existing uv-managed Python 3.12.13 bundled pip 25.0.1
wheel as a tool**, without installing it or downloading another package.

Actual operator command (ignored helper; no project dependency change):

```powershell
.\.venv\Scripts\python.exe -I var/step8cr-inspection/download_wheels.py
```

Helper uses runpy with that existing bundled tool and the following pip arguments:

```text
--isolated --no-input --disable-pip-version-check --no-cache-dir --retries 0 --timeout 30 download --no-index --no-deps --only-binary=:all: --require-hashes --platform manylinux_2_17_x86_64 --platform manylinux2014_x86_64 --python-version 3.12 --implementation cp --abi cp312 --dest var/step8cr-inspection/wheelhouse --requirement var/step8cr-inspection/download-requirements.txt
```

The generated requirements contain exactly the eight unchanged uv.lock artifact
URLs on HTTPS files.pythonhosted.org, each with its original SHA-256. No index
lookup, third-party mirror, environment/user config, unchecked resolver update,
sdist/build script or package installation. PIP_CONFIG_FILE=os.devnull disables
configuration files; inherited PIP_* options are cleared in that helper process.
Download exit 0. Hashes/sizes were recomputed after download and after copying
the verified inputs to the stable ignored build location.

| Artifact | Observed version | SHA-256/size against original lock |
| --- | --- | --- |
| annotated_types-0.8.0-py3-none-any.whl | 0.8.0 | MATCH |
| defusedxml-0.7.1-py2.py3-none-any.whl | 0.7.1 | MATCH |
| et_xmlfile-2.0.0-py3-none-any.whl | 2.0.0 | MATCH |
| openpyxl-3.1.5-py2.py3-none-any.whl | 3.1.5 | MATCH |
| pydantic-2.14.1-py3-none-any.whl | 2.14.1 | MATCH |
| pydantic_core-2.50.1-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl | 2.50.1 | MATCH |
| typing_extensions-4.16.0-py3-none-any.whl | 4.16.0 | MATCH |
| typing_inspection-0.4.4-py3-none-any.whl | 0.4.4 | MATCH |

Exact SHA-256 values are unchanged from [the artifact table above](#exact-offline-inputs-missing-and-preparation-plan).
Ignored download-manifest.json, wheels-verified.json and wheel-inspection.json
record URLs, sizes, hashes, tool identity and observed metadata. Bounded ZIP
inspection checked safe names/types, no extraction, eight METADATA/WHEEL records,
CPython/platform/ABI compatibility, Requires-Python and every wheel RECORD
payload hash/size. Linux 3.12 non-extra Requires-Dist closure is complete:
openpyxl -> et-xmlfile; pydantic -> annotated-types/core/typing-extensions/
typing-inspection; core and inspection -> typing-extensions. No other package
was downloaded or added. This is static wheel evidence, not native import success.

Downloaded audit copies live under ignored var/step8cr-inspection/wheelhouse/;
build copies under **var/parser-wheelhouse/linux-amd64-cp312/**. Wheels are never
Git staging candidates. Dockerfile/ignore rules enumerate exactly eight filenames,
not a permissive directory/glob. pip installs only from /build/wheels with
--no-index/--find-links, existing --require-hashes/--only-binary/--no-deps, inside
the build stage. No wheel archive or pip installer is copied to the final image.

### Necessary packaging corrections and build outcomes

The unchanged immutable source was not locally available by its exact reference.
Approved pull succeeded, exit 0:

```powershell
docker --context desktop-linux pull --platform=linux/amd64 docker.io/library/python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70
```

Three network-disabled builds exited 0; the first two were intermediate static
review images, not accepted final evidence:

1. Initial offline build: local ID
   sha256:5bc5f461bc5b260afa8b4618f3069b0cd4f169c28d971bf3aba9934712fec19f.
   Static review found CPython config/python.o build assets copied with stdlib.
2. After excluding config-3.12-*:
   sha256:d1e1903ddc2556548f77fd4b65548baf75ddf045467ca4a5c94f8571088772a5.
   Complete ELF review found _tkinter still copied although its Python-level GUI
   tree was excluded; libtk8.6.so and libtcl8.6.so were absent. CPython native
   self-test/example extensions were also unnecessary retained assets.
3. Reviewed final build excludes config-3.12-*, _tkinter.*, _test*, _ctypes_test.*,
   _xxtestfuzz.* and xxlimited*. Final archive verifies their absence, no .o/.a
   objects, and no unresolved DT_NEEDED reference among all retained ELF files.
   No GUI libraries were added and no parser dependency/version was changed.

Exact final command and observed result:

```powershell
docker --context desktop-linux build --network=none --platform=linux/amd64 --pull=false --provenance=false --load --progress=plain --tag sheetsafe-parser:static-review --iidfile var/step8cr-inspection/image-id-reviewed.txt --file parser_worker/image/Dockerfile .
```

**Exit 0.** Context allowlist: 22 regular inputs, 14 source/build + 8 wheels,
3,076,666 bytes of actual reviewed input files. BuildKit transfer reports about
3.07 MB; cached transfer sizes are not a complete context inventory. Each input
and in-project ancestor was checked for links/reparse points; input hashes are
recorded in ignored build-inputs.json. Source/test canaries reject credentials,
DBs, uploads, venvs, audit logs and arbitrary/unapproved/Windows wheels.

Both RUN steps had network=none; installation log used only /build/wheels.
--network=none does not forbid registry metadata resolution: the base was pulled
separately and BuildKit resolved its unchanged pin before using cached content.
No claim is made that the entire build process had zero registry communication.
No secret build argument, host bind, runtime dependency installation or daemon
access from web services was introduced.

Warnings retained: BuildKit FromPlatformFlagConstDisallowed for the intentionally
fixed linux/amd64 source; pip's root-user advisory **inside the isolated build
stage**, not a host installation or the final configured runtime user. Neither
warning was hidden or bypassed. They are distinct from the pytest warning below.

### Final image identity and actual configuration

| Identity | Verified value |
| --- | --- |
| Local review tag | sheetsafe-parser:static-review |
| Local final image ID / exported OCI manifest hash | sha256:8e7cc8280be3fb2dd6b717cb6c0a2543ee60104678598c66ddb57ea1ffaae3ed |
| Final configuration blob digest | sha256:9a3f00ea6fdf63f5742d176e675334990d28fe81b409761aaccb04e66e3fee6e |
| Source registry index digest | sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70 |
| Source linux/amd64 manifest digest | sha256:57d96f71de145a98e7ceca18ee4ade77bba4103a33a72dfaea026b23625c6bf0 |
| Source configuration digest | sha256:3c4d812a6efe003770aafbdba65f9c1960ba8234ab23a133934205a70bdcda77 |
| Verified remote parser registry digest | None; no parser registry push |
| Parser approved execution identity | None |

iidfile, tag lookup, immutable-ID lookup and SHA-256 of the exported OCI manifest
agree. Its descriptor binds the separately hashed config blob. Source registry
raw index/amd64 manifest hashes were freshly checked, binding the saved base's
configuration/layer contents. Docker reports a parser RepoDigest containing the
local manifest hash; that is **not** independent evidence of a remote registry
publication/digest. The earlier smoke image is neither parser identity nor fallback.

Actual inspected configuration: Linux/amd64; user **10001:10001**; workdir /work;
stop signal SIGTERM; exactly PATH=/usr/local/bin, LANG=C.UTF-8, HOME=/nonexistent.
No inherited base GPG_KEY/PYTHON_* environment entries. Entrypoint:

```json
["/usr/local/bin/python3.12", "-I", "-S", "-B", "-u", "/opt/sheetsafe/bootstrap.py"]
```

Config.Cmd is absent/null (no default arguments; Dockerfile CMD []). No configured
volumes, ports, OnBuild, shell override or healthcheck. Image size reported by
Docker: **155,853,218 bytes**; saved image archive: **41,173,504 bytes**.
These are different size measures, not a RAM/CPU capacity measurement.

### Bounded static filesystem/dependency evidence

Actual commands, all exit 0 after the explained corrections:

```powershell
docker --context desktop-linux image inspect sheetsafe-parser:static-review
docker --context desktop-linux image save --output var/step8cr-inspection/parser-image-reviewed.tar sheetsafe-parser:static-review
docker --context desktop-linux image save --platform=linux/amd64 --output var/step8cr-inspection/base-image.tar docker.io/library/python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70
.\.venv\Scripts\python.exe -I var/step8cr-inspection/inspect_image.py
.\.venv\Scripts\python.exe -I var/step8cr-inspection/context_audit.py
```

Ignored operator helpers do not extract paths, run ldd/guest binaries, import the
downloaded packages or call any container lifecycle API. They bound archive,
member counts/sizes, decompression and link resolution; reject unsafe paths/
special members; hash OCI manifests/config/compressed blobs/uncompressed DiffIDs;
and merge layers with whiteout handling. No container was used for inspection.

Final merged inventory: **2,343 paths**, six layers. DiffIDs:

```text
sha256:911a7712ea4d8c47af469b905ae6cc54c3b4aae67b91ea96d12c778180c182f4
sha256:6833927ad24a6b9a16d5fae4785bcbda33b206d1d183173bc475333f9b04a120
sha256:4fcf2a55a7aae6a2ebd0cd7e9340eaa563ffa140a17acb469b21a0de1d8cef9d
sha256:c725d749c0f8e8627887f77e236fa7ea0aff5a77199116391517c4f69aab8f63
sha256:118ccdd1736bc719144cc15b0ce0cb923e0c171f3b1269b53d0475a516e20e84
sha256:7eba78824fe6f3359bd124b069533d5c336587e89863b06b4218cc78e2ef6130
```

- Ten expected app/bootstrap files are byte-identical to reviewed host source,
  root-owned 0:0 and mode 0444. No other app module is present; backend, runner,
  repository, DB, env files, uploads and private worksheets are absent from the
  checked image paths. Bootstrap hash:
  sha256:da703ff164ada008f9f02bd1137b2c941a2caaff7ffbf6729688e750b1462152.
- Exactly the eight locked installed package METADATA versions match. All 364
  wheel payload file paths are accounted for: original payload bytes match,
  except RECORD files which pip rewrites for its installation bookkeeping.
  Only 16 expected empty REQUESTED / pip INSTALLER metadata files are additional.
  All 426 vendor entries are root-owned with no group/world write permissions.
- 1,736 retained runtime files match the freshly verified pinned base. Its Python
  header records 3.12.15; the final executable/stdlib bytes match that source.
  There is no requirement that host Python 3.12.13 and image patch version match.
- All **536 ELF file instances** were checked as ELF64/x86_64 with loader and
  DT_NEEDED references resolving to image paths under recorded search directories.
  Includes CPython, pydantic-core, zlib/expat and required standard extensions.
  Some native libraries are duplicated by dereferenced base links. File presence
  and this static graph do not prove dynamic loader selection, symbol-version/ABI
  compatibility, imports, locale behavior or successful parsing.
- No checked shell/pip/package-manager/compiler executable, Python header tree,
  config object/static archive, GUI/native test extension, wheel archive, build
  directory, pyc cache, DB, raw worksheet or host source path remains. Bounded
  credential signatures (regular files <=2 MiB) found zero hits. Exact source/
  wheel/base provenance is stronger evidence than heuristic secret scanning;
  neither is a vulnerability or malware certification.

Native closure remains conservative, not measured minimal; no complete SBOM,
license or current vulnerability assessment is claimed. Python still has general
stdlib capabilities: a minimal filesystem is not an OS sandbox. Runtime imports,
hard resource limits and enforcement all remain UNVERIFIED.

Audit development failures were not hidden: an initial inline Python diagnostic
lost quotes under PowerShell and was replaced with file-based helpers. The first
archive helper assumed the base local ID was a platform manifest; inspection
proved it is a source index while --platform export contains the amd64 manifest.
The helper now verifies that explicit index -> platform manifest -> config chain.
Its subsequent fail-closed ELF findings drove the two staging corrections above;
the final complete static audit exits 0, with no missing reference suppressed.

### Runtime gates and next smallest delivery

Fresh actual read-only host evidence:

```powershell
uv run --frozen --no-sync python -m runner.host_readiness --context desktop-linux
```

Exit **2**, as designed for pending readiness. Preflight channel local-npipe;
issues exactly **LSM_NOT_ADVERTISED**; execution_enabled false; SEC01-SEC10 all
UNVERIFIED. This probe still selects the previously reviewed smoke image for
its existing image contract; it does not admit the new parser image. Parser
approved_image_id remains None, require_parser_execution_ready still rejects,
and production entrypoint remains closed with parser_transport_unavailable / 78.

Native Linux prerequisite evidence, enforcing LSM/seccomp, cgroup limits/swap,
effective environment/network/filesystem isolation, watchdog and independent
verified teardown remain mandatory. The stopped-container archive/read-only
root/tmpfs compatibility and transport PRD amendment are still unresolved and
unapproved; late dispatch fencing/quiescence is unchanged. Windows Docker Desktop
does not certify a Linux Vultr VM, and no native host was provisioned.

Shortest next step: obtain read-only prerequisite evidence on an existing native
Linux host and decide the transport amendment explicitly. Then separately approve
a bounded fixed synthetic parser containment run with measured effective
restrictions and verified teardown. Runtime import checks belong in that approved
isolated run; no temporary host execution or insecure mount/LSM fallback. Production
durable dispatch/upload integration follows those gates, not another fake-only
subsystem. No execution approval is implied by this build record.

Official references used for preparation:
[pip cross-platform download](https://pip.pypa.io/en/stable/cli/pip_download/) and
[pip hash-checking/wheel-only mode](https://pip.pypa.io/en/stable/topics/secure-installs/).

### Actual Step 8C-R regression results and Git state

Final commands after both staging corrections:

```powershell
uv run --frozen --no-sync python -m pytest tests/test_parser_image.py tests/test_parser_policy.py tests/test_parser_jobs.py tests/test_parser_entrypoint.py tests/test_csv_parser.py tests/test_xlsx_parser.py tests/test_ingestion_contracts.py tests/test_ingestion_boundary.py -q -x -rs -p no:cacheprovider --basetemp var/step8cr-focused-reviewed-20261025
# 246 passed, 1 warning in 11.31s; exit 0
uv run --frozen --no-sync python -m pytest tests/test_runner_policy.py tests/test_runner_image.py tests/test_runner_preflight.py tests/test_runner_lifecycle.py tests/test_host_readiness.py tests/test_transport_protocol.py tests/test_transport_state.py -q -x -rs -p no:cacheprovider --basetemp var/step8cr-runner-20261025
# 697 passed in 1.66s; exit 0
uv run --frozen --no-sync python -m pytest -q -x -rs -p no:cacheprovider --basetemp var/step8cr-full-20261025
# 1329 passed, 1 skipped, 1 warning in 67.41s; exit 0
uv run --frozen --no-sync python -m compileall -q backend runner ingestion parser_worker tests
# exit 0
uv run --frozen --no-sync python var/step8b_scope_audit.py
# 16 expected text paths; zero known credential signatures; zero staged; exit 0
git diff --check
# exit 0
```

The full total is the prior 1324 tests plus five new offline context/install
security cases. No pytest failure or security assertion was bypassed. Earlier
67 image/policy tests and 246 focused cases also passed during preparation; the
results above are the final source state. Skip remains tests/test_storage.py:176,
Windows OS symlink privilege unavailable; mandatory native Linux follow-up.
The existing Starlette TestClient/httpx deprecation warning remains visible.
Build warnings and Git LF/CRLF advisories are separate, as described above.

Step 8C-R edited exactly these six already-present review files:

- README.md: current status/evidence and disabled runtime limitations.
- docs/parser-worker.md: this recovery/build/static inspection record.
- parser_worker/image/Dockerfile: eight explicit offline inputs and no-index pip.
- parser_worker/image/Dockerfile.dockerignore: exact ignored-wheel allowlist.
- parser_worker/image/stage_runtime.py: exclude confirmed build/GUI/test assets.
- tests/test_parser_image.py: preserve source protections, enforce exact local
  wheels/no-index install and reject extra/Windows/secret/audit context inputs.

No new tracked-path candidate was added beyond the inherited Step 8B set.
Full working tree: **3 modified, 13 untracked, zero staged**; HEAD and local
origin/main remain e28c3b3. No fetch/commit/push; remote state was not refreshed.
Existing backend, schema/migrations, auth, storage, old runner policy/lifecycle,
parser algorithms/contracts, requirements.lock, pyproject.toml and uv.lock are
unchanged. .gitignore is unchanged: .env/.env.local remain ignored and
.env.example remains tracked. Wheels, all three image exports/iidfiles, base
export, helper scripts, metadata, logs and test data remain ignored under var/.

Final scope checks cover all 16 modified/untracked text paths, known credential
patterns, Python parse, Markdown links/fences and tracked/untracked whitespace.
Source hashes in the image match current reviewed files. Signature scans are
bounded heuristics; no claim is made about every possible secret/CVE.
Final read-only Engine inventory also confirmed Containers=0, Running=0,
Stopped=0; the review tag still resolved to the exact final image ID above.

Reproducibility limitations: immutable base and exact wheels fix major content
inputs, but source timestamps, pip INSTALLER/RECORD generation, BuildKit/Engine
version and filesystem metadata can change output IDs. No byte-identical rebuild
guarantee or runtime security certification is claimed. Current final identity
was observed and verified, not invented or automatically execution-approved.
