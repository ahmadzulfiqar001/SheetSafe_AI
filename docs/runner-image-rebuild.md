# Step 7F: hardened rebuild and static verification

Historical Step 7F evidence. Step 7G subsequently pins this reviewed local
identity pair for static selection and detects fixed-tag reassignment. See the
[current admission record](runner-preflight.md#step-7g-local-static-image-admission).
The statements below about old pins describe Step 7F; execution remains disabled.

Observed on 2026-10-22, from HEAD `169effb` with the uncommitted Step 7E
definition/test changes. Build, metadata inspection and offline layer audit
passed. No container was created, started or executed; no guest Python/ELF binary
or payload ran. No registry push, commit, deployment or cloud expenditure occurred.
All SEC01-SEC10 runtime controls remain **UNVERIFIED**.

## Reviewed build inputs and outcome

The context is only `runner/image`, with the unchanged three-file `.dockerignore`
whitelist: Dockerfile, `.dockerignore`, bootstrap.py. The source stage is pinned;
the independent scratch stage copies that source filesystem, then declares the
reviewed metadata. No RUN, ARG, installer, remote ADD, mounts, volumes, ports or
build secrets are used. Credentials, backend/application code, virtual
environments, databases, uploads and unrelated host files are excluded.

The only Step 7F source edit updates the Dockerfile's status comment; the Step 7E
instruction graph, fixed bootstrap and policy are unchanged. Build input SHA-256:

| Input | SHA-256 |
| --- | --- |
| Dockerfile | `3b53ef2cd533d4323f609e3da27f78d5a9759d29f964f89870b3150bb7ccffea` |
| .dockerignore | `52ebb737177a46a6c18c54e65ea095449efb577bb2672096876f77084f4125e2` |
| bootstrap.py | `0d79451efdc367695efc7c785491bcc93f5dc507b1d0fafcfd6e14c89b4c7e4d` |

Exact command, with a previously absent review tag and a new ignored audit folder:

```powershell
docker --context desktop-linux build --network=none --platform=linux/amd64 --provenance=false --load --tag sheetsafe-runner:environment-review --iidfile var/step7f-inspection/image-id.txt runner/image
```

**Exit 0**, Docker Desktop Linux backend, BuildKit Docker driver. The pinned source
was cached. The log reported 34 bytes of cached context transfer; that is not the
complete context's size. `--network=none` restricts build-step networking, not
registry resolution or eventual runtime networking. There are no RUN steps here.
No inference key or placeholder was supplied. The old `sheetsafe-runner:smoke-v1`
tag still resolves to its original reviewed image ID after the build.

## Distinct immutable identities

| Meaning | Observed value |
| --- | --- |
| Source registry index digest | `sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70` |
| Source linux/amd64 manifest recorded in Step 7B | `sha256:57d96f71de145a98e7ceca18ee4ade77bba4103a33a72dfaea026b23625c6bf0` |
| New local image ID / OCI manifest hash | `sha256:551ae45bad03b4a1856ae503c62c01a8078394a19d3c318b53fc9f2e98f66bc9` |
| New configuration blob digest | `sha256:59f66d35ff913f60851bde600c75680bc0054c04f32ba72ec42ca2ae2ec6d546` |
| Preserved old local image ID | `sha256:4f6d2d12fcecf7c70e7923186c698785cfdf0b370a89c5cee186896207f01756` |
| Preserved old configuration digest | `sha256:0d78a20a59527cde284674316413b4d1bd5ba66ac95a7639be6b4823fdba1965` |
| Remotely verified runner registry digest | None |
| New image identity approved for execution | None |

Docker locally reports RepoDigests containing
`sheetsafe-runner@sha256:551ae45bad03b4a1856ae503c62c01a8078394a19d3c318b53fc9f2e98f66bc9`.
This is not evidence of a published/verified registry manifest. The image ID was
matched to the BuildKit iidfile, inspected metadata and SHA-256 of the exported
OCI manifest; its descriptor binds the independently hashed configuration blob.
Do not confuse that configuration digest with this backend's local image ID.

`LOCAL_IMAGE_ID` and `LOCAL_CONFIG_DIGEST` still bind the old reviewed pair.
`SandboxPolicy.final_image_digest` remains absent and execution stays disabled.
The new mutable review tag is not an admitted runtime reference. No parser was
weakened or monkeypatched to accept the new image automatically.

## Actual new image configuration

- Platform: Linux/amd64.
- User: `10001:10001`; workdir: `/work`; stop signal: `SIGTERM`.
- Entrypoint: `["/usr/local/bin/python", "-I", "-S", "-B", "-u", "/opt/sheetsafe/bootstrap.py"]`.
- Command: `["smoke-v1"]`; ArgsEscaped: true.
- Exactly three environment entries, no duplicates:

```text
PATH=/usr/local/bin:/usr/bin:/bin
LANG=C.UTF-8
HOME=/nonexistent
```

No GPG_KEY, PYTHON_VERSION or PYTHON_SHA256 survives in Config.Env. No additional
environment key/value was accepted. The new image's static environment mismatch
is resolved. The unchanged application preflight intentionally still inspects the
old image and reports its mismatch; new-image admission is a separate review.
No effective process environment was observed. Daemon-added HOSTNAME and other
runtime sources still require an enforced, measured environment boundary.

Labels are exactly `org.opencontainers.image.title=SheetSafe fixed smoke fixture`,
`org.opencontainers.image.version=smoke-v1` and
`io.sheetsafe.policy=sheetsafe-smoke-policy-v1`. There are no configured volumes,
exposed ports or OnBuild hooks. Configured identity/startup are static evidence,
not proof of actual non-root execution or effective isolation.

Docker reports image size **182,537,137 bytes**. The saved archive is
**45,490,176 bytes**; these are different measures. Three rootfs DiffIDs:

```text
sha256:f8659f5145bb1981d2ebead617f823511be97d0e096078cfccf9f7079a6e5d41
sha256:98d6962a831111c1c2b26799e6f4ac9dce7c1ac4a74453ff2776d6b340e22cad
sha256:6937c20303fdd1e3e03e966b25f47405780bb6379e6199978cfb0fb24ff05231
```

Their uncompressed tar lengths were 125,671,936, 6,656 and 1,536 bytes. The first
layer copies the source tree; the latter layers add bootstrap and `/work`.

## Offline filesystem evidence and limits

```powershell
docker --context desktop-linux image inspect sheetsafe-runner:environment-review
docker --context desktop-linux image save --output var/step7f-inspection/runner-image.tar sheetsafe-runner:environment-review
.\.venv\Scripts\python.exe var/step7f-inspection/inspect_image.py
```

All exited 0. The local one-off host audit reported `METADATA_OK` and
`OFFLINE_AUDIT_OK`. Raw metadata, iidfile, summary, archives and audit helper live
under ignored `var/step7f-inspection`; they are not staging candidates. The helper
is a local audit artifact, not a production verifier or tracked CI tool. Image
save exports image contents without requiring a container; see
[Docker image save](https://docs.docker.com/reference/cli/docker/image/save/).

The audit reads bounded tar/gzip members in memory and never extracts their
paths onto the host. It rejects unsafe member names/types and verifies OCI
manifest, config, compressed layer hashes and uncompressed DiffIDs. The merged
inventory matches all **6,596 paths** in the old reviewed archive. **5,051 regular
or hardlinked file contents and modes** match that reference; symlink targets
also match. This is not a claim that all directory/ownership metadata is equal.
Bootstrap is separately verified as root `0:0`, mode `0444`, 3,841 bytes, with
the unchanged input SHA-256 above and byte-identical old/new content.

Python headers record **3.12.15**, pip metadata records **25.0.1**, and Debian
metadata lists **105 installed packages**. Standard library/encodings files,
Python executable, libpython and ELF loader are present. A static ELF64/x86_64
PT_INTERP/DT_NEEDED inspection of Python plus 14 selected extensions resolved
**26 ELF files** inside the image. Extensions checked were `_json`, `_sha2`,
`_hashlib`, `_ssl`, `_sqlite3`, `_bz2`, `_lzma`, `_ctypes`, `zlib`, `binascii`,
`math`, `select`, `_socket` and `unicodedata`. Resolved files include libc, libm,
libssl/libcrypto, sqlite3, bz2, lzma, ffi and zlib. No ldd or guest binary ran.
This proves static file/dependency presence for the inspected roots, not dynamic
loader selection, ABI/import success, all optional extensions or runtime health.

Shell/dash, pip, Python headers and inherited Debian tooling remain, as expected
from the complete source-tree copy. Filesystem minimization and vulnerability
assessment remain separate work; no package installation occurred. No extra
project/host dataset, database, venv or credential path was found. A bounded
credential-signature scan of regular files up to 2 MiB found zero hits; this is
a heuristic, not a secret-free or malware certification. Equality to the reviewed
reference and the context whitelist are the stronger provenance checks here.

## Automated verification

```powershell
uv run --frozen --no-sync python -m pytest tests/test_runner_image.py tests/test_runner_policy.py -q -p no:cacheprovider
# 100 passed in 0.17s
uv run --frozen --no-sync python -m pytest tests/test_runner_preflight.py tests/test_runner_lifecycle.py -q -p no:cacheprovider
# 300 passed in 0.86s
uv run --frozen --no-sync python -m pytest -q -rs -p no:cacheprovider --basetemp var/step7f-tests-20261022
# 626 passed, 1 skipped, 1 warning in 24.18s
uv run --frozen --no-sync python -m compileall -q backend runner tests
# exit 0
git diff --check
# exit 0
uv run --frozen --no-sync python -m var.step7f-inspection.final_checks
# exit 0; new environment == canonical SandboxPolicy.environment
# current pin issues: LSM_NOT_ADVERTISED, IMAGE_ENVIRONMENT_MISMATCH
# metadata_prerequisites_met=False; execution_enabled=False; all 10 SEC unverified
# 0 credential-pattern hits across 9 unstaged source/test/documentation files
```

Tests were executed in the existing uv/Python 3.12 environment; they were not
changed to accept unexpected metadata in Step 7F. The skip is
`tests/test_storage.py::test_symlink_read_cleanup_and_ancestor_rejected` because
Windows refused file-symlink creation. It must pass without skipping on native
Linux storage as documented in the runner plan. Real Windows junction/hardlink
tests passed. The existing warning is Starlette's deprecated TestClient/httpx
integration; it was not hidden. Git LF/CRLF advisories are separate.

Two initial ad-hoc final diagnostic invocations failed before Docker queries:
one used an incorrect client class name; another lost quotes through PowerShell's
native argument handling. The corrected local module command above passed.
No implementation, build, offline-audit or automated-test failure occurred.

## File and Git review

Step 7F adds this document and updates README.md, runner-foundation-plan.md,
runner-image-inspection.md, runner-image-environment.md and runner-preflight.md.
Its only source edit is the Dockerfile's status comment. The two changed test
files below and the rest of the Dockerfile definition are inherited uncommitted
Step 7E changes, preserved and re-tested here. Combined working tree:

```text
 M README.md
 M docs/runner-foundation-plan.md
 M docs/runner-image-inspection.md
 M docs/runner-preflight.md
 M runner/image/Dockerfile
 M tests/test_runner_image.py
 M tests/test_runner_preflight.py
?? docs/runner-image-environment.md
?? docs/runner-image-rebuild.md
```

HEAD remains `169effb`; nothing is staged, committed or pushed. `.env` and
`.env.local`, `.venv` and all `var/` archives/metadata remain ignored;
`.env.example` remains tracked. Changed files contain no detected private-key,
GitHub-token, AWS-access-ID or OpenAI-key signature; pattern scans are heuristic.
No backend, migration, authentication, dependency or runtime-policy file changed.
Whitespace checks also covered the two untracked Markdown files.

## Remaining blockers and proposed next review

- All SEC01-SEC10 runtime controls remain UNVERIFIED: non-root execution, network
  denial, read-only root/bounded tmpfs, CPU/memory/PID and syscall restrictions,
  watchdog/time accounting, fresh-runtime isolation and verified teardown.
- `LSM_NOT_ADVERTISED` remains blocking; no AppArmor/SELinux exemption or host
  security change was introduced. Desktop tests do not certify a Vultr VM.
- Exact effective process ENV, stopped-container input/read-only-root/tmpfs
  compatibility, pre-stop artifact collection, cancellation and durable orphan
  recovery remain unresolved. No bind-mount or post-start-upload workaround.
- No lifecycle transport, execution command, arbitrary dispatch, generated-code
  execution, uploads or inference has been enabled. Web services retain no
  Docker daemon access.

Next smallest proposed increment: review and explicitly update the local
manifest/config pin pair in the read-only metadata contract, with substitution
rejection tests and execution still disabled. Keep registry identity absent
until a real registry verification exists. Separately verify the supported
Linux host's LSM/profile, cgroups, seccomp, filesystem/storage and service
permissions before any approved runtime experiment. No provisioning or cloud
spend is authorized. Await review before any next implementation.
