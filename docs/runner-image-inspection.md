# Step 7B: local runner image build and static inspection

This is the historical Step 7B record. The subsequent fake-only lifecycle adapter
and additional archive/environment admission blockers are documented in
[runner-lifecycle.md](runner-lifecycle.md). The old image is preserved unchanged.
Step 7E changed the Dockerfile; Step 7F built and inspected that definition under
a separate review tag. The hashes/layers below describe only the historical
Step 7B build. See the [environment hardening review](runner-image-environment.md)
and [Step 7F rebuild evidence](runner-image-rebuild.md) for the new image.

Observed on 2026-10-22. Build and static inspection passed. No container was
created, started or executed for this increment. The smoke fixture did not run.
All SEC01-SEC10 runtime controls remain **UNVERIFIED**. No image was pushed to
a registry. No inference credential, build secret or build argument was used.

## Build inputs and command

Build from the reviewed `runner/image` directory, never the repository root:

```powershell
New-Item -ItemType Directory -Path var/step7b-inspection -ErrorAction Stop | Out-Null
docker build --network=none --platform=linux/amd64 --provenance=false --load --tag sheetsafe-runner:smoke-v1 --iidfile var/step7b-inspection/image-id.txt runner/image
```

Observed exit code: **0**. BuildKit used the `desktop-linux` builder with the
Docker driver. Context transfer: **3.88 kB**. The context whitelist includes only
`Dockerfile`, `.dockerignore` and `bootstrap.py`. Credentials, virtual environments,
databases, uploads and unrelated files are excluded. This Dockerfile has no
`RUN`, installer, `ARG`, remote `ADD`, volume or port declaration. Registry access
downloaded the pinned base; `--network=none` is a build-step network setting,
not proof of runtime network isolation. Provenance output was disabled explicitly;
this is a local inspection build, not a signed/reproducible release attestation.

Reviewed file SHA-256 values (unchanged by Step 7B):

| Input | SHA-256 |
| --- | --- |
| Dockerfile | `80f789e90c6aa76f2896aa33376067ea6471cd771629ed800fb7badf865782c5` |
| .dockerignore | `52ebb737177a46a6c18c54e65ea095449efb577bb2672096876f77084f4125e2` |
| bootstrap.py | `0d79451efdc367695efc7c785491bcc93f5dc507b1d0fafcfd6e14c89b4c7e4d` |

Registry metadata inspection command:

```powershell
docker buildx imagetools inspect docker.io/library/python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70 --format '{{json .Manifest}}'
```

- Immutable official base index: `sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70`.
- Selected Linux/amd64 base manifest: `sha256:57d96f71de145a98e7ceca18ee4ade77bba4103a33a72dfaea026b23625c6bf0`.
- Metadata identified Python `3.12.15-slim-bookworm`; archive header inspection
  independently identified Python `3.12.15`. Host tests used existing Python
  3.12.13; no host dependency update was made.

## Local identity: not a verified remote runner digest

Image name: `sheetsafe-runner:smoke-v1`.

Docker build iidfile and subsequent `docker image inspect` both returned:

```text
sha256:4f6d2d12fcecf7c70e7923186c698785cfdf0b370a89c5cee186896207f01756
```

On this Docker Desktop containerd image store, `.Id` is the local OCI manifest
digest. The saved archive manifest bytes hash to this value. Its referenced
configuration bytes hash to the separate configuration digest:

```text
sha256:0d78a20a59527cde284674316413b4d1bd5ba66ac95a7639be6b4823fdba1965
```

Local inspection also reported this `RepoDigests` entry:

```text
sheetsafe-runner@sha256:4f6d2d12fcecf7c70e7923186c698785cfdf0b370a89c5cee186896207f01756
```

That local entry is **not evidence of a registry-published or remotely verified
SheetSafe digest**. No such remote runner digest was established. The tag is
mutable; a later local adapter must resolve and verify the reviewed immutable
local identity without automatic pulls or caller-selected images. A release
reference requires separate review/registry verification when authorized. Policy
still has `final_image_digest=None`, `execution_enabled=False`, and an always
failing readiness gate. No digest or readiness success was fabricated.

## Inspected configuration

| Field | Actual observation |
| --- | --- |
| Platform | `linux/amd64` |
| Configured user | `10001:10001` (effective runtime identity untested) |
| Entrypoint | `["/usr/local/bin/python","-I","-S","-B","-u","/opt/sheetsafe/bootstrap.py"]` |
| Default arguments | `["smoke-v1"]` |
| Working directory / stop signal | `/work` / `SIGTERM` |
| Environment names | `PATH`, `LANG`, `HOME`, `GPG_KEY`, `PYTHON_VERSION`, `PYTHON_SHA256` |
| Explicit application environment | `PATH=/usr/local/bin:/usr/bin:/bin`, `LANG=C.UTF-8`, `HOME=/nonexistent` |
| Volumes, exposed ports, OnBuild | None |
| Labels | title `SheetSafe fixed smoke fixture`; version `smoke-v1`; policy `sheetsafe-smoke-policy-v1` |
| Bootstrap | 3,841 bytes; root-owned `0:0`; mode `0444`; byte-for-byte host fixture match |

The three inherited metadata variables describe the public Python release and
public signing identity; `GPG_KEY` is not a private credential. Image environment
exactly matched the pinned base configuration plus the three explicit application
values. No host environment was injected. The later adapter/image hardening must
resolve these inherited variables against the narrower policy environment
allowlist; setting a few Docker environment overrides alone does not remove
image-inherited names. This image is not yet approved for runtime admission.

## Filesystem and dependency inspection (no payload execution)

Commands included:

```powershell
docker image inspect sheetsafe-runner:smoke-v1 --format '{{json .}}'
docker buildx imagetools inspect docker.io/library/python@sha256:57d96f71de145a98e7ceca18ee4ade77bba4103a33a72dfaea026b23625c6bf0 --format '{{json .Image}}'
docker image save --output var/step7b-inspection/runner-image.tar sheetsafe-runner:smoke-v1
docker image history --no-trunc sheetsafe-runner:smoke-v1
docker version --format '{{json .}}'
```

A one-off standard-library audit read the saved tar and layer tar members in
memory, without extracting archive paths or launching a container. It verified
the saved manifest/config hashes, each uncompressed layer hash, the four base
layer IDs against registry configuration, and the copied fixture bytes, owner
and permissions. Added paths were exactly `opt`, `opt/sheetsafe`,
`opt/sheetsafe/bootstrap.py`, and `work`. Across all six layers, path checks found
no repository, host home, environment files, virtual environment, upload/dataset
directories or SQLite files. Credential-pattern checks on regular files up to
2 MiB found no matches; these bounded heuristic checks are not a general secret
or vulnerability certification. Exact added-file verification is the primary
evidence that this build did not incorporate private host content.

Layer DiffIDs (uncompressed filesystem hashes, not registry manifest digests):

| Layer | Origin | DiffID |
| --- | --- | --- |
| 0 | Pinned base | `sha256:9b35de7893378218e365c34c2c735fb0032a859112fb7345ca8ea73f9aa1db70` |
| 1 | Pinned base | `sha256:535ecd2088497f5955e24fd33c534fc9ba37fb717a33a841315a358dd4ff8b35` |
| 2 | Pinned base | `sha256:536ebec0f9d8119e620ed0e261faa2cfdeab88621f35924fb0ec74f646b5c53b` |
| 3 | Pinned base | `sha256:b8a5c0b25a3657c3b43a3a4cf1815f27fd7ca6c8bc3ffd36164f90731ca83db4` |
| 4 | Bootstrap COPY | `sha256:7380ce5da5fad052a3db621aa7ae62657a0568be1b9351cd7575862054866437` |
| 5 | Working directory | `sha256:91909bc29c056006d2fcd175580e9a8e7a0b4803dabb87fcccdd01768034d403` |

Static metadata inventory found 105 installed Debian packages and Python `pip`
25.0.1. Selected Debian package versions: `libc6` 2.36-9+deb12u14;
`libssl3`/`openssl` 3.0.22-1~deb12u1; `libsqlite3-0` 3.40.1-2+deb12u2;
`dash` 0.5.12-2. These are installed package/header metadata observations, not
runtime version commands. The inherited base includes `/usr/bin/sh`, `dash`,
pip and Python headers. They were not leaked host development assets, but expand
the image surface and need a separate hardening/vulnerability review. No package
was installed during this build or at runtime.

Local tooling: Docker Desktop 4.96.0, Engine 29.9.1, containerd 2.4.2, runc 1.5.2;
Linux backend kernel `6.18.54.1-microsoft-standard-WSL2`. This does not certify a
Linux Vultr VM's kernel, cgroups, LSM, swap or daemon access boundaries. Build
timestamps and output hashes are recorded observations, not a byte-reproducible
build guarantee.

## Automated verification and remaining gates

```powershell
uv run --frozen --no-sync python -m pytest tests/test_runner_policy.py tests/test_runner_image.py -q -p no:cacheprovider
# 99 passed in 0.16s
uv run --frozen --no-sync python -m pytest -q -rs -p no:cacheprovider --basetemp var/step7b-tests-20261022
# 325 passed, 1 skipped, 1 warning in 44.25s
uv run --frozen --no-sync python -m compileall -q backend runner tests
# exit 0; no syntax errors
git diff --check
# exit 0; no whitespace errors
```

The skip is `tests/test_storage.py::test_symlink_read_cleanup_and_ancestor_rejected`
(Windows OS symlink privilege unavailable). Native Linux follow-up remains
mandatory in the [runner plan](runner-foundation-plan.md). The existing warning
is Starlette's deprecation of `httpx` in TestClient; dependencies were unchanged.
Git may also print LF-to-CRLF advisory messages; these are distinct from pytest's
single warning and do not indicate a whitespace-check failure.

Verified here: pinned base identity, build context boundary, actual image
configuration, exact fixture and filesystem layer contents. Pending: effective
UID/capabilities/no-new-privileges, network denial, read-only root/tmpfs, resource
limits, watchdog, seccomp/LSM, environment enforcement, fresh runtime, output
bounds and verified teardown. No runtime SEC requirement is marked verified.
FastAPI/Streamlit received no Docker integration. No bind mounts, privileges,
untrusted code or generated code were introduced.

Next smallest task, after review: unit-test the standalone bounded Docker
create/inspect/remove adapter contract against a fake transport, with immutable
image identity checks and fail-closed configuration/cleanup handling. Real smoke
execution requires a later explicit approval and runtime verification. Future
inputs retain the stopped-container archive design; no host bind fallback.

Official command references: [image save](https://docs.docker.com/reference/cli/docker/image/save/),
[image inspect](https://docs.docker.com/reference/cli/docker/image/inspect/),
[registry imagetools inspect](https://docs.docker.com/reference/cli/docker/buildx/imagetools/inspect/).
