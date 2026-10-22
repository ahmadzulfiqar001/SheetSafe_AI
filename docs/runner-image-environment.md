# Step 7E: image environment hardening, first increment

Historical Step 7E record. Step 7F subsequently built the reviewed definition and
verified its exact image ENV and offline filesystem under a separate review tag;
see [runner-image-rebuild.md](runner-image-rebuild.md). The old preflight pins and
disabled execution remain unchanged. Statements below about no rebuild describe
Step 7E only; image metadata matching is not effective runtime verification.

Prepared on 2026-10-22 from clean HEAD `169effb` (the request's `4a13b0f` predates
the approved Step 7D push). Definition/static verification only. No Docker build,
check-only build, container execution, dependency installation, commit or push was
performed. **IMAGE_ENVIRONMENT_MISMATCH is not resolved in a newly built image.**

## Confirmed cause and environment comparison

The approved immutable `SandboxPolicy.environment` is exactly:

```text
LANG=C.UTF-8
HOME=/nonexistent
PATH=/usr/local/bin:/usr/bin:/bin
```

The old single-stage `FROM python...` inherited its base configuration. Its ENV
instruction replaced PATH/LANG and added HOME, but retained three public Python
release/signing metadata variables. The unchanged preflight parser correctly
reports `IMAGE_ENVIRONMENT_MISMATCH`; emptying unwanted values leaves their keys
and still fails. They are not private credentials, but they are outside policy.

| Key | Pinned Python source config | Existing built runner config | New final definition / planned container request |
| --- | --- | --- | --- |
| LANG | `C.UTF-8` | `C.UTF-8` | `C.UTF-8` |
| HOME | Absent | `/nonexistent` | `/nonexistent` |
| PATH | Base's broader path, including sbin directories | `/usr/local/bin:/usr/bin:/bin` | `/usr/local/bin:/usr/bin:/bin` |
| GPG_KEY | Public signing identity | Inherited | Absent |
| PYTHON_VERSION | `3.12.15` | Inherited | Absent |
| PYTHON_SHA256 | Public source release hash | Inherited | Absent |

The exact source PATH recorded by Step 7B is
`/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`.
The source digest and prior registry configuration/layer inventory remain in the
[Step 7B record](runner-image-inspection.md). A fresh read-only Step 7E preflight
again observed all six existing runner environment names and both existing
blockers. No host/cloud/session variables were passed into a candidate runtime.

Docker's process environment is a separate layer: Docker documents automatic
HOME, HOSTNAME, PATH and, with a pseudo-TTY, TERM. The fixed policy supplies HOME
and PATH explicitly, and disables TTY. **HOSTNAME still needs effective runtime
verification**; image `Config.Env` or the requested container `Env` alone cannot
prove an exact process environment. No container was started to observe it here.
The fixed bootstrap is unchanged and does not yet prune that daemon-added key.
A later trusted launch/environment boundary must construct and measure the exact
candidate environment, or fail closed. No bootstrap-phase policy exception or
HOSTNAME allowlist expansion is approved by this change.
Source: [Docker process environment defaults](https://docs.docker.com/engine/containers/run/#environment-variables).

## Minimal definition change and dependency implications

The Dockerfile now uses exactly two stages:

```dockerfile
FROM docker.io/library/python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70 AS python_source
FROM scratch
COPY --from=python_source / /
```

The final stage separately declares only approved ENV, existing labels, the
root-owned mode-0444 bootstrap copy, UID/GID 10001, `/work`, SIGTERM and the existing
exec-form Python entrypoint with `-I -S -B -u` and `smoke-v1`. There is no RUN,
ARG, network installer, remote ADD, exposed port, volume, host path or caller
substitution. The original three-file context whitelist is unchanged.

An independent scratch stage receives copied filesystem content rather than
parent image configuration. This isolates the environment definition while
retaining the complete reviewed Python/runtime/library filesystem initially.
It is **not filesystem minimization**: shells/dash, pip, headers and the inherited
Debian packages remain. The copied source is immutable; it is not the host root
or repository. No component was blindly deleted and no package is installed at
candidate execution time. See [Docker ENV inheritance](https://docs.docker.com/reference/dockerfile/#env)
and [independent build stages](https://docs.docker.com/build/building/multi-stage/).

Copying only a Python binary into scratch would omit its ELF loader, shared
libraries, standard library, encodings and extension dependencies. Retaining the
reviewed tree avoids assuming a dependency closure before actual isolated import
tests are authorized. Selective removal of pip/headers/shells needs a separate
audited dependency inventory, build inspection and approved compatibility tests.
The current fixture is standard-library-only; future spreadsheet dependencies
are not provided by this image. New-build ownership, links, libraries, metadata
and bootstrap permissions still require archive inspection before use.

The old static test allowed one pinned FROM. It now requires the exact reviewed
source digest/alias, independent scratch stage and exact instruction graph/copies.
It forbids extra stages, ENV declarations, ARG overrides, commands and context
copies. This changes the approved build graph while preserving stricter startup,
identity and environment checks; it does not accept weakened runtime policy.

Existing `parse_image` validation needed no production code change. New tests
prove rejection of inherited/default/credential environment keys even when empty,
missing required keys and changed values. Rejection of image substitutions,
privileged startup and unsafe metadata remains covered by the existing suite.
Synthetic responses test validation only; they are not a new image inspection.

## Immutable identity and build review boundary

The old reviewed local image ID remains
`sha256:4f6d2d12fcecf7c70e7923186c698785cfdf0b370a89c5cee186896207f01756`,
and its reviewed configuration digest remains
`sha256:0d78a20a59527cde284674316413b4d1bd5ba66ac95a7639be6b4823fdba1965`.
No new digest is known or invented. `LOCAL_IMAGE_ID`, `LOCAL_CONFIG_DIGEST`, policy
final digest and disabled execution are unchanged. A future new image will fail
the old identity pin until separately inspected and approved; do not substitute
it automatically or use the mutable tag to bypass that review.

Next increment ready for approval: build this reviewed definition under a separate
local review tag, preserving the old image; inspect actual configuration, layers,
files, dependencies and bootstrap, with no smoke execution. Confirm exactly the
three required image ENV keys/values, record actual local/config IDs and any
reported RepoDigests without claiming remote verification, then review identity
pin updates separately. The previous one-off archive script assumes the old base
layer prefix; that assumption must be revised for a flattened filesystem copy,
not bypassed to fabricate a successful audit. Reproducible reviewed inputs are
the goal; timestamp-dependent output hashes are not promised to repeat.

## LSM investigation and remaining release gates

Fresh read-only preflight on Docker Desktop 4.96.0 / Engine 29.9.1 / API 1.56,
Linux/amd64, WSL2 kernel `6.18.54.1-microsoft-standard-WSL2`, still reported:

```text
LSM_NOT_ADVERTISED
IMAGE_ENVIRONMENT_MISMATCH
execution_enabled=False
```

Engine info advertises builtin seccomp and cgroup namespaces, not AppArmor or
SELinux. Runc's compiled support is not evidence that the daemon enabled or
enforced those LSMs. These are local observations, not a claim about all WSL2 or
Docker Desktop installations. Host security settings were not changed.

The existing PRD SEC07 contract says to enforce available AppArmor/SELinux;
`require_available_lsm=True` remains fixed. The current supported metadata mapping
requires advertised AppArmor and `docker-default`, so this local environment
remains blocked. No unconfined profile, implicit LSM exemption or downgraded
gate was introduced. SELinux-only mapping still requires explicit review.

Static/unit development may continue locally. Deployment release needs effective
LSM/profile verification, along with all other isolation probes, on the supported
Linux target/Vultr VM. Its actual kernel, LSM state, enforcement mode, daemon
permissions and cgroups must be measured; this is not authorization to provision,
deploy or spend credits. Desktop tests cannot certify that target.

The stopped-container archive/read-only-root/tmpfs and pre-stop artifact collection
conflicts remain in [the lifecycle review](runner-lifecycle.md) and
[the Step 7D transport proposal](runner-preflight.md). No uploads or transfer
workaround were enabled. All SEC01-SEC10 runtime controls, effective process ENV,
watchdog/CPU accounting, independent validation and durable cleanup remain
UNVERIFIED. An image metadata fix alone will not clear those release gates.

## Actual automated verification

```powershell
uv run --frozen --no-sync python -m pytest tests/test_runner_image.py tests/test_runner_policy.py -q -p no:cacheprovider
# 100 passed in 0.47s
uv run --frozen --no-sync python -m pytest tests/test_runner_preflight.py tests/test_runner_lifecycle.py -q -p no:cacheprovider
# 300 passed in 1.25s
uv run --frozen --no-sync python -m pytest -q -rs -p no:cacheprovider --basetemp var/step7e-tests-20261022
# 626 passed, 1 skipped, 1 warning in 35.13s
uv run --frozen --no-sync python -m compileall -q backend runner tests
# exit 0
git diff --check
# exit 0
```

The existing Windows file-symlink privilege skip and Starlette/httpx deprecation
warning remain. No test failure occurred. Git line-ending advisories are separate.
Bootstrap SHA-256 is unchanged:
`0d79451efdc367695efc7c785491bcc93f5dc507b1d0fafcfd6e14c89b4c7e4d`.
No backend/configuration/dependency changes or execution-policy changes were made.
