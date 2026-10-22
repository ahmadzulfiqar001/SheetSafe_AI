# Step 7C: stopped-container lifecycle contract

Implemented and tested on 2026-10-22 using Python 3.12.13 and existing uv.
All transport calls in this increment were in-memory fakes. No Docker CLI,
daemon connection, container creation, payload execution or image modification
was performed. All runtime SEC01-SEC10 protections remain **UNVERIFIED**.

## API and trust boundary

`runner/docker_backend.py` contains a frozen `ContainerJobSpec`, an injectable
`DockerTransport` protocol, strict inspection validation and a scoped
`DockerLifecycleAdapter.prepared(FixtureRequest)` context manager. The fake lives
only in `tests/test_runner_lifecycle.py`. There is no production Docker transport,
start/exec method, arbitrary command interface, public remove-by-ID operation or
integration with FastAPI/Streamlit. No dependencies or backend files changed.

Only the exact existing `FixtureRequest("smoke-v1")` type is accepted. Job IDs,
container names and ownership nonces are generated internally. Specification
fields have no constructor overrides; request dictionaries, image names, commands,
mounts and privilege/policy changes are not accepted. Every request body is a
fresh mapping built from the existing server-owned policy. No host environment
or `.env` settings are read. Python freezing guards routine mutation; it does not
isolate a compromised trusted runner process.

The fixed reference is Step 7B's reviewed **local** identity:
`sha256:4f6d2d12fcecf7c70e7923186c698785cfdf0b370a89c5cee186896207f01756`,
with target platform `linux/amd64`. It is not a verified remote registry digest.
A future real driver must resolve that identity without pulls, verify its
manifest/config binding and platform, and conservatively map Engine responses.
The existing `SandboxPolicy.final_image_digest=None`, disabled execution and
always-failing execution readiness gate are preserved.

## Fixed request and inspection checks

| Field | Required value |
| --- | --- |
| User | `10001:10001` |
| Image/startup | Fixed local identity; existing isolated Python bootstrap; only `smoke-v1` |
| Capabilities/privilege | Drop `ALL`, add none, privileged false, `no-new-privileges=true` |
| Network | `none`, network disabled, no ports, extra hosts, caller DNS or links |
| Root/workspaces | Read-only root; `/work` 268435456 bytes, `/tmp` 67108864 bytes; `rw,nodev,nosuid,noexec,uid=10001,gid=10001,mode=700` |
| CPU | Period 100000, quota 100000: one vCPU; **not** cumulative CPU-time enforcement |
| Memory/swap | Memory and memory-plus-swap both 1073741824 bytes |
| Processes/namespaces | 32 PIDs; private PID (Engine empty mode), IPC and cgroup namespaces |
| Mounts/devices | No binds, volumes-from, shared volumes, devices, socket or device requests |
| Environment | Exactly policy LANG, HOME and PATH; extra image/host variables rejected |
| Lifecycle/logging | No restart, no automatic removal, daemon log driver `none`; explicit inspected removal |
| Seccomp/LSM | No seccomp override; Docker default required by future effective checks. Current strict inspection contract requires `AppArmorProfile=docker-default`; other LSM mappings need explicit review, no unconfined fallback |

Metadata must identify the exact full 64-character lowercase container ID,
generated name, job/owner labels and fixed image. It must describe a fresh
`created` container, with no running process, PID, pause, restart or dead state.
Every required field and value is compared with exact types; `0` does not stand
in for `False`. Missing/extra fields, unconfined profiles, host mounts, inherited
secrets or weakened resource settings fail closed.

The inspection dictionary is a **strict internal projection**, not raw Engine
JSON. Native daemon responses contain additional fields/defaults; a future real
driver must explicitly review/validate them before constructing this projection,
not silently discard unknown security-relevant data. The representation of image
IDs, empty namespaces, tmpfs and network attachments also needs actual daemon
inspection. `configuration_verified` means this modeled contract matched; no
effective runtime protection or successful execution is inferred from it.

The current built image has three extra public Python release/signing variables.
A regression test models those observed names and rejects them. Positive fake
responses model the target contract, not the current image's readiness. Image
environment hardening and Linux LSM support remain real admission blockers.

## Lifecycle and failure behavior

The state path is `CREATING -> CREATED -> CONFIGURATION_VERIFIED -> CLEANING ->
ABSENT`; failures may go directly to cleanup or finish `UNRESOLVED`. Job outcome
is separate: pending, configuration-only, failed or cancelled. Immutable receipts
always say execution disabled and retain all ten unverified SEC controls.

The context manager always attempts scoped cleanup, including when creation or
inspection raises, the caller body fails, or cancellation/interrupt occurs. It
preserves cancellation, records sanitized error codes, and never prints raw API
exceptions, credentials, SQL, paths or user content. Ordinary unexpected API
errors remain failures even if later absence verification succeeds.

Cleanup inspects the generated name and full ID and verifies ownership before
one forced remove call. A mismatched/foreign resource is never removed. Success
requires explicit `ContainerNotFound` for **both** ID and name after removal.
An exception, timeout, malformed metadata, a no-op remove or a replacement under
the reserved name cannot count as absence. Replacement containers are not chased
or deleted. There are no sleeps, retry loops or global prune operations.

Definite `CreateRejected` means the trusted transport guarantees no creation;
the adapter also checks reserved-name absence. A lost create response may be
reconciled only through the generated name and matching ownership. With no valid
recoverable identity, absence by name alone leaves creation uncertain and blocks
admission. A real driver must not automatically retry create or allow unsettled
requests to produce resources after it reports reconciliation complete.

Only one active job is admitted per adapter. Duplicate IDs are remembered for
the instance lifetime. After unresolved cleanup the instance remains blocked,
with no public reset; failed cleanup receipts remain available. A successful
remove response alone never clears the block. A removal API error followed by
verified absence still fails the operation but records cleanup truthfully.

These locks, IDs and receipts are **in-memory**, not durable ownership leases or
restart recovery. New instances/processes cannot be treated as a reconciliation
mechanism. Before any real worker use, add a durable journal, scoped startup
reaper and operator-controlled admission gate that survives process failure.
The synchronous protocol supplies a one-second per-call timeout contract; only
a future concrete transport can enforce actual I/O/output bounds. No five-second
cancellation or wall-clock termination guarantee is claimed from these fakes.

## Stopped-container input transport investigation

The PRD's stopped-runtime archive requirement is retained. No archive API or
transfer code was added. No host binds or live `exec` upload fallback is allowed.

Docker documents that a tmpfs mounted over existing files hides those files.
Therefore pre-start copies into `/work` can become invisible at startup.
Docker's copy documentation also describes mounted/tmpfs filesystem limitations.
Sources: [Docker tmpfs](https://docs.docker.com/engine/storage/tmpfs/),
[Docker cp](https://docs.docker.com/reference/cli/docker/container/cp/).

Research found an additional obstacle: Moby's `checkWritablePath` rejects archive
extraction into a read-only rootfs outside a writable volume. This check appears
in both the reviewed tagged source and current main branch. It is source-level
evidence, not a local Docker experiment. Simply choosing `/input` instead of
`/work` does not solve it. The documented container-update interface does not
offer a read-only-root transition to rely on.
Sources: [Moby tagged archive implementation](https://raw.githubusercontent.com/moby/moby/docker-v29.1.3/daemon/archive_unix.go),
[current implementation](https://raw.githubusercontent.com/moby/moby/master/daemon/archive_unix.go),
[Docker update options](https://docs.docker.com/reference/cli/docker/container/update/).

A safe future design must provide all of these gates:

1. Allocate a fresh stopped runtime/snapshot from the fixed reviewed image with
   no candidate process admitted during input preparation.
2. Validate bounded uncompressed archive bytes before transport: fixed paths,
   no traversal, links, devices, sparse expansion, unexpected ownership or files.
3. Stage into a dedicated server-controlled `/input` region outside the future
   `/work` and `/tmp` mount points. Install root-owned, read-only input files;
   re-read bounded bytes and hashes. Do not turn private inputs into image layers.
4. Use a runtime-supported operation to seal the input snapshot/root read-only
   before startup; inspect the final policy, visibility and permissions before
   admitting any parser. A later trusted bootstrap can copy selected validated
   bytes to bounded tmpfs if required; this has not been implemented or approved.
5. Verify deletion of every input snapshot/runtime after use, including restart
   recovery, with encrypted operator storage and retention protections verified.

The reviewed Docker Engine archive/create/update combination has **not** been
shown to support steps 3-4 under the current no-bind/no-shared-volume policy.
Snapshot preparation is a research option requiring runtime capability tests and
architecture review, not a capability of this adapter. No concrete safe Docker
input-transfer sequence is claimed yet. Do not weaken `ReadonlyRootfs`, add host
mounts, commit private input images, or substitute post-start uploads. Keep input
admission disabled until this design dependency is resolved and approved.

## Observed automated verification

```powershell
uv run --frozen --no-sync python -m pytest tests/test_runner_lifecycle.py -q -p no:cacheprovider
# 101 passed in 0.27s
uv run --frozen --no-sync python -m pytest tests/test_runner_policy.py tests/test_runner_image.py tests/test_runner_lifecycle.py -q -p no:cacheprovider
# 200 passed in 0.37s
uv run --frozen --no-sync python -m pytest -q -rs -p no:cacheprovider --basetemp var/step7c-final-tests-20261022
# 426 passed, 1 skipped, 1 warning in 22.32s
uv run --frozen --no-sync python -m compileall -q backend runner tests
# exit 0
git diff --check
# exit 0
```

The first test attempt had a collection error because `request` is a reserved
pytest parameter name; it was renamed to `payload` before the passing runs.
No security assertion was relaxed. New regressions cover cancellation during
removal and prevent another adapter's owned container from being removed.
Tests block process launch/network access and fail at teardown if such an attempt
was caught internally. No actual container or generated Python was executed.

Existing skip: Windows file-symlink creation privilege unavailable in
`test_symlink_read_cleanup_and_ancestor_rejected`. Mandatory native Linux follow-up
remains in the runner plan. Existing warning: Starlette/httpx TestClient
deprecation. Git's LF-to-CRLF advisories are separate from that pytest warning.

Pending runtime controls include cumulative 10-second CPU accounting, 20-second
wall watchdog and two-second kill bound, five-second cancellation, effective
identity/cgroups/seccomp/LSM/network/tmpfs verification, bounded output collection,
fresh-state probes, durable orphan cleanup and authenticated operator separation.
Fakes certify none of these or the eventual Vultr deployment.

Next smallest increment after review: fixture-driven tests for real Engine
metadata projection and image/LSM/environment prerequisites, without starting a
container. A real transport and durable ownership/reconciliation must be reviewed
before even stopped real containers are created; execution needs a later gate.
