# Private storage and verified file cleanup (Step 6)

This is an internal, synthetic-only byte store. No upload, download, parser,
inference, generated-code execution, validator or runtime-control endpoint is
introduced. Public sessions still advertise `private_uploads_enabled: false`.

## Layout and ownership

`SHEETSAFE_PRIVATE_STORAGE_PATH` optionally selects a dedicated local directory.
The default is `storage/` beside the configured database, normally `var/storage/`.
Keep it outside public/static roots, sandboxes, network filesystems and backups.
The default `var/` is ignored by Git. A custom directory must also be outside Git.
The parent must already exist; storage never creates arbitrary ancestor trees.

Schema migration 4 adds a database-bound root identity, random per-session
namespaces, and a storage object registry. Earlier migrations are unchanged.
Opaque, generated 32-character hex object IDs are references, never filesystem
paths. Categories are `original`, `version`, `candidate`, `temporary`,
`quarantine`, and reserved `validated`. Evidence JSON/text goes into quarantine.
The registry records owner, run, candidate version, type, size, SHA-256,
creation time and `STAGING`/`SEALED` state. Session expiry governs every object.
Source files cannot be overwritten; only one original exists per session.

Operations accept a previously authenticated principal and recheck its token
hash, owner and active status in SQLite. Run ownership is checked separately.
Internal reads may inspect quarantined bytes; there is no public route exposing
them. `StoredFile` contains no absolute path. Error boundaries use existing safe
HTTP error handling, without serializing SQL, exceptions, paths or credentials.

## Writes, reads and quarantine

The namespace is durably registered before its directory is created. A
nonblocking interprocess namespace lock serializes file operations. It is held
across I/O, without holding a database writer transaction for the byte stream.
Revocation therefore does not wait for a slow producer. Writers reserve a
`STAGING` record before creating a server-named `.part` file, bound each chunk,
verify actual length, hash the bytes, flush/fsync, and rename within the same
directory. A short writer transaction rechecks active ownership and seals the
metadata. Only a committed `SEALED` record permits reading. A crash after rename
leaves an unreadable, registered staging object for session cleanup.

Reads enforce size and hash integrity and recheck authorization before returning.
Call synchronous methods off the API event loop. The source iterable is trusted
backend code: its individual `next()` calls must not block indefinitely. The
future bounded transport must enforce its own stream deadlines. The ten-second
write budget is checked between chunks; it cannot preempt a blocked producer.

PRD pages 11, 14 and 15 supply these byte budgets:

- Original CSV/XLSX: 20 MiB. Versioned normalized CSV/JSON: 100 MiB parsed cap.
- Collected files: 10 MiB each, 20 MiB total and 10 files per run candidate,
  counting temporary, quarantined and future validated objects together.
- Temporary text is reserved for logs, capped at 64 KiB per file/stream.
  Other text evidence uses quarantine. Candidate source is separately bounded
  to 10 MiB and one source object per candidate version (versions 1 through 3).
- Read/write chunks are at most 64 KiB. Incomplete reservations count against
  budgets; they are never silently discarded or reused after failure.

These are storage checks, not proof of CSV/workbook/image safety. Row/cell/sheet,
archive expansion, formula-neutralization, image regeneration, structured JSON
and semantic checks belong to isolated ingestion and independent validation.
No parsing or decoding of untrusted formats occurs in FastAPI here.

Only inert extensions CSV, XLSX input, Python source, PNG, JSON and text are
accepted for their designated categories. Active HTML/SVG/JavaScript is excluded.
All execution outputs remain internal and quarantined. Direct writes to
`validated` and `publish()` fail closed. An independent validator and verified
runner teardown must be connected before atomic result publication is enabled;
caller-supplied success booleans are not accepted as evidence.

## Filesystem safeguards

POSIX uses `O_NOFOLLOW`, directory descriptors, regular-file/link-count checks,
0700 directories, 0600 files, `flock`, fsync and an atomic same-directory rename.
Windows pins every ancestor with no-delete-sharing directory handles, rejects
all reparse points (including junctions), uses `OPEN_REPARSE_POINT` for regular
files, and an exclusive file handle for the namespace lock. Hardlinks, special
files, alternate streams and caller-selected paths are rejected. No recursive
deletion API exists. Unknown entries cause failure, rather than being removed.
The root marker binds the configured directory to the database; a missing or
different marker, nonempty user directory or unregistered namespace fails closed.

This boundary assumes only the application identity writes its private root;
it does not defend against a compromised host administrator or same-identity
process deliberately bypassing the API. Windows inherited ACLs and deployed
Linux identity/permissions need separate verification. The POSIX branch requires
Linux acceptance testing before deployment; local results cover Windows only.

## Cleanup, recovery and limits

The existing lifecycle coordinator owns revocation, leases, retries, deadlines
and receipts. Its inventory now includes registered storage namespaces.
FastAPI lifespan initializes the storage adapter before cleanup recovery and
readiness. Readiness also checks the storage root identity/inventory.

The adapter accepts only a matching running cleanup request for an already
revoked session. Dataset and code references must resolve through that session's
trusted registry; legacy/unmapped references block verification. It locks only
that namespace, rejects unexpected entries/links, unlinks registered final and
partial files, verifies empty category directories, removes those directories
and the namespace, then records namespace cleanup. The registry remains until
the coordinator atomically purges object and session records, so a failed purge
cannot lose its reference mappings. Missing registered files are
idempotent success, provided the correct root is still verified. A retry after a
crash resumes from durable metadata. No arbitrary client path is ever traversed.

Each invocation removes at most 64 files and checks a one-second cooperative I/O
budget between operations; larger inventories retry under the existing budget.
Filesystem enumeration is capped at 4096 entries per directory and unexpected
overflow blocks rather than certifying cleanup. A cancelled adapter signals and
joins its worker thread, avoiding unobserved background deletion. An OS I/O call
stuck in the kernel cannot be forcibly interrupted; deadlines during such an
outage cannot be guaranteed and require operator recovery.

Only verified removal permits session metadata purge, WAL checkpoint and the
existing `COMPLETE` receipt. Transient locks/permissions/I/O errors retry;
unknown files, links and unmapped references block. The original five-minute
deadline and missed-deadline evidence remain unchanged. Failed cleanup pauses
readiness/new admissions and never reactivates a session. Storage staging/sealing
audits contain only pseudonyms, run IDs, byte counts and hashes; no filenames,
file bytes, code, credentials or exception text. Existing 24-hour audit and
30-day aggregate retention remain enforced.

No runner is shipped. Runtime evidence still blocks cleanup without a runner
adapter; file removal does not imply that a container was removed.

## Release blockers

At-rest encryption is **not implemented or certified** by this component.
Before enabling any real upload, verify encrypted application-controlled file
and SQLite storage, key custody outside sandboxes, separate service identities,
private OS ACLs, TLS, operator access control, disabled content backups/snapshots,
swap/crash-dump handling and provider privacy terms. No config switch in this
step enables real uploads. Application unlink/checkpoint does not certify
physical-media, provider, backup or OS-cache erasure.
