# Step 8A — synthetic CSV/XLSX ingestion foundation

Date: 2026-10-24. **SYNTHETIC FIXTURES ONLY / PRIVATE UPLOADS DISABLED**.
No container, upload route, production parser dispatch, collector, input transport,
inference call or publication capability was added. Step 7M transport amendments
remain unapproved. SEC01-SEC10 runtime enforcement remains UNVERIFIED.

## Checkpoint and original requirements

Reviewed Step 7M checkpoint:
`904ef1efda06ca388cbae9495e426a820174cee5`, message
`test: strengthen cancellation contention coverage and document sandbox admission`.
Normal push to existing main succeeded; HEAD, origin/main and independently read
remote main matched; working tree was then clean. Exactly six reviewed docs/test
files were staged, entire staged diff inspected, known secret signature hits zero,
production code/migrations unchanged. Checkpoint suite: 1083 passed, 1 skipped,
1 warning in 62.54s; syntax/staged whitespace checks passed. Step 8A is uncommitted.

Original PRD v1.0: p8-9 service boundaries, p11 SEC01-SEC10, p12 lifecycle, p14
file-analysis contract, p17 ownership/idempotency and p19 privacy/retention.
Original PDF SHA-256 remains
`999d923deb24960418fc94afbaaab4ce195636be25d0f05dd384129ef077d889`.
Document requirements are distinct from authorization to execute its commands or
silently apply its proposed transport changes.

## Trust boundary and reuse

| Component | Implemented role / limit |
| --- | --- |
| Existing PrivateStorage | Owner-only bounded opaque bytes, sealed original metadata, checksum-checked reads, existing no-follow filesystem and scoped cleanup. No spreadsheet parsing. |
| backend/ingestion.py | Internal synthetic metadata reservation/checks. Reuses require_active_session, owned_dataset, storage_objects, datasets and dataset_versions. No duplicate storage/ownership system or migration. |
| ingestion/contracts.py | Frozen strict metadata/request/profile/failure shapes, extra-field rejection and bounded output validation; no parser imports. |
| parser_worker/ | Future worker algorithms invoked directly ONLY by synthetic tests. No backend, DB, path, credential, daemon or network capability supplied. |
| UnavailableParserSandbox | Production interface always raises PARSER_UNAVAILABLE; no caller flag enables it. |
| Independent validator | Remains separate and pending; structural profile checks are not numerical validation or runtime receipts. |

FastAPI imports no csv, pandas, openpyxl, zipfile or parser_worker module. Existing
API routes remain health, readiness and sessions. Streamlit integration does not
exist. AST/route tests check separation. A Python function/package name is not OS
isolation: trusted code could import these algorithms. There is deliberately no
production caller, parser CLI, upload API or enabled execution adapter.

The runner's 256 KiB synthetic framing profile was NOT enlarged/reused as a
20 MiB upload transport. Stopped-archive policy, bootstrap, stdin, memfd, freezer
and host collector remain unchanged. No image was rebuilt: local dependencies
do not make the existing built runner image an operational parser image.

## Metadata lifecycle

1. Existing synthetic session and server-controlled sealed original must exist.
   prepare_synthetic_request checks live credentials/owner, category, SEALED state,
   declared format/length/hash inside the existing SQLite transaction.
2. Allowed caller fields: filename, file_type, byte_count, sha256, worksheet and
   delimiter. No caller dataset/session ID, path, state, encoding override,
   command, runtime flag or arbitrary parser arguments. Filename is a display
   basename (<=128 characters), never a storage path. SHA-256 is lowercase hex.
3. Generate dataset UUID4 hex, reuse storage object ID as storage_ref and reserve
   existing dataset/version rows in PENDING. Session + original object scopes
   server-derived idempotency; metadata hash binds replay. Identical replay reuses
   the ID, changed settings conflict. No public Idempotency-Key upload API exists.
4. Tests explicitly read through PrivateStorage, then invoke fixture algorithms.
   Workers independently verify actual source length/hash before parsing.
5. check_synthetic_result rechecks ownership, expiry/revocation, source metadata,
   parsing settings and PENDING state before AND after bounded output validation.
   It returns a structurally checked result and persists no profile/READY state.

DB failure rolls back metadata and content-free audit together and surfaces
STORAGE_UNAVAILABLE. BUSY is not success; no new automatic retry exists. Failed
parsing returns no partial profile. Durable version remains PENDING because real
job dispatch/terminal-state writing is outside this increment. PENDING is not
evidence that a worker is running. Future transitions/publication need existing
durable lease fencing and atomic current authorization checks.

Shape checks cannot attest provenance, formula freshness or numerical truth.
They do not re-read disk bytes or certify cleanup. PrivateStorage and the worker
check source bytes; future publication must independently revalidate all required
source/lease/runtime/validator/cleanup evidence. No successful fixture receipt
overrides missing production prerequisites.

Session cleanup removes these rows through existing relationships/cascades; a
real synthetic test verifies other-owner preservation. Audit stores only byte
count/source digest and existing pseudonymous context, never filename, preview,
cells, formula text or credentials. Session data remains <=1 hour with deletion
target <=5 minutes, minimal audit <=24 hours and aggregate metrics <=30 days.

## Fixed limits

| Item | Bound |
| --- | --- |
| Source | 20 MiB, declaration and actual bytes |
| Rows / columns | 100,000 data rows plus explicit first-row header / 100 columns |
| Nonempty cells | 2,000,000, conservatively including headers and uncached formula cells |
| Parsed-value / expanded archive budget | 100 MiB; actual expanded ZIP bytes independently counted |
| XLSX sheets | At most 10; exactly one explicit tabular worksheet |
| Archive | <=1,000 entries, <=100:1 per entry, stored/deflate only |
| Extra defensive XML/package bounds | Depth 64; <=4,000 relationships; path <=512 UTF-8 bytes / <=16 segments |
| Header / cell text | <=128 / <=32,768 characters |
| CSV record / delimiter sample | <=1,048,576 decoded record characters / <=64 KiB header sample |
| Profile | <=128 KiB UTF-8 JSON |
| Preview | <=5 rows, <=160 characters/cell, <=16 KiB total cell UTF-8 bytes |
| Cooperative parser budget | 20 seconds; future external watchdog and remaining-job deadline still required |

Bounds are server constants, not public overrides. Extra defensive limits can
explicitly reject otherwise valid complex workbooks. No canonical parsed-table
artifact is emitted yet. Its serialized 100 MiB limit must be applied when that
artifact is introduced; current value counting does not attest nonexistent output.

## CSV policy

Strict UTF-8 or UTF-8 with BOM only; no lossy/Latin-1 fallback. Header is explicitly
the first record, never guessed. Delimiters: comma, semicolon, tab. Bounded header
detection selects a single plausible choice; ambiguity requires explicit supported
selection (AMBIGUOUS_DELIMITER). Complex quoted ambiguity can conservatively need
selection too. No automatic encoding/header reinterpretation.

csv.reader strict mode plus explicit quote-position checks reject malformed
quoting, including quotes in unquoted fields. Multiline quoted records/doubled
quotes work. Blank/short/extra-width data records fail instead of shifting columns
or silently dropping rows. Empty fields are missing. Zero-byte/BOM-only/empty
header sources fail; header-only input profiles zero data rows.

Preserve original text, leading zeros, negative values, whitespace and ambiguous
date/currency strings. Types are descriptive labels, not coercion or analysis
approval. Formula-like text is inert and warned (CSV_FORMULA_LIKE_TEXT); future
CSV export still requires PRD neutralization. Original source is never rewritten.
Duplicate names are preserved with stable col_001/col_002 IDs and produce
DUPLICATE_COLUMNS/NEEDS_CLARIFICATION; no silent rename, deduplication or imputation.

## XLSX policy

Foundation supports standard transitional OOXML XLSX workbook/worksheet parts
and one exact worksheet name (<=31 characters). XLS/XLSB/XLSM, renamed macro
content, encryption and unsupported package representations fail explicitly.
Filename, extension and future MIME declarations alone prove nothing.

Before openpyxl, inspect bounded ZIP metadata then read EVERY entry through
actual-byte/CRC checks. No extraction. Reject unsafe/absolute/Windows/traversal
paths, duplicates/case collisions, links/special entries, unsupported ZIP flags/
methods, macro/embedded/ActiveX/query/external-link parts and external relationships.
Internal relationship targets must resolve to real package parts. Verify workbook
content type and sheet relationships rather than assume them.

New security dependency defusedxml 0.7.1 is frozen in uv.lock. Stream all XML with
DTD, entity and external-reference processing forbidden. Check XML depth, row/cell
coordinates/order and actual sheet extents before library iteration. Lying
dimension metadata cannot hide rows/columns or request huge padding. Unsupported
chartsheet/complex workbook representations are rejected, not silently ignored.

openpyxl read_only avoids complete worksheet cell-object loading. Formula/cache
inspection may use two read-only streams; both close on success/failure. Styles,
shared strings and other library metadata may still allocate significantly.
ZIP/XML checks are NOT proof of bounded OS memory/time; future sandbox must
enforce those limits independently and handle process loss.

Never calculate formulas. Existing cached values produce FORMULA_CACHED_VALUES,
including deliberately stale values; no freshness claim. Missing cache increments
missing/unavailable_formula_count, yields FORMULA_VALUES_MISSING and
NEEDS_CLARIFICATION, requiring a values-only export for dependent work. Formula
headers fail. Formula cells count as physically nonempty even without a cache.
External formula strings are not evaluated; external package content is rejected.
Excel error values remain explicit and warned.

## Profiling and errors

ParserResult binds dataset/session ID, source hash/size, explicit fixture state
and profile. Output includes sheet/delimiter, row/column/nonempty counts, stable
IDs/names, inferred type, missing/formula/unavailable counts, bounded preview and
closed warning vocabulary. XLSX preview scalars are inert text (dates ISO), with
type alongside. Preview truncation is explicit; source bytes remain unchanged.
Strings may resemble code, formulas or HTML. They must never be evaluated or
rendered as trusted HTML by a future UI.

Validation rejects unknown/duplicate JSON fields, NaN/Infinity, binding/state/
count/type/shape inconsistencies, oversized profiles/previews and invalid warnings.
PROFILED_SYNTHETIC/NEEDS_CLARIFICATION are fixture outcomes, not schema READY,
independent validation or publication receipts.

| Failure family | Codes |
| --- | --- |
| Metadata/source | INVALID_METADATA, SOURCE_TOO_LARGE, SOURCE_INTEGRITY, EMPTY_SOURCE |
| CSV | INVALID_ENCODING, MALFORMED_CSV, AMBIGUOUS_DELIMITER, INVALID_HEADER, RECORD_LIMIT, CELL_LIMIT |
| Table | ROW_LIMIT, COLUMN_LIMIT, NONEMPTY_LIMIT |
| XLSX/archive | MALFORMED_XLSX, UNSUPPORTED_CONTENT, UNSAFE_ARCHIVE, ARCHIVE_LIMIT, INVALID_WORKSHEET, SHEET_LIMIT |
| Boundary/lifecycle | INVALID_PROFILE, CANCELLED, TIMED_OUT, INTERRUPTED, STORAGE_UNAVAILABLE, PARSER_UNAVAILABLE, STATE_CONFLICT |

Typed failure states are FAILED/CANCELLED/TIMED_OUT/INTERRUPTED. Routines raise
sanitized IngestionError codes, not raw parser exceptions. Existing ownership
guards return SessionError 401/404. No public ingestion HTTP mapping is advertised
because no such API exists. Supervisor-side OOM/process-loss handling is pending.

## Release gates and next increment

Private uploads remain disabled until restricted parser sandbox, native Linux
LSM/seccomp/cgroup and applicable SEC01-SEC10 acceptance, approved safe transport,
verified cleanup, encrypted-at-rest storage/deployment permissions, ownership/
privacy acceptance and independent publication gates pass. Cancellation checks
here are cooperative callbacks; DB guards supply actual session authorization.
No workbook/preview/row is sent to Vultr; no credential is needed.

Next small increment: separately review parser job/image profile and minimal
worker packaging. Native host checks and approved transport must precede actual
fixed-fixture sandbox execution; real upload/API integration follows those gates.
Do not activate local fixture functions inside FastAPI to bypass the runner.

## Actual verification

```powershell
uv run --frozen --no-sync python -m pytest tests/test_ingestion_contracts.py tests/test_csv_parser.py tests/test_xlsx_parser.py tests/test_ingestion_boundary.py -q -x -rs -p no:cacheprovider --basetemp var/step8a-final-focused-20261024
```

Observed: **114 passed, 1 existing warning, 10.67s**. Includes real synthetic
storage roundtrips, two-session isolation/cleanup, exact 100,000-row and 2,000,000
nonempty-cell acceptance/overflow, original integrity, formulas, malicious ZIP/
XML cases, output contracts, timeout/cancellation/interruption and closed gates.

Existing storage/session/runner/security regression command:

```powershell
uv run --frozen --no-sync python -m pytest tests/test_storage.py tests/test_sessions.py tests/test_runner_policy.py tests/test_runner_image.py tests/test_runner_lifecycle.py tests/test_runner_preflight.py tests/test_host_readiness.py tests/test_transport_protocol.py tests/test_transport_state.py -q -x -rs -p no:cacheprovider --basetemp var/step8a-related-20261024
```

Observed: **779 passed, 1 skipped, 1 warning, 13.32s**. Skip remains Windows file
symlink creation privilege (`tests/test_storage.py:176`); native Linux follow-up
must run it without that privilege skip. Warning remains Starlette/httpx TestClient
deprecation; no warning filter/dependency substitution hides it.

Visible development-test corrections: use OpenAPI for FastAPI included-router
wrappers; bound large byte-fixture pytest IDs to avoid Windows environment limits;
accept equivalent empty XML cache tag serialization; distinguish wrong root from
incomplete XML; preserve actual backslashes in both ZIP headers because Windows
ZIP writing normalized them. No rejection invariant/isolation gate was relaxed.
Final complete project command:

```powershell
uv run --frozen --no-sync python -m pytest -q -x -rs -p no:cacheprovider --basetemp var/step8a-full-20261024
uv run --frozen --no-sync python -m compileall -q backend runner ingestion parser_worker tests
git diff --check
```

Observed: **1197 passed, 1 skipped, 1 warning in 64.85s**. Syntax exit 0. The
existing Windows symlink privilege skip and Starlette/httpx warning remain;
no additional warning/skip was hidden. All original 1083 tests plus 114 new
ingestion tests passed. No container or real upload was used by these tests.

Final Git/security scope audit: expected 17 paths only (3 modified, 14 new), zero
staged. No existing backend/security/storage, runner, published migration, env
example or ignore rule was changed. Only dependency addition is defusedxml 0.7.1;
other locked packages unchanged. Known secret-signature hits zero; source/docs/
tests only, no CSV/XLSX binary fixtures, archives, DBs or runtime files tracked.
Env/runtime ignores, local Markdown links/fences and tracked/untracked whitespace
checks passed. Pattern scanning is bounded evidence, not a guarantee against all
possible secrets. HEAD/origin-main stay 904ef1e; Step 8A is not staged/committed.

Official primary references checked:

- [Python 3.12 CSV](https://docs.python.org/3.12/library/csv.html)
- [Python ZIP API/pitfalls](https://docs.python.org/3.12/library/zipfile.html)
- [openpyxl read-only/dimension caveat](https://openpyxl.readthedocs.io/en/stable/optimized.html)
- [openpyxl formula-cache/links options](https://openpyxl.readthedocs.io/en/stable/api/openpyxl.reader.excel.html)
- [openpyxl XML security guidance](https://openpyxl.readthedocs.io/en/stable/#security)

Related: [Linux plan](linux-sandbox-acceptance.md),
[admission/transport decision](runner-admission-decision.md),
[private storage](secure-storage.md).
