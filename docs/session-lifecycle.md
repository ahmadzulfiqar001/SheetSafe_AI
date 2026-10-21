# Session lifecycle and retention

`LifecycleCoordinator` is the one lifecycle implementation. Session DELETE checks
authentication, ownership, Origin and CSRF, then requests cleanup within the same
writer transaction as revocation. Expiry is already enforced by authentication;
the coordinator also discovers expired, revoked or deletion-pending legacy rows.
The original expiry/request timestamp anchors the fixed 300-second deadline.
Repeated internal requests reuse the receipt and never extend that deadline.
HTTP replay after revocation continues to return 401; revoked credentials do not
gain access to cleanup controls or receipt inspection.

## Durable flow

1. Revoke access, signal run cancellation and insert one `PENDING` request.
2. Claim with a random lease token for 30 seconds. Only the current token may
   purge metadata or certify completion. Expired leases recover after restart.
3. Inspect only that session's metadata. Verify runtime teardown first, then
   storage removal through reviewed adapters. Step 6 wires the private storage
   adapter; registered dataset/code references must resolve in its registry.
   Execution evidence still blocks without a runner adapter.
4. Purge session metadata and cascading datasets/profiles/runs/attempts in one
   transaction. Mark the durable phase `CHECKPOINT` before committing.
5. Verify SQLite `wal_checkpoint(TRUNCATE)` before certifying `COMPLETE`. A pinned
   reader, failed transaction, or lost lease cannot produce a successful receipt.
   A crash between purge and checkpoint resumes at the checkpoint phase.

An empty session can finish with resource statuses `NONE_REGISTERED`; this means
no registered external-resource evidence existed, not that host files or containers
were deleted. `VERIFIED` is reserved for an adapter's matching-session receipt.
Adapters receive opaque server session/request IDs, not client-supplied paths.
They must validate their own server-controlled namespace, reject traversal and
links, bound/cancel I/O, and be idempotent across retries and expired leases. Future
artifact/storage/runner schemas must extend inventory verification before release.
The storage adapter performs only scoped, verified nonrecursive removal; no
container command is implemented. See [secure storage](secure-storage.md).

## Scheduling, retries and failure

FastAPI startup runs recovery before readiness, then starts one serial task per
application process. Default polling is 10 seconds, with at most 50 jobs per cycle
and a five-second admission budget between jobs. SQLite operations run off the
event loop; adapters have a two-second default timeout. Jobs and retention pruning
have bounded batch sizes. Graceful shutdown signals the task and awaits its current
cycle; process crashes leave durable leases rather than a false success.

Explicit transient adapter failures, timeouts, database errors and checkpoint
contention retry with bounded backoff, at most five claims by default. Missing
adapters, invalid verification and unknown adapter failures block for operator
review. Internal `resume_blocked` can resume only within the original budget and
deadline; it is not a public endpoint and does not reset quarantine before success.

Readiness and new session admissions fail closed for blocked/failed cleanup,
overdue data, expired claims, or an unhealthy/stale worker. Authentication/health
continue to work where otherwise valid. A missed deadline is retained as a fixed
failure fact even if cleanup later completes; counts are never labeled compliant.
Pending/blocked cleanup cannot reactivate sessions, move resource ownership, or
publish results. Future artifact publication must use the same transaction-level
active-owner checks and equivalent database guards.

## Retention boundaries

- Session access lasts at most one hour. Original data/code/artifacts and detailed
  records are targeted for deletion within five minutes of expiry/request.
- Content-free audit events and completed cleanup receipts expire after at most
  24 hours and are pruned in bounded batches. Unresolved requests retain the
  minimum recovery status until fixed; they indicate an unresolved retention
  failure, not compliant erasure. No raw credentials, questions, filenames, code,
  IP addresses or exception text are included in lifecycle evidence.
- Daily completion/deadline-miss counters contain no session identifiers or private
  content and expire no later than 30 days from their day bucket's start.
- SQLite `secure_delete=ON` and verified WAL truncation reduce retained application
  copies. They do not certify physical-media, OS-memory, backup or provider erasure.
  Database encryption and deployment-level storage controls remain release gates.

The scheduler cannot guarantee deadlines during outages, permanently blocked
resources or excessive backlog. Such conditions stay visible in durable state,
sanitized logs and readiness; private uploads remain disabled. No inference key,
external service, uploaded-data parser, sandbox runner or frontend is added here.
