# Session protocol and deployment boundary

Session APIs require no inference key. Private uploads remain disabled.

## Transport and origins

Configure `SHEETSAFE_ALLOWED_ORIGINS` as a JSON list of exact origins (no paths,
wildcards, user info or trailing slash). The default trusts no origin. Production
requires HTTPS origins. Request scheme must be HTTPS for secure session cookies.
Configure the eventual TLS proxy and Uvicorn trusted-proxy addresses explicitly;
the application does not read `X-Forwarded-For` itself.

Production cookies use `__Host-sheetsafe_session`, Secure, HttpOnly,
SameSite=Strict, Path=/ and no Domain. Same-site origins are intended; cross-site
embeds are unsupported. CORS credentials are allowed only for configured origins.

For local HTTP only, explicitly set `SHEETSAFE_ENVIRONMENT=development`,
`SHEETSAFE_ALLOW_INSECURE_LOCAL_COOKIES=true`, and loopback-only allowed origins,
such as `["http://localhost:8000","http://localhost:8501"]`. Bind Uvicorn to
127.0.0.1. Both request host and peer must be loopback. This uses the distinct
`sheetsafe_dev_session` cookie. Production/test reject the insecure flag.

## Create and revoke

`POST /api/v1/sessions`: send an allowed `Origin`, `Content-Type: application/json`,
`X-SheetSafe-Request: 1`, and `{}` or `{"mode":"synthetic"}`. Bodies are capped at
1024 bytes. The response is 201 with session ID, UTC Unix expiry, lifetime,
synthetic mode, `private_uploads_enabled: false`, and a session-bound `csrf_token`.
The bearer credential is delivered only in the HttpOnly cookie. Never log cookies
or this response's CSRF token. A new creation always issues fresh credentials.

For `DELETE /api/v1/sessions/{id}`, send the cookie, allowed `Origin` and
`X-CSRF-Token` from that creation response. Authentication and ownership are checked
again inside the write transaction. Access is revoked immediately; deletion is
marked and existing run records receive a cancellation request. The receipt says
`cancellation_status: requested` and `cleanup_status: not_started` at enqueue time.
The lifespan retention worker processes the durable request; external resources
require verified adapters. See [session lifecycle](session-lifecycle.md). No process
stop, file removal or physical erasure is claimed by the DELETE receipt. Replay after revocation
returns 401. Creating another session cannot recover the previous session's data.

## Persistence and authorization

Session credentials contain 256 random bits. SQLite stores SHA-256 hashes only;
password hashing is not used for these uniformly random bearer tokens. CSRF tokens
are HMACs bound to the raw credential with a fixed purpose string, recomputed from
the authenticated cookie, and never persisted. Browser SameSite, exact Origin
checks, a custom bootstrap header and CSRF headers are complementary controls.

Session lifetime is fixed, at most one hour, and checked server-side on every
authentication. Private-mode or deletion-pending rows are not accepted by this
milestone's authenticator. Reusable ownership guards in `backend/security/authorization.py`
must run inside the same transaction as each future protected read or mutation.
Use trusted owner metadata, not request-provided owner IDs. Event streams require
parent-run ownership and pseudonym filtering; future artifacts must resolve their
owner from stored run metadata and recheck expiry/revocation before download.
Long-lived event streams must use fresh short-lived database checks before each
poll/send; never reuse a read snapshot or cached principal for the stream lifetime.

Creation admission is transactional across workers sharing the same SQLite file:
default 5 accepted creations per peer IP per fixed UTC minute, 60 globally, and
1000 total session records. IPs are stored only as short-lived hashes in a separate
rate-limit table, not audit details; forwarded headers are not read by this code.
Stale buckets are pruned on creation and by the retention worker. Rejected creations do not create rows/audit
events. The record cap includes expired/revoked sessions and fails closed until
safe lifecycle cleanup verifies reclamation. Edge-level connection/request limits and
reviewed proxy configuration are still needed before public deployment.

Schema migration 2 adds durable admission counters; migration 3 adds lifecycle
coordination without rewriting previous migrations. SQLite is not encrypted by this module. Private mode,
operator upload access control, encrypted storage, provider privacy verification,
deployed storage permissions/encryption verification and running-worker coordination
remain later release gates. Step 6 adds the synthetic-only storage adapter; see
[secure storage](secure-storage.md).
