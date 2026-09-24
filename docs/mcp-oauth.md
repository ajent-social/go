# MCP OAuth authorization server contract (`mcpoauth`)

Capability: `identity.mcp-oauth`. Status: CANDIDATE pending maintainer review.
This is a proposed extraction for one immediate consumer, not a released or
audited security API. Read [provenance](provenance-mcpoauth.md) and the
[worklog](mcpoauth-worklog.md).

## Scope

A bounded OAuth 2.1 authorization server for a single protected resource (an
MCP server) with public PKCE clients:

- RFC 8414 authorization-server metadata and RFC 9728 protected-resource
  metadata, both pre-marshaled from configuration. Nothing is derived from
  request `Host` headers.
- RFC 7591 dynamic client registration for public clients only. No client
  secret is issued. Client-supplied URLs (`jwks_uri`, `client_uri`, and so on)
  are ignored and never fetched.
- Authorization endpoint (`GET`) that validates the request, stores an
  immutable consent record and hands the application an opaque handle.
- Token endpoint for `authorization_code` with mandatory S256 PKCE and,
  unless disabled, `refresh_token` with strict single-use rotation and
  reuse-triggered family revocation (new extension, not extracted; see
  provenance).
- RFC 7009 revocation of access or refresh tokens; either revokes the whole
  grant. Unknown tokens are indistinguishable from revoked ones.
- Opaque 256-bit access and refresh tokens stored only as SHA-256 digests;
  `Verify` returns subject, binding, scopes, client and a stable `GrantID`
  for the application, and consults the grant on every call.

Deliberately absent and not advertised: confidential clients,
`plain` PKCE, implicit, device and client-credentials grants, stored per-client
scopes, a consent page, sessions, CSRF tokens, rate limiting, a user model and
any authorization policy. The official MCP SDK remains the protocol
implementation.

## Application responsibilities

- Authenticate the browser before rendering consent, and validate its own
  CSRF token on the consent form. OAuth `state` is a client value and is not
  CSRF protection for the server.
- Decide `Approval.Subject` and `Approval.Binding` (opaque strings) only after
  checking the authenticated principal may authorize that binding.
- On every verified request, re-check that the subject is still active and
  still owns the binding. Verification proves token validity, not policy.
- Rate limit the public endpoints at the mount point using `RemoteAddr` or an
  explicitly trusted proxy header.
- Provide a durable `Store`. The bbolt adapter is a single-process reference;
  no in-memory store is shipped.

## Validation rules

Authorization request (`GET` only, query ≤ 8 KiB, every value ≤ 2 KiB, no
duplicated parameter, no control characters):

1. `client_id` and `redirect_uri` are required. The client must exist and the
   URI must exactly equal a registered value and pass shape validation.
   Failures are answered `400` directly, never by redirect.
2. Only then are protocol errors redirected with `error`,
   `error_description` and `state`: `response_type` must be `code`,
   `code_challenge_method` must be `S256`, `code_challenge` must be 43
   base64url characters, `resource` when present must equal the configured
   resource (`invalid_target`), `scope` tokens must be unique and within the
   configured ceiling (`invalid_scope`), `state` is optional and ≤ 1 KiB.

Redirect URI shape (registration and authorization): absolute `https` URL with
a host, or when `AllowLoopbackRedirects` is set an `http` URL whose host is a
numeric IPv4 or IPv6 loopback literal on any port. `AllowLocalhostRedirects` is a separate compatibility opt-in for exact
`http://localhost:<port>` callbacks with a valid explicit port. It does not
permit subdomains, trailing dots, alternate spellings or localhost issuers.
Numeric loopback is preferred: localhost resolution depends on the client
environment. Both HTTP options default off. No userinfo,
fragment, whitespace, control characters, custom schemes, or non-canonical
forms. Exact string match includes scheme, host, port, path and query.

Approval: the code inherits client, redirect URI, PKCE challenge and resource
from the stored record. Scopes must be explicit and non-empty and may only narrow the requested set; subject must
be a non-empty clean string. The consent record is consumed atomically, so a
handle approves at most once. Rejected approvals leave the record intact.

Token exchange (`POST` form, body ≤ 16 KiB, no query string, no duplicated
parameter): the code is consumed atomically before any comparison, so a
concurrent or failed attempt burns it. Client, redirect URI, expiry, resource
and PKCE are then checked; stored scopes are re-narrowed against the configured
ceiling. Success returns `access_token`, `token_type: bearer`, `expires_in`
and `scope` with `Cache-Control: no-store`.

Verification fails closed on store error, unknown, revoked or expired tokens,
resource mismatch, empty subject, or scopes outside the ceiling.

## Grants and refresh tokens

Every successful code exchange creates one grant (token family) with an
immutable binding of client, subject, binding, resource and scopes, an
absolute expiry (`RefreshTTL`, default 30 days, max 90 days) and a single
`RevokedAt` switch. Access tokens (`TokenRecord`) and refresh tokens
(`RefreshRecord`) carry the `GrantID`.

- `Verify` reads the token and then its grant on every call. A missing,
  revoked or expired grant, or any binding mismatch between token and grant,
  denies. Nothing is cached.
- The `refresh_token` grant requires `refresh_token` and `client_id`;
  `scope` may only narrow to a subset of the grant's scopes (empty keeps
  them); `resource`, if present, must match. The new access token expires at
  `min(now + AccessTokenTTL, grant.ExpiresAt)`; the new refresh token expires
  with the grant. Nothing slides and nothing widens.
- Rotation is strict: each refresh token rotates once. A second presentation
  for the correct client revokes the whole family atomically (every access
  and refresh token, including the newest unused one) and answers
  `invalid_grant`. A presentation with a wrong `client_id` is answered
  `invalid_grant` without touching the family. The previous access token is
  not revoked by rotation and expires on its own schedule.
- `Revoke` and the revocation endpoint accept either token kind and revoke
  the grant. `token_type_hint` is ignored.
- `DisableRefresh: true` removes the grant from issuance, metadata and
  registration. A grant is still created so `GrantID` is always available;
  it expires with its single access token.
- Lost responses: if the rotation commits but the response is lost, the
  client's retry is a reuse and the family is revoked; the user re-authorizes.
  Two instances of one client refreshing concurrently with the same token
  produce one success and then a revoked family. There is no grace window.

## Store contract

Every method is independently atomic and durable; no method requires a
transaction spanning another. IDs of consent, code, token and refresh records
are hex SHA-256 digests of the secret; grant IDs are random hex. Raw secrets
never reach the store.

| Method | Semantics |
| --- | --- |
| `CreateClient`, `CreateConsent`, `CreateCode` | insert without overwrite; `ErrExists` on collision |
| `Client`, `Consent`, `Grant`, `Token`, `Refresh` | read committed state; `ErrNotFound` if absent; never filter by expiry or revocation |
| `ConsumeConsent`, `ConsumeCode` | delete and return in one step; exactly one concurrent caller succeeds, others get `ErrNotFound` |
| `CreateGrant` | insert grant, first access token and optional first refresh token in one transaction; any collision fails all with `ErrExists`; application issuance policy may return `ErrDenied` inside the transaction |
| `RotateRefresh` | one transaction: load the old refresh record (`ErrNotFound`); if already used, set `RevokedAt` on its grant, commit that write and return `ErrReused`; else load the grant (`ErrNotFound`; revoked: `ErrDenied`), apply optional application policy (`ErrDenied`), insert the new token and refresh record (`ErrExists`), mark the old record used with `ReplacedBy`. Exactly one of two concurrent rotations succeeds |
| `RevokeGrant` | set `RevokedAt` once; idempotent; `ErrNotFound` if absent |

A SQLite implementation maps each record type to a table keyed by `id`,
implements consume as `DELETE ... RETURNING` and runs `CreateGrant` and
`RotateRefresh` as write transactions. The reuse branch of `RotateRefresh`
must commit its revocation even though the call returns an error. Live
application checks (account state, binding epoch, quotas) belong inside
`CreateGrant` and `RotateRefresh`, evaluated against the grant's subject and
binding; returning `ErrDenied` from rotation writes nothing and leaves the
refresh token unused. Expired rows may be swept by the application; a token
never outlives its grant, so one cutoff is safe for all tables. Correctness
never depends on sweeping, and a missing grant fails closed.

## Limits

| Item | Bound |
| --- | --- |
| Access token TTL | default 1h, max 24h |
| Refresh (grant) TTL | default 30d, max 90d, absolute, never shorter than the access TTL |
| Code TTL | default and max 10m |
| Consent TTL | default 10m, max 30m |
| Scopes | 1..64, each ≤ 128 bytes, RFC 6749 scope-token charset |
| Registered redirect URIs | 1..10, each ≤ 2 KiB |
| `client_name` | ≤ 255 bytes, no control characters |

## Comparison with existing libraries

- `github.com/modelcontextprotocol/go-sdk` `auth`/`oauthex`: verifies bearer
  tokens and implements client-side discovery and metadata. It does not
  provide an authorization server with consent, code issuance or storage.
  This package fills that gap and is intended to sit in front of the SDK's
  server handler.
- `github.com/ory/fosite`: a full OAuth 2 and OpenID Connect framework with
  many grants, JWTs, refresh tokens, introspection and pluggable storage. It
  is the mature choice when those features are needed. This package is a
  fraction of that surface: two grants, one resource, opaque tokens, a
  thirteen-method store.
- `github.com/go-oauth2/oauth2`: a general server with multiple grants and
  storage adapters. Its defaults include features (implicit, password) this
  package deliberately omits, and its refresh handling does not implement
  reuse-detecting rotation.

No independent security audit of this package has been performed. Claims
above are backed by the unit tests listed in the worklog, not by external
review.

## Reference adapter operating limits

The bbolt adapter does not impose registration quotas or evict clients. Its
Sweep scans each expiring-record bucket in one write transaction; large
databases can delay authorization. Mount-level rate limits alone do not
bound lifetime storage. Public deployments must supply bounded registration
retention and storage policy, or an application adapter with those limits.
Serenity uses its own SQLite adapter rather than this reference adapter.

A storage commit error can have an ambiguous outcome. Clients must not infer
that a failed refresh left the old token unused: retrying a committed rotation
revokes the family. Reauthorization is the recovery path.

Restoring a snapshot can resurrect used or revoked tokens. A product restore
must invalidate all OAuth grants, codes and pending consent records before
serving requests (or advance an external durable revocation epoch). The
reference adapter cannot infer that its file came from a backup.
