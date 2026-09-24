# MCP OAuth implementation worklog

## 2026-09-23 — extraction and candidate implementation

Branch `feat/mcp-oauth`. Packages `mcpoauth` and `mcpoauth/boltstore` added;
`servicecred` untouched. Source is an owner-authorized restricted product
implementation; see [provenance](provenance-mcpoauth.md).

Design decisions:

- Refresh tokens were not implemented in this first pass (superseded by the
  entry below once the consumer needed them for native MCP client
  interoperability).
- The token endpoint consumes the code before comparing bindings, so any
  failed attempt with a leaked code burns it. Deviation from the source,
  which compared first.
- The consent step is split from HTTP: the server records the validated
  request and returns a handle; the application renders its own page with its
  own session and CSRF and later calls `Approve` or `Deny`. Approval cannot
  change client, redirect URI, PKCE or resource and can only narrow scopes.
- `state` is optional (bounded), unlike the source which required it.
- No in-memory store is exported; the test double lives in the test file.

Verification (local, single package each, not a full-module run):

```
go vet ./mcpoauth/ ./mcpoauth/boltstore/
go test -race -count=1 ./mcpoauth/           # 95 test and subtest passes
go test -race -count=1 ./mcpoauth/boltstore/ # 4 tests
```

Test coverage by requirement: config validation; metadata not host-derived
and no refresh advertised; happy path with hashed storage and `Verify`;
replay and burn-on-failure; 32-way concurrent redemption yields one success;
wrong client, unknown client, wrong redirect, wrong and malformed verifier,
resource mismatch, unsupported grant, missing parameters; duplicate, query,
wrong content type, oversized body, oversized field, CRLF and malformed form
rejections; direct-400 without redirect for missing or unknown client and for
redirect prefix, suffix, query, fragment, userinfo, case, CRLF, plain http and
custom-scheme injections; duplicate and oversized authorization parameters;
redirected protocol errors for response type, plain PKCE, missing or malformed
challenge, scope outside ceiling or duplicated, resource mismatch; approval
widening or replacement rejected with record intact; deny; consent, code and
token expiry; verify denial for unknown, other-resource, out-of-ceiling and
revoked tokens plus store failure surfacing; revocation idempotence and
unknown-token indistinguishability; registration acceptance ignoring remote
metadata URLs and twenty rejection cases; loopback redirect acceptance and
rejection matrix with exact port match. Bolt adapter: private directory
enforcement, create-without-overwrite, consume-once under 16 goroutines,
revocation durability, sweep, context cancellation, and a full authorize,
approve, exchange, replay, verify, revoke flow with the database closed and
reopened between every step.

Not done: maintainer review; independent security review; consumer
verification (restricted integration in progress, not merged); cross-compile
matrix; `golangci-lint`; full-module `go test -race ./...` (not run to respect
the shared build limit).

## 2026-09-23 — refresh token rotation extension (new code, not extracted)

Same branch. Adds a grant (token family) model and the `refresh_token`
grant on top of the unchanged authorization-code flow. Motivation: native
MCP clients register with `authorization_code` + `refresh_token` and an
hourly re-login is not workable. The restricted source has no refresh
tokens; everything in this entry is new and reviewed only by its tests.

Design decisions:

- One `GrantRecord` per code exchange is the immutable binding and the single
  revocation switch. `Verify` reads token then grant every call and denies on
  any mismatch; there is no per-token revoked flag and nothing is cached.
  `Identity.GrantID` lets the application keep an MCP session across refresh.
- Strict rotation. `Store.RotateRefresh` is the one atomic
  mark-used-or-detect-reuse operation; reuse revokes the grant and that
  write must commit even though the call returns `ErrReused`. The bbolt
  adapter carries the result out of the closure for exactly that reason.
- Wrong `client_id` is rejected before the store is touched, so guessing
  never revokes a legitimate family. `client_id` is public for public
  clients; this is friendliness, not a boundary. The boundary is possession
  of an unused refresh token.
- Refresh never widens or extends: scope is a subset of the grant, access
  expiry is capped by the grant's absolute expiry (default 30 days, max 90),
  the refresh token inherits that expiry, no sliding window.
- The previous access token survives rotation until its own expiry.
- Application live policy attaches inside `CreateGrant` and `RotateRefresh`
  and returns `ErrDenied`; a rotation denied by policy writes nothing.
- `CreateToken` and `RevokeToken` were removed from `Store` (pre-merge
  candidate, no released consumers). `TokenRecord.RevokedAt` was removed.
- Token endpoint: `client_id` is required for both grants; `resource`
  remains optional but must match when present (unchanged from the
  extraction, to avoid breaking clients that omit it; the server serves one
  resource regardless). Duplicate parameters are still rejected.
- Metadata and registration advertise or accept `refresh_token` only when
  it is enabled (`DisableRefresh` false, the default).

Verification (local, single package each, race detector, not a full-module run):

```
go vet ./mcpoauth/ ./mcpoauth/boltstore/
go test -race -count=1 ./mcpoauth/           # 105 test and subtest passes, 0 failures
go test -race -count=1 ./mcpoauth/boltstore/ # 5 tests, 0 failures
```

New coverage: rotation keeps `GrantID`, subject, binding, client and scopes,
issues fresh secrets, marks the old record used with `ReplacedBy` and
generation 2; reuse of generation 1 after two rotations revokes all three
access tokens and both later refresh tokens; wrong and unknown client on an
unused and on a used token issue nothing and do not revoke, and the real
client rotates afterwards; missing `client_id` and missing or duplicated
`refresh_token` are `invalid_request`; widening, foreign and duplicated
scopes and a foreign resource are rejected without consuming; empty scope
keeps the grant's scopes and leaves the grant record unchanged; access
expiry is capped by the grant and the refresh expiry equals it; expired
family, revoked-by-refresh, revoked-by-access, unknown token and store
failure paths; `Verify` denies on missing grant, binding, subject and scope
mismatch and on revocation, and surfaces store errors; 32 concurrent refreshes
yield exactly one rotation and then a revoked family; live policy denial at
rotation leaves the token unused and at issuance writes no grant; disabled
mode issues no refresh token, still returns a `GrantID`, rejects the grant
and its registration, and config bounds are enforced. Bolt adapter: partial
grant issue rolls back on any member collision; rotation, reuse revocation
and repeated reuse are durable across close and reopen; revoked grants do
not rotate; sweep respects the token-then-grant ordering; 16 concurrent
`RotateRefresh` calls give one success and fifteen `ErrReused` with the
grant revoked; full authorize, approve, exchange, refresh, replay, verify
flow with the database reopened between every step.

Known consequences: a lost refresh response leads to re-authorization; two
client instances sharing one refresh token will revoke each other.

Not done: maintainer and security review; consumer verification (the
restricted SQLite adapter is being updated by its owner against
private API addendum notes, not in this repository); interoperability
against real cloud MCP clients is unverified; `golangci-lint`; full-module
`go test -race ./...` (shared build limit).

## 2026-09-24 — review hardening and consumer checks

Automated source reviews identified and regression tests now cover empty
stored/approved scope sets, malformed query pairs, duplicate registration
JSON keys, and stored callback revalidation. These fail closed. Approval
requires explicit non-empty scopes; unnamed clients have a visible fallback.

A local consumer completed native Codex 0.155.1 OAuth login and a real MCP
recall call with the acquired token (synthetic empty memory; not retrieval
quality). Claude Code 2.1.281 registration demonstrated an exact localhost
callback requirement. A separately disabled-by-default localhost callback
option permits that form only with an explicit valid port; numeric loopback
remains preferred. Neither option weakens issuer/resource URL validation.

The full module passed `go vet ./...` and `go test -race ./...`, including
the localhost regression matrix. Public CI and maintainer review remain gates.
The reference adapter now checks cancellation while sweeping; lifetime
registration bounds and sweep latency remain application responsibilities.
Strict refresh reuse revocation after lost responses is intentional, documented,
and not evidence of an independent security audit. No cloud client qualification
or human approval is claimed.
