# identity.service-credentials

Status: CANDIDATE implementation for review. No stable API or production adoption
is claimed. Public source provenance is recorded in [provenance](provenance-servicecred.md).

## API and authority

`servicecred.New(store)` constructs the lifecycle service. `Issue(ctx, ceiling,
requested)` returns a redacted Secret plus Metadata only after a successful
store write. The caller derives the ceiling from already-authorized policy;
passing an attacker-supplied ceiling would defeat this boundary. The requested
owner/resource must match exactly, scopes must be a subset, and expiry may not
exceed the ceiling. Every credential expires. There are no wildcard scopes.

`Verify(ctx, raw, required)` rereads authoritative storage and checks a
constant-time SHA-256 verifier, owner, resource, all required scopes, expiry and
revocation. Requirements come from the endpoint/resource being accessed, not
from the client. The application must separately check disabled-account status
and any changing authority policy. The library has no universal account model.

`Revoke(ctx, owner, resource, id)` atomically matches the exact authorized
binding before setting revocation. IDs are not secrets. The Store interface has
four methods: atomic create-without-overwrite, authoritative lookup, atomic
binding-checked revoke, and exact-binding metadata listing. `Service.List`
returns sanitized metadata; the caller must authorize management access first.
Store implementations are part of the trust boundary; they must preserve
immutable grants and return errors, never fabricated records.

## Secret and failure behavior

Tokens contain a random public lookup ID and 256 random secret bits, with a
versioned prefix. Only the digest is stored. Prefixes do not grant authority.
Secret's JSON, text, slog value and all Go formatting verbs redact its value;
Reveal explicitly returns it for the issuance response. Do not log that result.
The library cannot prevent callers from logging raw HTTP headers or promise
memory erasure in Go.

Malformed, wrong, expired, revoked or insufficient credentials yield ErrDenied.
Store failures deny verification with a wrapped error; applications should map
these to a generic external denial and avoid leaking internal storage details.
If issuance storage fails, no secret is returned. An ambiguous commit error can
leave an inaccessible credential: authorized metadata listing plus revoke is the
recovery path. Lost successful issuance responses cannot reveal the same secret
again. Rotation uses a new independent ID and explicit revoke; no hidden grace.

Revocation is effective for verification begun after a successful revoke returns.
Concurrent verification may linearize before revocation. Already admitted work
and long-lived streams are not retroactively canceled. Applications needing that
behavior must implement explicit task cancellation/revalidation. Do not cache
positive verification results across requests.

## Durable adapter

`servicecred/boltstore.Open(ctx,path)` explicitly initializes a new local bbolt
store or opens the existing one. Parent directory, database and lock-file
permissions must be private; symlink database paths are rejected. The
application controls the parent directory and lifecycle (hostile same-account
filesystem changes are not an isolation boundary). Creating a store requires a
writable parent; opening an existing store for verification only requires read
access, while writes require write access. Each operation opens a fresh
transaction and releases its file lock. A writer that acquires the exclusive
intent lock blocks later readers while existing readers drain. Admission polls
with a one-second maximum or an earlier context deadline, so this is not a
strict scheduler fairness guarantee. Cancellation is checked before
transactions; it does not abort an already committing transaction. No NoSync
option is used.

Create never replaces an existing ID. Revoke checks owner/resource inside the
write transaction. Missing or corrupt storage fails closed. List returns only
metadata for one exact authorized owner/resource, including revoked records.
Sidecar and bbolt file locks coordinate processes on one local filesystem; no
multi-host or network filesystem consistency is promised. Applications needing
PostgreSQL can supply an adapter with the same contract after demonstrating a
real need. This file-locking adapter is available on Darwin, DragonFly, FreeBSD,
Linux, NetBSD, OpenBSD and Solaris. `Open` returns `errors.ErrUnsupported` on
other platforms; applications can use another Store implementation there.

## Review gates

- Contract and denied-path tests must pass under the race detector.
- A real consumer must wire durable storage, endpoint authorization, session
  ownership and revocation; package tests alone do not count as adoption.
- Maintainer review remains required before security API merge or promotion.
- Interactive login, OAuth, billing and public browser-publishable keys are
  outside this package; use established provider/library integrations.
