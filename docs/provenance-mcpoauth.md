# MCP OAuth provenance and alternatives

Capability: `identity.mcp-oauth`. Status: CANDIDATE.

The `mcpoauth` package is adapted, with explicit owner authorization, from an
OAuth 2.1 authorization-code implementation in a restricted-source product
maintained by the same owner. The owner requested extraction into this
Apache-2.0 repository; the adaptation is offered under this repository’s
license. No public license for the restricted original has been established
by this review, and no third-party implementation is relicensed here. The source, its name, paths, revision
hashes and internal review history are restricted and are not published here;
readers of this repository cannot independently verify the origin. The exact
mapping is held privately by the maintainer.

What was carried over: the validation order that checks `client_id` and the
exact-match `redirect_uri` before any redirect; mandatory S256 PKCE; the
RFC 7636 verifier syntax check and constant-time comparison; hashed
single-use codes with atomic consumption; RFC 7591 registration for public
clients with bounded bodies, names and redirect lists; the RFC 8414 and
RFC 9728 pre-marshaled metadata documents; RFC 7009 revocation semantics with
`no-store`; and the body-size guard.

What was removed or replaced: the product's consent page, its
email/password and third-party sign-in on that page, its fixed two-scope
policy and copy, its user and token repositories, its rate limiter and its
proxy-header scheme detection. In their place: an application-owned consent
step through an immutable server-side consent record and opaque handle;
configured issuer and resource binding; configured scope ceilings narrowed at
request and approval; a small `Store` interface with atomic consume
semantics; access-token issuance inside the package with hashed storage;
duplicate-parameter and control-character rejection; loopback redirect
support for local clients; and a bbolt reference adapter.

What is new and NOT extracted: the grant (token family) model, refresh token
issuance, strict rotation with reuse detection and atomic family revocation,
the `CreateGrant`/`RotateRefresh`/`RevokeGrant` store operations, the
`GrantID` on `Identity`, grant-checked `Verify`, and the corresponding bbolt
adapter code and tests. The restricted source has no refresh tokens. This
extension was written in this repository against RFC 6749 §6 and §10.4,
RFC 6819 §5.2.2.3 and the OAuth 2.1 draft's refresh token rotation
requirements, and has received automated source review and regression testing, not an independent security audit. The owner subsequently approved this candidate integration on 2026-09-24.

Consumer evidence: [Serenity PR #271](https://github.com/sirerun/serenity/pull/271)
merged the pinned library integration after public CI and explicit owner
approval. Native Claude Code and Codex each completed OAuth login and a real
recall against a local synthetic fixture. The owner-authorized deployment is
[v0.1.9-hosted-candidate](https://github.com/sirerun/serenity/releases/tag/v0.1.9-hosted-candidate).
Its live OAuth sign-in, consent, refresh, MCP tool discovery and revocation
checks passed, as reported by the implementing agent. This is one consumer,
not broad adoption, cloud-client qualification or an independent audit.

Alternatives evaluated: the official MCP Go SDK (`auth`, `oauthex`) covers
resource-server verification and client discovery but not a product
authorization server; `ory/fosite` and `go-oauth2/oauth2` are broader
frameworks whose surface exceeds the bounded need. See
[the contract](mcp-oauth.md) for the comparison.

Dependencies: standard library `crypto/rand`, `crypto/sha256`,
`crypto/subtle`, `net/url`, `net/http`; `go.etcd.io/bbolt` v1.4.3 (MIT) for
the reference adapter. No new dependency, cryptography or MCP protocol code
is introduced.
