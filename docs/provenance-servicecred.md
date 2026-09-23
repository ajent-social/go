# Service credential provenance and alternatives

Capability: `identity.service-credentials`. Status remains CANDIDATE pending
maintainer review. This is a proposed extraction, not a production release.

Public source inspected: zerfoo/zerfoo `serve/security/apikey.go` and
`serve/security/apikey_bbolt.go`, Apache-2.0. The latter was verified through the
public repository Contents API as blob
`6019d04cffe73f69751057a516b79f7b2cfb82fa` on 2026-09-22.
The source originated at `security/apikey_bbolt.go` in commit
`0d486ed64e85894902e1ff9a53edfc2bbffa8ac3`. It moved to the current path in
commit `51ab5efe2a78534bcb5da19ee6df98dddd2e633c`, verified as an ancestor of
public `origin/main` in the local upstream clone.
Source: https://github.com/zerfoo/zerfoo/blob/51ab5efe2a78534bcb5da19ee6df98dddd2e633c/serve/security/apikey_bbolt.go
License: https://github.com/zerfoo/zerfoo/blob/51ab5efe2a78534bcb5da19ee6df98dddd2e633c/LICENSE

The boltstore package adapts its JSON-record/bbolt-transaction storage pattern.
It retains attribution and uses the source's Apache-2.0 license. No private code
was copied. Other lifecycle observations are restricted, maintainer-reported,
and not independently reproducible; they do not establish public adoption.

Semantic differences from the public source: mandatory expiry, explicit exact
owner/resource binding, scope narrowing at issuance, no mutable public record
pointers, no silent storage errors, atomic create without overwrite and atomic
binding-checked revocation. Rotation is deliberately composed by the caller:
issue a new independent ID and revoke the old ID. There is no implicit grace
period or shared-memory index that could remain stale after another writer.

Standard library crypto/rand, crypto/sha256 and crypto/subtle provide randomness,
verifiers and comparison. SHA-256 applies to uniformly random 256-bit secrets,
not passwords. Password hashing and interactive session/OAuth flows should use
established implementations and remain outside this capability.

bbolt v1.4.3 (MIT) supplies transactional local storage; golang.org/x/sys v0.29.0
(BSD-3-Clause) supplies Unix flock calls for admission and writer coordination.
The adapter is not a multi-host database; applications requiring that topology
should supply a store with the same create/read/revoke consistency contract. No
custom cryptography, payment client, MCP protocol or generic authorization
engine is introduced.
