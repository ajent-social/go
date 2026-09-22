# Service credential implementation worklog

2026-09-22. Lifecycle: CANDIDATE, not promoted. Disposition: EXTRACT.

Implemented the first lifecycle package and a bbolt adapter. Public source and
license review are in provenance-servicecred.md. Restricted independent source
inspection established matching issue-once/digest/revoke behavior but differing
binding/session semantics; no identifying details or private code are published.

Executed locally: `go test -race ./...` and `go vet ./...`, both pass. Tests cover
wrong secret, owner/resource/scope mismatch, scope/lifetime escalation, expiry,
secret serialization and disk disclosure, durable reopen after revocation,
concurrent store instances, idempotent revoke, missing/corrupt storage, failed
issuance and caller cancellation. This is contract/security evidence, not by
itself real consumer adoption or production deployment.

Real consumer integration and its separate verification are in progress.
Maintainer review has not run. No second consumer migration, API release or
security-sensitive merge has been performed. Next gate: durable consumer
verification, then a reviewed immutable dependency and catalog evidence.
