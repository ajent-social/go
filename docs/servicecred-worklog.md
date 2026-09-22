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

A real application worktree imports this module and wires the durable adapter
into its authenticated HTTP transport and local credential management CLI.
Executed consumer build, vet and the complete browser-enabled race suite: PASS.
Consumer checks cover independently scoped credentials, wrong owner/resource,
missing connection scope, cross-credential session-ID takeover denial, lease and
cancellation ownership, revocation through an independent store handle, a fresh
OS process rejecting revoked credentials, and failure-closed missing storage.
An additional real-Chrome fixture path exercises navigation, snapshot, typing,
click, selection, extraction and model-planned tasks through this authentication.

Consumer evidence is RESTRICTED, MAINTAINER_REPORTED, not independently
reproducible from this public repository. It is local branch integration, not a
merged consumer release or production deployment. No consumer identity, source
hash or private path is published. The first transport test run hung during test
cleanup; closing client streams before the HTTP server resolved it, and the full
suite then passed. No failed run is counted as passing evidence.
Maintainer review has not run. No second consumer migration, API release or
security-sensitive merge has been performed. Next gate: maintainer review, immutable dependency verification and catalog
evidence review.
