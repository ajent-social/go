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
Maintainer review has not run. As of 2026-09-22, no second consumer migration,
API release or security-sensitive merge had been performed. Next gate:
maintainer review, immutable dependency verification and catalog evidence
review.

## 2026-09-23 — review corrections

At source revision `059b954de5bf08220ee10b31f0680c74c092f9dc`, local
`go test -race ./...` and `go vet ./...` passed. Compile-only checks passed for
Darwin/arm64, Windows/amd64, AIX/ppc64 and illumos/amd64. Tests now cover
alternate secret formatting and slog, lock cancellation, bounded revoke
progress under continuous same-process and cross-process verification,
read-only verification, migration of databases without sidecar lock files,
relative paths, revoked metadata timestamps, and caller/store scope isolation.
Unsupported-platform builds include an `errors.ErrUnsupported` assertion; a
native Windows CI job runs that test.

The restricted consumer run above used an earlier candidate revision
(`b482cdf508200db1abc1a182421d8f5c8ddaac90`); that consumer has not been
reverified against this reviewed revision. It remains restricted maintainer
reporting, not public adoption evidence. Public REAL_CONSUMER verification is
NOT_RUN. Lifecycle remains CANDIDATE; the headless AI review is not human
maintainer review.

## 2026-09-24 — PostgreSQL store adapter

Added `servicecred/pgstore` with idempotent schema, binding-checked revoke,
create-without-overwrite and exact-binding list. Local execution:
`go vet ./servicecred/pgstore/...` and `go test -race ./servicecred/pgstore/`
against PostgreSQL on `/tmp` database `amsl_servicecred_test` — PASS (lifecycle,
collision, concurrent revoke/verify, nil DB). CI gains a Postgres 16 service and
`AMSL_PGSTORE_TEST_DSN`. Status remains CANDIDATE. Public second-consumer and
restricted skills-discovery adoption are tracked separately; catalog promotion
still requires human review.
