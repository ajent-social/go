# First capability implementation plan

Scope: identity.service-credentials. Other runtime candidates remain separate
work, not promises made by this implementation. Finish a verified slice before
expanding. No billing provider client, universal user model or UI framework.

- [x] Compare existing implementations and standard/external alternatives.
- [x] Establish source/license boundaries and public provenance.
- [x] Implement explicit issuance, binding, expiry/revocation and redacted secrets.
- [x] Adapt durable transactional storage with explicit failure semantics.
- [x] Run initial contract/security tests and race/vet.
- [ ] Reverify an independent consumer against the reviewed revision using evidence readers can reproduce.
- [x] Publish implementation and catalog changes as reviewable pull requests (#1 and #2).
- [x] Add PostgreSQL-compatible SQL Store adapter (`servicecred/sqlstore`) with contract tests.
- [x] Public zerfoo consumer adopt (open PR https://github.com/zerfoo/zerfoo/pull/1014; not yet merged).
- [x] Restricted skills-discovery concurrent adopt (maintainer-reported; local branch helper + integration test; legacy tokens unchanged).
- [ ] Human maintainer reviews the security API and evidence.
- [ ] Decide lifecycle promotion after review; never infer it from tests alone.

Next gates: merge AMSL sqlstore PR and zerfoo consumer PR after maintainer
review; reverify an immutable module pin; keep status CANDIDATE until human
review.

## 2026-09-24 — merges and delivery adoption

Merged: go#4 (sqlstore), capabilities#5 (catalog evidence), zerfoo#1014
(public consumer). Adopted `delivery.go-validation` reusable workflow from
`ajent-social/workflows@2377e766f704dfe984a1e589933b91f2bc3c50a1` for
credential-contracts; product-specific boltstore matrix stays local.
