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
- [x] Add PostgreSQL Store adapter (`servicecred/pgstore`) with contract tests.
- [ ] Public zerfoo consumer adopt (independently reproducible).
- [ ] Restricted skills-discovery concurrent adopt (maintainer-reported).
- [ ] Human maintainer reviews the security API and evidence.
- [ ] Decide lifecycle promotion after review; never infer it from tests alone.

Next independent consumer gate: public zerfoo wiring of `servicecred` +
boltstore (or pgstore) with restart-safe revocation evidence readers can
reproduce. Keep status CANDIDATE until human review.
