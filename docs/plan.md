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
- [ ] Publish implementation and catalog changes as reviewable pull requests (implementation PR #1 is open).
- [ ] Human maintainer reviews the security API and evidence.
- [ ] Decide lifecycle promotion after review; never infer it from tests alone.

Next independent consumer gate: credentials must not adopt another credential's
transport session, lease or cancellation authority. Verify restart-safe
revocation and origin checks using public, independently reproducible evidence.
