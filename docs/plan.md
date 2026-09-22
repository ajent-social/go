# First capability implementation plan

Scope: identity.service-credentials. Other runtime candidates remain separate
work, not promises made by this implementation. Finish a verified slice before
expanding. No billing provider client, universal user model or UI framework.

- [x] Compare existing implementations and standard/external alternatives.
- [x] Establish source/license boundaries and public provenance.
- [x] Implement explicit issuance, binding, expiry/revocation and redacted secrets.
- [x] Adapt durable transactional storage with explicit failure semantics.
- [x] Run initial contract/security tests and race/vet.
- [ ] Verify the complete consumer integration with durable storage.
- [ ] Publish implementation and catalog changes as reviewable pull requests.
- [ ] Human maintainer reviews the security API and evidence.
- [ ] Decide lifecycle promotion after review; never infer it from tests alone.

Next consumer gate: independent credentials must not adopt another credential's
transport session, lease or cancellation authority. Revocation must survive a
process restart; real browser fixture execution must preserve origin checks.
