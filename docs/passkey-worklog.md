# identity.passkeys worklog

2026-09-24. CANDIDATE.

Implemented `passkey` with BeginRegistration / BeginLogin / Finish / DeleteCredential,
memory store, go-webauthn v0.17.4. Tests cover config validation, ceremony
consume-before-verify, and add-requires-existing. No private source copied.
