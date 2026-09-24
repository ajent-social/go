# identity.password-reset

Status: CANDIDATE. Package: `github.com/ajent-social/go/passwordreset`.

## Intent

Issue and consume single-use password-reset tokens (SHA-256 at rest) with TTL
and a Notifier seam. Mirror the consume-once pattern of `magiclink`. After
Consume, the application verifies the account and sets a new password via an
established password-hashing library (not this package).

## Non-goals

Password hashing, session minting, account directory.

## Provenance

Original public implementation. Behavioral boundaries informed by restricted
maintainer inspection of a private product password-reset seam; no private
source was copied.
