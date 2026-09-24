# identity.passkeys

Status: CANDIDATE. Package: `github.com/ajent-social/go/passkey`.

## Intent

Coordinate discoverable, user-verified WebAuthn ceremonies around
[go-webauthn](https://github.com/go-webauthn/webauthn). RP ID and origins come
from configuration only (never request `Host`). Ceremonies are consumed before
verification so replays fail closed.

`passkey/memory` for tests. `passkey/sqlstore` for multi-host PostgreSQL-compatible
servers (credentials stored as JSON TEXT).

## Non-goals

Login UI, CSRF cookies, session minting, user directory, attestation policy
beyond what go-webauthn enforces with the configured authenticator selection.

## Provenance

Original public implementation. Ceremony consume-before-verify and configured
origin binding match patterns in a restricted product (ajent-social human
accounts using go-webauthn). No private source was copied.
