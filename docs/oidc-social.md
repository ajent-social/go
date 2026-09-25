# identity.oidc-social

Status: CANDIDATE. Package: `github.com/ajent-social/go/oidc`.

OIDC authorization-code login around go-oidc / x/oauth2. State is
consume-once; redirect URIs must be configured absolutes (https or loopback
http). Link IdP subjects to local accounts via bindings. Sessions remain
REFERENCE_EXISTING (scs).

## Adapters

- `oidc/github` — non-OIDC OAuth 2.0 (user + emails API) producing the same
  `Identity` shape and sharing `oidc.Store`.
- `oidc/apple` — Apple client-secret JWT (ES256) helper plus issuer preset for
  `oidc.New`.
- `oidc/microsoft` — Microsoft identity platform issuer/scopes preset for
  `oidc.New`.

GitHub is not covered by the core OIDC path (no standard ID token); use
`oidc/github`.
