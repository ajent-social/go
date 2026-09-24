# identity.oidc-social

Status: CANDIDATE. Package: `github.com/ajent-social/go/oidc`.

OIDC authorization-code login around go-oidc / x/oauth2. State is
consume-once; redirect URIs must be configured absolutes (https or loopback
http). Link IdP subjects to local accounts via bindings. Sessions remain
REFERENCE_EXISTING (scs).

GitHub (non-OIDC OAuth) is not covered by this package — prefer Google/Apple
OIDC issuers or a separate adapter later.
