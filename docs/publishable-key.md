# identity.publishable-key

Status: CANDIDATE. Package: `github.com/ajent-social/go/publishablekey`.

## Intent

Issue-once **browser-embeddable** public identifiers with hashed storage and
optional allowed-origin lists (exact match or `https://*.example.com` subdomain
wildcard). Prefixes alone establish no authority. Never derive allowed origin
from request `Host`.

Complements `identity.service-credentials` (backend machine secrets). Publishable
keys must not grant machine-class scopes.

## Non-goals

Secret/backend API keys (`servicecred`), session minting, entitlement policy.

## Provenance

Original public implementation. Behavioral boundaries informed by restricted
maintainer inspection of a private product publishable-key seam; no private
source was copied.
