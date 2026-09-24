# identity.device-flow

Status: CANDIDATE. Package: `github.com/ajent-social/go/deviceflow`.

## Intent

Coordinate the OAuth 2.0 device authorization grant (RFC 8628): request a
device code, poll the token endpoint, return an access token to a CLI or
headless client. Authorization and token endpoint URLs are configured
absolutes — never hard-coded to a vendor.

## Non-goals

Credential file paths, product CLI UX, browser session minting.

## Provenance

Original public implementation. Behavioral boundaries informed by restricted
maintainer inspection of a private product device-flow CLI login seam; no
private source was copied.
