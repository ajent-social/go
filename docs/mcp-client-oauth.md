# identity.mcp-client-oauth

Status: CANDIDATE. Package: `github.com/ajent-social/go/mcpclientoauth`.

## Intent

Coordinate OAuth 2.1 authorization-code + PKCE when the **product is the
client** connecting to remote MCP (or other) authorization servers. Durable
token records use caller-sealed ciphertext; the package never logs bearer
secrets. Auto-refresh within a configured margin; RFC 7009 revoke best-effort
at the provider then delete locally.

Distinct from `identity.mcp-oauth` (`mcpoauth`), where the product is the
authorization server.

## Non-goals

Consent UI, IdP login, KMS key management, MCP protocol transport.

## Provenance

Original public implementation. Behavioral boundaries informed by restricted
maintainer inspection of a private product MCP client OAuth seam; no private
source was copied.
