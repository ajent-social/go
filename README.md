# AMSL for Go

Reusable application behavior, earned through real consumers.

This repository is the Go implementation home for
[AMSL](https://github.com/ajent-social/capabilities). The module is
`github.com/ajent-social/go`.

The first CANDIDATE implementation is `servicecred`, with a durable local bbolt
adapter in `servicecred/boltstore` and a multi-host SQL adapter in
`servicecred/sqlstore` for PostgreSQL-compatible servers (including
[SereneDB](https://github.com/serenedb/serenedb)). It provides issue-once machine
secrets, explicit owner/resource/scopes, mandatory expiry and durable
revocation. It is proposed for maintainer review, not a stable or released
security API.

The second CANDIDATE is `mcpoauth`, a bounded OAuth 2.1 authorization server
for a single MCP protected resource with public PKCE clients, plus a bbolt
reference store in `mcpoauth/boltstore` and a multi-host SQL adapter in
`mcpoauth/sqlstore`. It is an owner-authorized adaptation
of restricted product code; see the [contract](docs/mcp-oauth.md),
[provenance](docs/provenance-mcpoauth.md) and
[worklog](docs/mcpoauth-worklog.md). Refresh token rotation with
reuse-triggered family revocation is a new extension on top of the extracted
authorization-code flow.

A third CANDIDATE is `billing/checkout` for durable customer binding and
hosted checkout attempt recovery around an established payment provider. See
[billing checkout](docs/billing-checkout.md). Redirect URLs are not payment
evidence; entitlement policy stays with the application.

A fourth CANDIDATE is `billing/subscription` for a durable verified-event
inbox and local subscription projection after SDK signature verification. See
[billing subscription](docs/billing-subscription.md). Grace and `past_due`
policy stay with the application. Checkout companions include
`billing/checkout/stripeadapt`, `billing/checkout/sqlstore`,
`billing/portal` (Stripe Customer Portal), `billing/stripeverify` (webhook
signature → VerifiedEvent), and `billing/entitlement` (projection status gate).

Human auth CANDIDATEs for the hosted path: `accounts`, `passkey` (go-webauthn
ceremonies; patterns informed by ajent-social human accounts, no private source
copied), `magiclink` (email challenge tokens), `oidc` (OIDC authorization-code
social login around go-oidc) with `oidc/github`, `oidc/apple`, and
`oidc/microsoft` adapters, `passwordreset`, and `deviceflow` (RFC 8628 CLI
login). Each of accounts/passkey/magiclink/oidc/tenant has a multi-host
`sqlstore` adapter (PostgreSQL-compatible, including SereneDB). Browser session
cookies remain REFERENCE_EXISTING (e.g. SCS).

Additional identity/delivery CANDIDATEs: `mcpclientoauth` (product as OAuth
**client** to remote MCP servers; sealed token blobs), `publishablekey`
(embeddable public keys with origin allowlists; complements `servicecred`),
and `webhookegress` (HMAC-signed outbound webhooks).

Hosted instance lifecycle CANDIDATE: `tenant` coordinates slug → provision →
ready → upgrade/destroy around a product `Runtime` (typically Pulumi
`containerdeploy` + `tenantdnstls`). Call `billing/entitlement` before Request.

Additional CANDIDATEs: `usage` (bounded meters), `sealedvault` (caller-sealed
ciphertext only).

Composition recipe (CLI → hosted multi-tenant paid MCP with user/billing
management and passkey/magic/OIDC auth):
[docs/recipes/cli-to-hosted-paid-mcp.md](docs/recipes/cli-to-hosted-paid-mcp.md).

Read the [contract](docs/service-credentials.md),
[provenance and alternatives](docs/provenance-servicecred.md), and
[implementation worklog](docs/servicecred-worklog.md) before adopting it.
Applications retain login, authorization, account-status and paid-access policy.
The bbolt adapter uses local file locks and is supported on Unix platforms listed
in the contract; on other platforms, provide another `Store` implementation.
`sqlstore` accepts an application-owned `*sql.DB`; swap PostgreSQL ↔ SereneDB
(or another compatible server) by changing the driver and DSN only.

```sh
go vet ./...
go test -race ./...
# sqlstore tests need a PostgreSQL-compatible server; CI sets AMSL_SQLSTORE_TEST_DSN, or locally:
#   createdb -h /tmp amsl_servicecred_test
#   AMSL_SQLSTORE_TEST_DSN='host=/tmp dbname=amsl_servicecred_test sslmode=disable'
```

Use established libraries for crypto, sessions, payment clients and MCP. See
[contributing](CONTRIBUTING.md) and the
[canonical RFC](https://github.com/ajent-social/capabilities/blob/main/docs/rfc/0001-amsl-bootstrap.md).
