# AMSL for Go

Reusable application behavior, earned through real consumers.

This repository is the Go implementation home for
[AMSL](https://github.com/ajent-social/capabilities). The module is
`github.com/ajent-social/go`.

The first CANDIDATE implementation is `servicecred`, with a durable local bbolt
adapter in `servicecred/boltstore` and a multi-host PostgreSQL adapter in
`servicecred/pgstore`. It provides issue-once machine secrets, explicit
owner/resource/scopes, mandatory expiry and durable revocation. It is proposed
for maintainer review, not a stable or released security API.

The second CANDIDATE is `mcpoauth`, a bounded OAuth 2.1 authorization server
for a single MCP protected resource with public PKCE clients, plus a bbolt
reference store in `mcpoauth/boltstore`. It is an owner-authorized adaptation
of restricted product code; see the [contract](docs/mcp-oauth.md),
[provenance](docs/provenance-mcpoauth.md) and
[worklog](docs/mcpoauth-worklog.md). Refresh token rotation with
reuse-triggered family revocation is a new extension on top of the extracted
authorization-code flow.

Read the [contract](docs/service-credentials.md),
[provenance and alternatives](docs/provenance-servicecred.md), and
[implementation worklog](docs/servicecred-worklog.md) before adopting it.
Applications retain login, authorization, account-status and paid-access policy.
The bbolt adapter uses local file locks and is supported on Unix platforms listed
in the contract; on other platforms, provide another `Store` implementation.
`pgstore` accepts an application-owned `*sql.DB` against PostgreSQL for shared
authoritative storage across hosts.

```sh
go vet ./...
go test -race ./...
# pgstore tests need PostgreSQL; CI sets AMSL_PGSTORE_TEST_DSN, or locally:
#   createdb -h /tmp amsl_servicecred_test
#   AMSL_PGSTORE_TEST_DSN='host=/tmp dbname=amsl_servicecred_test sslmode=disable'
```

Use established libraries for crypto, sessions, payment clients and MCP. See
[contributing](CONTRIBUTING.md) and the
[canonical RFC](https://github.com/ajent-social/capabilities/blob/main/docs/rfc/0001-amsl-bootstrap.md).
