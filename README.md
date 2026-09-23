# AMSL for Go

Reusable application behavior, earned through real consumers.

This repository is the Go implementation home for
[AMSL](https://github.com/ajent-social/capabilities). The module is
`github.com/ajent-social/go`.

The first CANDIDATE implementation is `servicecred`, with a durable local bbolt
adapter in `servicecred/boltstore`. It provides issue-once machine secrets,
explicit owner/resource/scopes, mandatory expiry and durable revocation. It is
proposed for maintainer review, not a stable or released security API.

Read the [contract](docs/service-credentials.md),
[provenance and alternatives](docs/provenance-servicecred.md), and
[implementation worklog](docs/servicecred-worklog.md) before adopting it.
Applications retain login, authorization, account-status and paid-access policy.
The bbolt adapter uses local file locks and is supported on Unix platforms listed
in the contract; on other platforms, provide another `Store` implementation.

```sh
go vet ./...
go test -race ./...
```

Use established libraries for crypto, sessions, payment clients and MCP. See
[contributing](CONTRIBUTING.md) and the
[canonical RFC](https://github.com/ajent-social/capabilities/blob/main/docs/rfc/0001-amsl-bootstrap.md).
