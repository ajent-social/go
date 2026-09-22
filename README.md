# AMSL for Go

Reusable application behavior, earned through real consumers.

This repository is the Go implementation home for [AMSL](https://github.com/ajent-social/capabilities). **Status: repository foundation. No runtime capability is implemented or promoted yet.** The module is `github.com/ajent-social/go`; there is no installable service-credential API to depend on today.

The first proposed slice is [scoped service credentials](docs/service-credentials.md). It must clear contract review, original-code/provenance review, adversarial tests and real application adoption before experimental promotion.

Use established libraries for crypto, sessions, payment clients and MCP. Keep application authorization and paid-access policy with the application.

```sh
go test .
go vet .
```

These currently verify only that the documentation package compiles. They do not verify runtime behavior. See [bootstrap status](docs/bootstrap.md), [contributing](CONTRIBUTING.md) and the [canonical RFC](https://github.com/ajent-social/capabilities/blob/main/docs/rfc/0001-amsl-bootstrap.md).
