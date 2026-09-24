# identity.accounts

Status: CANDIDATE. Package: `github.com/ajent-social/go/accounts`.

Thin subject registry (id, optional unique email, display name, active/disabled).
Not orgs, RBAC, or billing entitlement. Use `Account.ID` as `servicecred` Owner.

`accounts/memory` for tests. `accounts/sqlstore` for multi-host PostgreSQL-compatible
servers (DSN swap to SereneDB).
