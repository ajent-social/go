# Recipe: CLI tool → hosted multi-tenant paid MCP service

Status: integration recipe for AMSL candidates. Not a SaaS framework and not a
stable blueprint. Each capability remains CANDIDATE until human review and
real consumer evidence.

## Goal

Take a useful local Go CLI/tool and offer it as a hosted service with:

1. Human sign-in (product-owned; use maintained OIDC + sessions, e.g. SCS)
2. Multi-tenant machine credentials (`servicecred` + `sqlstore`)
3. MCP access via OAuth (`mcpoauth` + durable Store; use SQL for multi-host)
4. Paid access via Stripe checkout + subscription projection
5. Product policy: what a paid tenant may invoke

The tool/engine stays product code. AMSL owns repeated coordination seams.

## Recommended composition order

| Step | AMSL / external | Notes |
| --- | --- | --- |
| 1 | Host + private Postgres | Product infra; prefer AMSL Pulumi contracts when ready |
| 2 | OIDC login + sessions | REFERENCE_EXISTING (`scs`, provider SDK) — not AMSL |
| 3 | `servicecred` + `sqlstore` | Issue/verify/revoke `amsl1_` keys per tenant owner/resource |
| 4 | `mcpoauth` | Bound MCP resource; consent after browser auth; Verify on MCP requests |
| 5 | Official MCP SDK | Protocol server — `protocol.mcp-server` is REJECTED for AMSL |
| 6 | `billing/checkout` + `stripeadapt` + SQL store | EnsureCustomer / StartCheckout / RecoverAttempt |
| 7 | `billing/subscription` | AcceptVerifiedEvent after Stripe signature verify; GetProjection(customer) |
| 8 | Product entitlement | Map projection status → allow/deny tool use; **redirect ≠ paid** |
| 9 | `delivery.go-validation` | Pin reusable workflow for CI |

## Multi-tenant defaults

- Treat `servicecred.Access.Owner` as the tenant/account id from your user table.
- Treat `Resource` as the hosted tool instance or MCP server id.
- Scopes are product vocabulary (`mcp:invoke`, `billing:read`, …).
- Use `sqlstore` (Postgres-compatible, including SereneDB) for anything shared
  across replicas. `boltstore` is single-host only.
- Resolve account → Stripe `CustomerRef` via `billing/checkout` bindings before
  reading `subscription.GetProjection`.

## Paid-access failure contract

1. Checkout success URL must **not** grant access.
2. Stripe webhook signature verify (SDK) → `subscription.AcceptVerifiedEvent`.
3. Admission paths resolve customer ref, call `GetProjection`, apply **your** grace/`past_due` rules.
4. Lost checkout responses: `RecoverAttempt` before creating a new unguarded session.

## Minimal wiring sketch

```go
credStore, _ := sqlstore.Open(ctx, db)           // servicecred/sqlstore
creds, _ := servicecred.New(credStore)

oauthStore, _ := oauthsql.Open(ctx, db) // mcpoauth/sqlstore for multi-host
oauth, _ := mcpoauth.New(cfg, oauthStore)

pay, _ := stripeadapt.New(os.Getenv("STRIPE_SECRET_KEY"))
billStore, _ := checkoutsql.Open(ctx, db)
billing, _ := checkout.New(billStore, pay)

subs, _ := subscription.New(subStore) // after AcceptVerifiedEvent from webhook
// entitlement: bind, err := billStore.LookupCustomer(ctx, account)
//               proj, err := subs.GetProjection(ctx, bind.CustomerRef)
```

Pin module versions. Keep product authorization beside AMSL Verify calls.

## What AMSL deliberately does not do

Universal user model, price catalog, email, admin UI, cloud account setup, or
replacing the MCP SDK. Those stay in the application or established libraries.

## Evidence status

As of this recipe, packages are CANDIDATE. Hours-scale delivery assumes agents
reuse these seams and write product policy from scratch — not that promotion
or production readiness is already proven.
