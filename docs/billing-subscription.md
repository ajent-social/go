# billing.subscription-reconciliation

Status: CANDIDATE implementation for review. Package:
`github.com/ajent-social/go/billing/subscription`.

## Intent

Maintain a durable inbox of signature-verified provider events and a local
per-customer subscription projection. Callers authenticate Stripe (or other)
webhooks with the official SDK, normalize the payload, then call
`AcceptVerifiedEvent`. Admission paths read `GetProjection(customerRef)` and
apply **product** entitlement rules (grace, `past_due`, seat limits). Checkout
redirect URLs are never payment evidence.

Map local accounts to `CustomerRef` via `billing/checkout` customer bindings
(or equivalent), not inside this package.

## API

- `AcceptVerifiedEvent(event)` — dedupe on `(Livemode, EventID)`; same
  `PayloadHash` is harmless; conflicting hash → `ErrConflict`. Empty
  `CustomerRef` persists as unmatched without touching projections.
- `GetProjection(customer)` — durable local view

Out-of-order: `PeriodEnd` never moves backward; terminal statuses
(`canceled`/`unpaid`/`deleted`) are not revived by older non-terminal events.

## Store

`subscription/memory` for tests. `subscription/sqlstore` for multi-host
PostgreSQL-compatible servers (DSN swap to SereneDB). `ApplyProjection` is CAS
on lease epoch.

## Non-goals

Universal entitlement predicates, multi-provider façades, webhook signature
verification (use the provider SDK), and price catalogs.

## Provenance

Original public implementation from the published capability contract. No
private billing source was copied.
