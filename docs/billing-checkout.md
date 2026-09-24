# billing.customer-checkout

Status: CANDIDATE implementation for review. Package:
`github.com/ajent-social/go/billing/checkout`.

## Intent

Coordinate durable local customer binding and hosted checkout attempts around
an established payment provider (Stripe via a `Provider` adapter). Reuse the
official SDK for provider HTTP; this package owns attempt identity, lease-safe
recovery after lost responses, and conflict detection when approved parameters
change.

## API

- `EnsureCustomer(account, attempt)` — bind or recover a provider customer
- `StartCheckout(input)` — claim a checkout attempt and return a redirect URL
- `RecoverAttempt(account, attempt)` — resolve unknown/in-flight attempts

A success redirect URL is **not** payment evidence. Paid access belongs to the
caller (typically after verified webhooks / subscription reconciliation).

## Store

`Store` abstracts durable bindings and attempts. `checkout/memory` is for tests
and single-process demos. `checkout/sqlstore` targets PostgreSQL-compatible
servers (including SereneDB). `checkout/stripeadapt` wraps the official Stripe
Go SDK as a `Provider`.

## Non-goals

Price engines, multi-provider façades, entitlement policy, card data, and
universal subscription access predicates.

## Provenance

Original public implementation from the published capability contract. No
private billing source was copied.
