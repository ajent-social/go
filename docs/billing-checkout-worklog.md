# billing.customer-checkout worklog

2026-09-24. Lifecycle: CANDIDATE. Disposition: EXTRACT.

Implemented `billing/checkout` with `EnsureCustomer`, `StartCheckout`,
`RecoverAttempt`, a `Store` interface, `Provider` seam for the official Stripe
SDK, and an in-memory store for tests. Executed: `go test -race ./billing/...`
PASS (idempotent ensure, checkout replay/conflict, recover-after-unknown,
provider failure → unknown). No live Stripe keys. No private source copied.

Next: Stripe SDK adapter, SQL store, Ferro hosted consumer in test mode
(login → checkout → webhook → access; redirect alone denied). REAL_CONSUMER
and HUMAN_REVIEW remain NOT_RUN.

## 2026-09-24 — recover lease fix

`RecoverAttempt` now claims a fresh lease before commit so it cannot overwrite
another worker's terminal row on a stale epoch; stale non-terminal outcomes
return `ErrBusy`. `StartCheckout` derives a bounded EnsureCustomer attempt ID
so max-length checkout attempts no longer fail validation. Tests cover long
attempt IDs and stale-lease protection.

## 2026-09-24 — stripeadapt + sqlstore

Added `billing/checkout/stripeadapt` (official stripe-go/v82 customer + Checkout
Session) and `billing/checkout/sqlstore` (PG-compatible customers/attempts).
Composition recipe: `docs/recipes/cli-to-hosted-paid-mcp.md`.

