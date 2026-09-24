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
