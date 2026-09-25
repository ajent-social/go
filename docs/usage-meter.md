# billing.usage-meter

Status: CANDIDATE. Package: `github.com/ajent-social/go/usage`.

## Intent

Durable per-owner counters with CAS consume against an explicit limit.
Period keys are caller-defined (e.g. calendar month).

## Non-goals

Stripe billing meters, currency, or invoice line items.
