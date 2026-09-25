# billing.entitlement

Status: CANDIDATE. Package: `github.com/ajent-social/go/billing/entitlement`.

## Intent

Fail-closed gate: allow product actions only when a local subscription
projection status is in an explicit allow-list (default `active`, `trialing`).
Looks up checkout customer binding then subscription projection.

## Non-goals

Grace/`past_due` policy (caller must list statuses), Stripe API calls, or
treating checkout redirect success as paid.
