# billing.subscription-reconciliation worklog

2026-09-24. Lifecycle: CANDIDATE. Disposition: EXTRACT.

Implemented `billing/subscription` with verified-event inbox, lease-CAS
projections, memory and SQL stores. Duplicate `(livemode, event_id)` with the
same payload hash is a no-op; conflicting hashes return `ErrConflict`.
Out-of-order PeriodEnd/terminal rules covered by package tests. No live Stripe
keys. No private source copied.

Next: catalog implementation pointer after merge; Path C consumer proving
webhook → projection → access with redirect denied. REAL_CONSUMER and
HUMAN_REVIEW remain NOT_RUN.
