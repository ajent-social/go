# billing.stripe-webhook-verify

Status: CANDIDATE. Package: `github.com/ajent-social/go/billing/stripeverify`.

## Intent

Verify `Stripe-Signature` with stripe-go and map events into
`subscription.VerifiedEvent` for `AcceptVerifiedEvent`.

## Non-goals

HTTP routing, entitlement policy, or inventing a second webhook crypto path.
