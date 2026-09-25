# delivery.webhook-ingress

Status: CANDIDATE. Package: `github.com/ajent-social/go/webhookingress`.

## Intent

Verify inbound AMSL HMAC webhook signatures on HTTP requests. Signature header
matches `webhookegress`: `X-AMSL-Signature: t=<unix>,v1=<hex hmac>` over
`t + "." + body`. Default skew is five minutes. `VerifyRequest` reads a bounded
raw body and returns it on success.

## Non-goals

Provider webhook formats (Stripe, Svix/Resend, GitHub, etc.), outbound delivery
(see `webhookegress`), event taxonomies, or durable inbox semantics.

## Provenance

Original public implementation. Signature format is identical to
`webhookegress.Sign` / `Verify` so egress producers and ingress receivers
interoperate without a shared import of the dispatcher.
