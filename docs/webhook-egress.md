# delivery.webhook-egress

Status: CANDIDATE. Package: `github.com/ajent-social/go/webhookegress`.

## Intent

Register HTTPS webhook endpoints, emit events, HMAC-SHA256 sign payloads, and
deliver with bounded concurrency, durable attempt status, and per-owner rate
limits. Event type strings are caller-defined.

Signature header: `X-AMSL-Signature: t=<unix>,v1=<hex hmac>` over
`t + "." + body`.

## Non-goals

Inbound provider webhook verification (use the provider SDK), product event
taxonomies, exactly-once delivery guarantees.

## Provenance

Original public implementation. Behavioral boundaries informed by restricted
maintainer inspection of a private product egress webhook seam; no private
source was copied.
