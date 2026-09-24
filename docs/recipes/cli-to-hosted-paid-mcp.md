# Recipe: CLI tool → hosted multi-tenant paid MCP service

Status: integration recipe for AMSL candidates. Not a SaaS framework and not a
stable blueprint. Each capability remains CANDIDATE until human review and
real consumer evidence.

## Goal

Take a useful local Go CLI/tool and offer it as a hosted service with:

1. Human accounts + auth (passkey and/or email magic link and/or OIDC social) + browser sessions
2. User management (thin account registry; disable fail-closed)
3. Billing management (checkout + subscription projection + Stripe portal)
4. Multi-tenant machine credentials (`servicecred` + `sqlstore`)
5. MCP access via OAuth (`mcpoauth` + `sqlstore`)
6. Product entitlement: what a paid tenant may invoke
7. Dedicated instance lifecycle (`tenant` + Pulumi `privatedatabase` / `containerdeploy` / `tenantdnstls`)

The tool/engine stays product code. AMSL owns repeated coordination seams.

## Recommended composition order

| Step | AMSL / external | Notes |
| --- | --- | --- |
| 1 | Host + private Postgres | Pulumi `privatedatabase` or product infra |
| 2 | `accounts` + `sqlstore` | Create / EnsureByEmail / Disable / RequireActive |
| 3a | `passkey` + `sqlstore` + go-webauthn | Discoverable UV passkeys; RP from configured origin |
| 3b | `magiclink` + `sqlstore` + Mailer | Email challenge; you send mail and mint session after Consume |
| 3c | `oidc` + memory/store | Social OIDC (Google/Apple…); link subject → account; mint session after Accept |
| 3d | Sessions | REFERENCE_EXISTING (`scs` or hashed cookie like product sessions) |
| 4 | `servicecred` + `sqlstore` | `Owner` = `accounts.Account.ID` |
| 5 | `mcpoauth` + `sqlstore` | Consent after browser auth; Verify on MCP requests |
| 6 | Official MCP SDK | Protocol server — not AMSL |
| 7 | `billing/checkout` + `stripeadapt` + SQL | EnsureCustomer / StartCheckout / RecoverAttempt |
| 8 | `billing/subscription` | AcceptVerifiedEvent after Stripe signature verify |
| 9 | `billing/portal` | Self-serve invoices / payment method / cancel |
| 10 | Product entitlement | Projection status → allow/deny; **redirect ≠ paid** |
| 11 | `tenant` + Runtime | Request → Provision → Ready; Runtime = Pulumi apply |
| 12 | `tenantdnstls` + `containerdeploy` | `*.product.cloud` cert + digest-pinned Fargate |
| 13 | `delivery.go-validation` | Pin reusable CI workflow |

## Auth notes (from ajent-social passkey patterns)

- Prefer discoverable, user-verified passkeys via go-webauthn — do not hand-roll
  attestation or signature checks.
- Ceremony cookies: consume before verify (single-use even on failed assertion).
- Relying party ID = hostname of the configured public origin; never `Host`.
- Email magic is complementary for recovery/onboarding; ajent-social human
  accounts intentionally omit email in that product — AMSL still offers
  `magiclink` for products that need it.
- After either Finish(passkey), Consume(magiclink), or Accept(oidc)+LinkBinding,
  call `accounts.RequireActive` then mint **your** session.
- OIDC redirect URIs and issuer trust are configured absolutes — never from
  request `Host`. State is consume-once.

## User management

`accounts` is deliberately thin. Workspace/org membership, roles, and admin UI
stay in the application. Disabled accounts must not receive new sessions or
MCP consent.

## Billing management

1. Checkout → bind customer (`billing/checkout`)
2. Webhook → projection (`billing/subscription`)
3. Customer “manage billing” → `billing/portal.Start` (Stripe Customer Portal)
4. Entitlement reads projection, never the success redirect

## Multi-tenant defaults

- `servicecred.Access.Owner` = `accounts.Account.ID`
- `Resource` = hosted tool / MCP server id
- SQL stores for anything shared across replicas; boltstore is single-host only

## Minimal wiring sketch

```go
acct, _ := accounts.New(acctStore)
pk, _ := passkey.New(passkey.Config{RPDisplayName: "App", Origin: origin}, pkStore)
ml, _ := magiclink.New(magiclink.Config{BaseURL: origin + "/auth/magic"}, mlStore, mailer)

// after passkey.Finish or magiclink.Consume:
//   a, _ := acct.RequireActive(ctx, subjectID)
//   session.Put(r, a.ID) // scs or equivalent

creds, _ := servicecred.New(credStore)
oauth, _ := mcpoauth.New(cfg, oauthStore)
billing, _ := checkout.New(billStore, stripeadapt.Must...)
subs, _ := subscription.New(subStore)
portalSvc, _ := portal.New(billStore, portalStripe)
```

## Dedicated instances

After entitlement is true, `tenant.Request` then `Provision` against a product
`Runtime` that applies Pulumi (`tenantdnstls` for `slug.product.cloud`,
`containerdeploy` for digest-pinned Fargate, optional shared
`privatedatabase`). Hostname = `slug.baseDomain`. Destroy fails closed on
runtime errors (status `failed`).

## What AMSL deliberately does not do

Universal org/RBAC model, HTML login pages, email provider account setup, price
catalog, or replacing the MCP SDK / go-webauthn / Stripe SDK / Pulumi AWS
provider.

## Evidence status

Packages are CANDIDATE. Hours-scale delivery assumes agents reuse these seams
and write product UI/policy — not that promotion is proven.
