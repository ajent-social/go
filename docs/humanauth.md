# identity.human-session

Status: CANDIDATE. Package: `github.com/ajent-social/go/humanauth`.

## Intent

Compose `magiclink` and `passkey` into a working browser sign-in:

- a hashed-token session cookie (only `sha256(cookie)` is stored, the same
  digest-at-rest pattern as `magiclink.Challenge.TokenDigest` and
  `passkey.Ceremony.HandleDigest`);
- a per-session CSRF token, checked together with the standard library's
  `http.CrossOriginProtection`;
- the HTTP routes the magic-link and passkey ceremonies need.

This is the "hashed cookie" option for step 3e (Sessions) of the
[CLI → hosted paid MCP recipe](recipes/cli-to-hosted-paid-mcp.md). It adds no
module dependency.

`New` builds its own `magiclink.Service` (`BaseURL = PublicURL + Prefix +
"/magic"`) and `passkey.Service` (`Origin = PublicURL`), so the mailed link,
the WebAuthn origin, the relying-party ID and the trusted CSRF origin all come
from one configured value. `Host` is never read.

`humanauth/memory` is for tests; `humanauth/sqlstore` is for multi-host
PostgreSQL-compatible servers (table `amsl_humanauth_sessions`, schema applied
idempotently by `Open`).

## Routes

`p` is `Config.Prefix` (default `/auth`). `Paths()` returns these paths,
sorted; `Handler()` matches full request paths, so mount it at each path or at
`p + "/"`.

| Method and path | Guard | Behaviour |
| --- | --- | --- |
| `POST p/magic/request` (form `email`, `next`) | cross-origin | `SubjectForEmail` → `Admit` → `magiclink.Issue`. Every outcome logs at warn (never the email or token) and returns 303 to `p/magic/sent`, so a refused email looks like an allowed one. A safe `next` is kept in the `<base>_next` cookie. |
| `GET p/magic/sent` | — | "Check your email" page. |
| `GET p/magic` | — | Redeem page: a `POST p/magic` form, a Sign in button, `<script src="p/magic.js">`. |
| `GET p/magic.js` | — | Moves the fragment token into the form, drops the fragment with `history.replaceState`, submits once. |
| `POST p/magic` (form `token`) | cross-origin | `Consume` → `SubjectForEmail` → `Admit` → mint → 303 to `next` or `AfterLogin`. Any failure: 400 "link invalid or expired", no session. |
| `GET p/passkey.js` | — | `humanauthPasskey.login(prefix)` and `humanauthPasskey.register(prefix, csrfToken)`. |
| `POST p/passkey/login/begin` | cross-origin | `BeginLogin` → ceremony cookie → options JSON. |
| `POST p/passkey/login/finish` | cross-origin | Ceremony cookie read and cleared before `Finish`; body capped at 64 KiB; `KindLogin` only; `Admit` → mint → `{"redirect": AfterLogin}`. Failure: 400 `{"error":"passkey sign-in failed"}`. |
| `POST p/passkey/register/begin` | session + CSRF (401 / 403) | `BeginRegistration(subject, add = CountCredentials > 0)` → ceremony cookie → options JSON. |
| `POST p/passkey/register/finish` | session + CSRF | Ceremony cookie cleared, body capped, `Finish`; kind must be register or add and the subject must be the session's → 204. |
| `POST p/logout` | CSRF when a session exists | Deletes the record, expires the cookie, 303 to `AfterLogout`. |

"Cross-origin" means `http.CrossOriginProtection.Check` fails → 403.

Every response carries `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
`X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src
'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none';
form-action 'self'` and, except the two scripts, `Cache-Control: no-store`.
Pages use embedded `html/template`s with no inline script or style;
`Config.Stylesheet` adds one `<link rel="stylesheet">`.

## Cookies

| Cookie | Value | Attributes |
| --- | --- | --- |
| `CookieName` (default `__Host-session`) | base64url of 32 random bytes | `Path=/`, `HttpOnly`, `SameSite=Lax`, `Expires` = session expiry, `Secure` when `PublicURL` is https |
| `<base>_next` | base64url of a local path | `Path=p`, `HttpOnly`, `SameSite=Lax`, `Max-Age` = `MagicLinkTTL` |
| `<base>_ceremony` | passkey ceremony handle | `Path=p/passkey`, `HttpOnly`, `SameSite=Strict`, `Max-Age` = `CeremonyTTL` |

`<base>` is `CookieName` without a leading `__Host-` (those cookies need
`Path=/`, and these two use narrower paths). `New` rejects `__Host-` and
`__Secure-` names on an http origin. http is accepted only for `localhost`,
`127.0.0.1` and `[::1]`.

Signing in again from a browser that already carries a session deletes the
earlier record. `next` and `AfterLogin`/`AfterLogout` must be local paths:
start with `/`, not `//` or `/\`, no control characters, no scheme or host.

## CSRF

`CheckCSRF` passes GET, HEAD and OPTIONS. Other methods need both:

1. `http.CrossOriginProtection` (built once in `New`, with `PublicURL` as the
   only trusted origin) passes, and
2. a session exists and its token matches `X-CSRF-Token` in constant time.
   The `csrf_token` form field is read only when that header is absent and the
   body is `application/x-www-form-urlencoded`. Multipart bodies are never
   parsed, so they must send the header.

Use `CSRFToken(r)` to render the token into forms or pages that call
`humanauthPasskey.register`.

## Policy contract

The application implements `Policy`; humanauth never decides who may sign in.

- `SubjectForEmail(ctx, email)` maps an email to a `Subject`. Any error
  refuses: no mail at request time, no session at redeem time. If the
  challenge carries a subject id, the redeem-time subject must match it.
- `Admit(ctx, subjectID)` runs before every session is minted, by either
  method, and before a magic link is mailed. It returns the current subject,
  whose `ID` must equal the one asked for. Any error refuses. Disabled
  accounts must fail here.

`Subject.ID` becomes the WebAuthn user handle, which the authenticator stores.
Use an opaque stable id, not the email; put the email in `Subject.Name`.

## What the application still owns

- The login page (email form posting `email` and `next` to `p/magic/request`,
  and a button calling `humanauthPasskey.login(p)`), and any account settings
  page offering `humanauthPasskey.register(p, csrfToken)`.
- Rate limiting, at least on `POST p/magic/request`. Mail delivery time can
  also differ between allowed and refused addresses; rate limiting bounds what
  that reveals.
- Account policy and the user directory, via `Policy`.
- A periodic `Sweep` to delete expired session records. Expired magic-link
  challenges and passkey ceremonies are single-use and expire on their own.
- Session listing and revocation UI, via `Sessions`, `Revoke` and
  `RevokeSubject`.

`Config.Now` drives session expiry and also re-checks magic-link expiry at
redeem; `magiclink` itself enforces its expiry on the wall clock.

## Non-goals

User directory, account policy, rate limiting, login page, OIDC social login,
password reset, and session storage other than the hashed-record `Store`.

## Tests and consumer verification

Actual tests (`go test -race ./humanauth/...`):

- config validation, magic-link sign-in with exact cookie attributes and
  digest-only storage, refused emails indistinguishable from allowed ones,
  single use, expiry, `Admit` refusal, `next` sanitisation, cross-site
  rejection on every guarded route, session expiry, `CheckCSRF` cases
  (header, urlencoded field, multipart, another session's token, cross-site),
  logout, listing and revocation, `Sweep`, security headers on every route,
  and `Paths`;
- passkey register → add → login end to end against a test-only software
  authenticator (`humanauth/internal/testauthn`: ES256, `none` attestation,
  discoverable credential), ceremony consume-before-verify and replay, session
  and CSRF guards on registration, and `Admit` refusal at login;
- `humanauth/sqlstore` against PostgreSQL (`AMSL_SQLSTORE_TEST_DSN`).

The browser scripts (`magic.js`, `passkey.js`) are not exercised by an
automated browser test.

Consumer verification: none recorded yet. One restricted consumer, unverified by readers,
is wiring this package in.

## Provenance

New implementation, no private code copied.
