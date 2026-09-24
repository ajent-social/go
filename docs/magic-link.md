# identity.magic-link

Status: CANDIDATE. Package: `github.com/ajent-social/go/magiclink`.

## Intent

Issue and consume single-use hashed email challenges. Mail delivery is a
`Mailer` seam (SMTP/provider). After `Consume`, the application mints a browser
session (e.g. SCS) for the subject.

`magiclink/memory` for tests. `magiclink/sqlstore` for multi-host PostgreSQL-compatible
servers.

## Non-goals

User directory, HTML email templates, rate-limit middleware (callers rate-limit
at the edge), and password auth.
