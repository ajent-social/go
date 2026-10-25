# identity.mcp-client-oauth

Status: CANDIDATE. Package: `github.com/ajent-social/go/mcpclientoauth`.

## Intent and boundary

Coordinate explicit-endpoint authorization-code + S256 PKCE when an application
is the OAuth **client** to a remote server. Store caller-sealed token ciphertext
and associate it with an application-supplied owner and server binding. The
application retains login, users, workspaces, permissions, consent and live
access policy. This package does not become the application's identity authority.
It is distinct from `mcpoauth`, an authorization server.

Discovery, registration, challenge handling, MCP transport, browser sessions,
consent UI and KMS management are outside this coordinator. Use the official
MCP Go SDK for protocol orchestration. This package does not claim full MCP
conformance or SDK interoperability qualification.

## Lifecycle v2: generation fencing and refresh ownership

Each `(ownerID, serverID)` binding has an opaque generation, store-managed
revision and one state: `empty`, `ready`, `claimed`, or `disconnected`.
Operations on a binding must be linearizable across every participating replica.
The SQL adapter uses atomic conditional updates and a transactional row lock
for disconnect; a process mutex is not its coordination mechanism.

| Operation | Precondition | Atomic result |
| --- | --- | --- |
| Start / BeginConnection | Fresh, never-reused random generation | Replace prior generation, clear ciphertext, revision 0, `empty` |
| Exchange / CompleteToken | Pending generation equals stored generation, revision 0, `empty` | Sealed token, revision + 1, `ready` |
| ClaimRefresh | Exact generation/revision from a `ready` snapshot | Revision + 1, `claimed`; return claimed snapshot |
| Refresh / CompleteToken | Exact claimed generation/revision | Replace ciphertext, revision + 1, `ready` |
| Revoke / Disconnect | Any state, including absent token | Atomically snapshot prior token, clear ciphertext, revision + 1, `disconnected` |

Start is an explicit reconnect: it immediately invalidates the old connection,
old pending callbacks and old refresh completions, even if authorization is
abandoned or pending persistence fails. Applications must authorize Start and
Revoke themselves. Generations must never be reused. Disconnect leaves a durable
invalidation record; completion is an UPDATE/CAS, never an upsert. A callback
already exchanging a code may finish its remote request, but cannot install its
result after disconnect or a newer Start. Pending state is consumed once; owner
and TTL checks precede the code POST.

Refresh claims commit **before** any refresh POST. Competing callers using the
same snapshot receive `ErrConflict`; a lookup during a claim receives
`ErrRefreshUncertain`. The coordinator does not wait or send a second POST. A
later lookup can use the winner's completed token. There is no claim expiry,
lease stealing, retry loop or automatic replay of the old refresh credential.
After transport errors, malformed responses, provider errors, seal errors,
cancellation, failed persistence or a crashed owner, the claim remains blocked.
The provider may have rotated even if the client did not receive a result.
If no successful completion is available, require a new authorization via Start
(or disconnect). Never reset a claim to `ready` to recover it. A database commit
error is not proof that the write did not commit: reread storage rather than
replaying the provider request. A failed ClaimRefresh returns without any POST.

Revoke commits local invalidation **before** best-effort provider revocation.
It also fences pending callbacks when no token exists. Local storage failure
returns an error. Provider errors are ignored; successful Revoke establishes
local disconnection only. It cannot recall plaintext already handed to a caller,
stop an in-flight remote request, or guarantee revocation at the provider.

The memory adapter implements the same transitions for coordinators sharing
**one Store instance**, using a mutex and owned copies of ciphertext. It is
process-local and ephemeral, not multi-process or durable qualification. Multiple
processes must use one authoritative SQL database or an equivalently qualified
LifecycleStore, never separate memory stores.

## API and storage migration (intentional narrow contract change)

The `New`, Start, Exchange, ValidToken and Revoke signatures and original Store
interface remain. New fields on exported structs are additive for keyed Go
literals; unkeyed literals must migrate to keyed literals. `New` now requires the
optional **LifecycleStore v2** capability and returns `ErrUnsupportedStore` for
legacy stores, rather than silently dropping lifecycle invariants. Custom stores
must implement the atomic semantics above, preserve pending generations, return
owned ciphertext, and make DeleteToken equivalent to durable Disconnect.

Both supplied adapters reject legacy unconditional PutToken with
`ErrUnsupportedStore`; direct callers must use BeginConnection and conditional
CompleteToken, or preferably Start/Exchange. TokenRecord now carries Generation
and Version; callers must not synthesize stale-write retries. LookupToken only
returns ready tokens; claimed yields `ErrRefreshUncertain`, and empty/disconnected
bindings yield `ErrNotFound`.

SQL Open creates `amsl_mcp_client_pending_v2` and `amsl_mcp_client_tokens_v2`.
It does not import old tokens, rewrite old tables or prove provider validity.
Drain **all old replicas and in-flight requests** before enabling v2, require
users to reconnect, and expire old pending browser flows. Old and new binaries
must not serve the same bindings concurrently: old binaries can still expose
legacy credentials and perform uncoordinated refreshes from the old tables.
A rolling mixed-version deployment is unsupported. A rollback requires the same
drain and reconnect discipline; never reactivate legacy token rows. Preserve or
remove legacy tables only through an application-owned, reviewed retention and
migration procedure. They can still contain secrets. No destructive migration
is performed by this adapter.

All replicas must use the same immutable ServerConfig for a server ID. Changing
issuer, audience, client identity or endpoint binding requires draining pending
flows and reconnecting under a new server ID; do not reinterpret stored grants.
Expired pending verifiers are not automatically pruned or encrypted by sqlstore.
The caller owns restricted database access, encryption at rest, retention and
seal/open key custody. PlainSeal/PlainOpen are test/development helpers only.

## Resource and authorization-response issuer

Set `ServerConfig.Resource` to the explicit canonical protected-resource URL.
The exact value is sent as `resource` on the authorization URL, code token POST
and refresh POST. It is not inferred from the token endpoint or callback.
Validation requires an absolute HTTPS URL (HTTP only on loopback), no userinfo,
fragment, uppercase host, trailing hostname dot, explicit default port or dot
path segments. URLs must round-trip without rewriting. Queries and significant
trailing slashes are preserved; callers choose the intended canonical audience.
An empty Resource keeps legacy **generic OAuth** behavior; it is not an MCP
resource-aware mode. Existing MCP callers must explicitly configure it.

Set `ServerConfig.ExpectedIssuer` to require exact callback `iss` equality.
Pass the parsed authorization-response issuer in `ExchangeInput.Issuer`.
Missing/mismatched values fail before any code POST. Without ExpectedIssuer,
legacy callbacks with no issuer remain accepted, and a supplied issuer is
rejected because this coordinator cannot validate it. The application must
reject duplicate callback parameters and handle authorization errors before
calling Exchange. This opt-in mode does not discover issuer metadata or infer
advertised RFC 9207 support; issuer-enabled servers require configuration.

The already-declared official Go SDK v1.8 supplies protected-resource and
authorization-server discovery, registration selection, resource-aware code
exchange, callback issuer validation and `AuthorizationCodeHandlerConfig`
`InitialTokenSource`/`NewTokenSource` hooks. Those are the intended protocol
integration seams, not a reason to add parallel discovery here. A future SDK
adapter must ensure **every** refresh goes through durable ownership; simply
using the SDK's default token source does not establish multi-replica safety.
SDK Streamable HTTP, discovery, registration, resource/issuer handling and
consumer denied-path interoperability remain separate, unexecuted release gates.

## Token response parsing

An omitted `refresh_token` in a successful refresh response retains the existing
refresh token, for providers that do not rotate on every refresh. This does not
apply to an explicitly present value: null, non-string, empty, control-character
or non-ASCII refresh credentials are rejected. A present `access_token` must
likewise be a nonempty printable ASCII string; it is always required. A present
`token_type` must be a nonempty RFC 6749 type-name or absolute URI, and a present
`scope` must be a printable ASCII string (empty scope is permitted). Omitted
optional token_type and scope retain the earlier compatibility behavior; no
Bearer-only token interpretation policy is imposed here.

Malformed credential responses return an error before sealing or completing the
token write. During refresh, the durable claim remains fenced because the
provider may already have consumed the old refresh token. Neither the bad
response nor a subsequent ValidToken call resets the connection to ready or
replays the old token. Reconnect remains the recovery path for an unavailable
outcome. Parser errors identify the field, never the credential value.

## Credential endpoint security

Token and revocation POSTs never follow HTTP redirects, including when the
caller supplies a permissive http.Client. New clones that client, replaces
CheckRedirect with denial, retains its Transport/TLS settings and caps Timeout
at 15 seconds (a shorter positive caller timeout is retained). The original
client is not changed. Token endpoint 3xx is a failure and a refresh claim stays
blocked; revocation 3xx is best-effort failure after local invalidation.

Configured endpoint trust, DNS/proxy behavior and custom Transport behavior
belong to the caller. This is not a general SSRF-safe discovery fetcher. A custom
RoundTripper must not implement its own redirects or credential POST retries.
Response bodies are bounded; tokens and provider response bodies are not logged.

## Proposed acceptance commands and evidence

This lifecycle refinement is **source only**: gofmt was applied; compilation,
tests, lint, SQL services, provider interoperability, application integration
and production acceptance were not run. The test sources below describe intended
regressions, not observed passes. Independent exact-head review, qualified
checks and human maintainer approval are required before merge or release.

For an authorized check runner:

```sh
go test -race -count=1 ./mcpclientoauth/...
go vet ./mcpclientoauth/...
# Narrow malformed-response/omission regressions (also included above):
go test -race -count=1 ./mcpclientoauth -run '^TestMemoryLifecycle/refresh-response$'
# Set DSN to an authorized disposable PostgreSQL-compatible database first.
AMSL_MCP_CLIENT_SQL_REQUIRED=1 go test -race -count=1 ./mcpclientoauth/sqlstore
# Narrow real-SQL response regressions, with the same DSN requirement:
AMSL_MCP_CLIENT_SQL_REQUIRED=1 go test -race -count=1 ./mcpclientoauth/sqlstore -run '^TestSQLLifecycle/refresh-response$'
```

`AMSL_SQLSTORE_TEST_DSN` selects the real SQL service. Supplying it makes failures
fatal. `AMSL_MCP_CLIENT_SQL_REQUIRED` set to any nonempty value fails visibly
without that DSN. With neither set, SQL tests explicitly skip: the memory harness
is never SQL qualification. SQL tests use two independent database pools and
unique binding rows, do not truncate tables, and leave their rows for inspection.
Do not point tests at a production database.

Regression sources cover: blocked refresh versus disconnect; old refresh and
callback versus reconnect; callback versus disconnect before any token exists;
two coordinators synchronized after reading the same old refresh token with
one outbound POST; lost rotating response with no replay; malformed credential
responses that remain fenced with one old-token POST; omitted refresh-token
retention and valid replacement persistence; credential POST
redirects for code/refresh/revoke (301/302/303/307/308) with a secret collector
receiving zero requests; resource validation/propagation; expected issuer denial
before POST; and unsupported-store denial. The rotating provider fixture is
synthetic; it is not official-server, SDK or live provider acceptance. Real SQL
adapter execution and its database-specific transaction behavior need their own
receipts. No status promotion or consumer adoption is asserted.

## Provenance

Original public implementation and lifecycle refinement. Earlier behavioral
inspection was restricted, maintainer-reported evidence, not independently
reproducible consumer verification. No private source was copied. Dependencies
and protocol orchestration remain with established libraries and the official
SDK; this refinement adds no dependency.
