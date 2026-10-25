# MCP Streamable HTTP with AMSL bearer verification

Use the pinned official Go SDK v1.8.0 for transport, discovery and tool dispatch.
AMSL supplies reusable OAuth machinery beneath the application: the application
still owns login, account/workspace identity, consent UI, authority and effects.
This recipe is a composition sketch; it is not a standalone application or a
claim of deployed acceptance.

Mount AMSL discovery, authorization, registration (if enabled), token and
revocation handlers separately. Configure a fixed public issuer and resource;
never derive them from request Host. The consent handler must authenticate the
application user, show the current request, check CSRF and current application
authority, then call `Approve` with the application's subject and binding. Pass
only explicitly approved scopes. `Consent` and `Approve` revalidate CIMD metadata.

The protected MCP endpoint uses the SDK directly:

```go
// oauthServer is *mcpoauth.Server; sdkServer is *mcp.Server.
// Imports: context, errors, net/http, github.com/ajent-social/go/mcpoauth,
// github.com/modelcontextprotocol/go-sdk/auth and .../mcp.
stream := mcp.NewStreamableHTTPHandler(
    func(*http.Request) *mcp.Server { return sdkServer },
    &mcp.StreamableHTTPOptions{
        Stateless: true,
        MaxRequestBodyBytes: 1 << 20, // choose a finite application bound
    },
)
bearer := auth.RequireBearerToken(oauthServer.TokenVerifier,
    &auth.RequireBearerTokenOptions{
        ResourceMetadataURL: "https://mcp.example.com/.well-known/oauth-protected-resource",
        Scopes: []string{"read"},
    })(stream)
origins := http.NewCrossOriginProtection()
// Default protection rejects cross-origin browser requests. Add only explicitly
// trusted application origins if required; do not trust arbitrary request input.
mux.Handle("/mcp", origins.Handler(bearer))
```

Use TLS at the public boundary, an explicit allowed Host policy and finite HTTP
server read/header/write/idle timeouts appropriate to streaming. Origin
protection is not authentication and is not a substitute for the application's
consent CSRF protection. Keep SDK body bounds positive; a negative value disables
the SDK limit. The SDK's deprecated `CrossOriginProtection` option defaults to
nil; the explicit standard HTTP middleware above is intentional. Configure
trusted proxy forwarding separately; do not blindly trust forwarded Host headers.

Every business-effect tool must require a current application authorization
callback. It must deny when that callback or SDK identity is absent:

```go
// currentAuthorization is supplied by the application; it checks live workspace
// membership, requested operation, current policy and any effect-specific limits.
// It must remain an application decision, including transaction/TOCTOU handling.
mcp.AddTool(sdkServer, &mcp.Tool{Name: "read_item"},
    func(ctx context.Context, req *mcp.CallToolRequest, args struct{}) (
        *mcp.CallToolResult, any, error,
    ) {
        if req.Extra == nil || currentAuthorization == nil {
            return nil, nil, errors.New("authorization unavailable")
        }
        id, ok := mcpoauth.IdentityFromTokenInfo(req.Extra.TokenInfo)
        if !ok {
            return nil, nil, errors.New("authentication required")
        }
        if err := currentAuthorization(ctx, id, "read_item"); err != nil {
            return nil, nil, err
        }
        return readAuthorizedItem(ctx, id) // application-owned business effect
    })
```

Use `IdentityFromContext(r.Context())` in ordinary HTTP middleware after SDK
bearer authentication. Inside tools use `req.Extra.TokenInfo`, which the SDK
propagates to requests. The complete subject, binding, client, grant, scopes and
expiry remain available. The SDK session UserID binds the full grant context;
it is not the person ID or the bearer token. Bearer verification consults current
AMSL token/grant state on every HTTP request. Neither SDK identity nor stored
OAuth scopes grant live application permissions.

Clients use the official `mcp.NewClient` and `mcp.StreamableClientTransport`,
with an authorized HTTP client attaching the AMSL PKCE-issued bearer. Discovery
and wire negotiation remain SDK concerns. To revoke via HTTP, post both `token`
and its public `client_id` to the configured revocation endpoint. A mismatched
client receives success without mutation. `Server.Revoke` remains a trusted
server-side API and must not be exposed as an unbound HTTP shortcut.

Suggested coordinator checks (not executed for this source candidate):

```sh
go test ./mcpoauth/...
go test -race ./mcpoauth/...
```

`TestSDKStreamableHTTPWithIssuedPKCEBearer` exercises the actual SDK client and
server, local discovery documents, list/call, current application authorization,
Origin/body boundaries and absent/wrong/revoked bearer denial.
`TestCIMDFullPKCEAndChangingRedirect` uses a local trusted TLS fixture and private
DNS/dial seams, preserving the production address checks. All such results are
local evidence only. Maintainer review, executed checks and independent consumer
qualification remain separate release gates.
