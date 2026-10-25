package mcpoauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ajent-social/go/mcpoauth"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type bearerTransport struct {
	origin string
	token  string
	base   http.RoundTripper
}

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header = r.Header.Clone()
	if b.origin != "" {
		r.Header.Set("Origin", b.origin)
	}
	if b.token != "" {
		r.Header.Set("Authorization", "Bearer "+b.token)
	}
	return b.base.RoundTrip(r)
}

// This is application composition, not an exported AMSL middleware API.
// Validate every PRESENT Origin before any method/auth/transport handling.
func withConfiguredOrigin(configuredOrigin string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origins := r.Header.Values("Origin")
		if len(origins) > 0 && (len(origins) != 1 || origins[0] != configuredOrigin) {
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func TestSDKStreamableHTTPWithIssuedPKCEBearer(t *testing.T) {
	f := newFixture(t, mcpoauth.Config{})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	issue := func(binding string) string {
		t.Helper()
		code := f.issueCode(mcpoauth.Approval{Subject: "person", Binding: binding, Scopes: []string{"read"}})
		rr := f.exchange(code, nil)
		if rr.Code != 200 {
			t.Fatalf("exchange %d", rr.Code)
		}
		var out struct {
			AccessToken string `json:"access_token"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.AccessToken
	}
	token := issue("workspace-one")
	info, err := f.srv.TokenVerifier(ctx, token, nil)
	if err != nil {
		t.Fatal(err)
	}
	other, err := f.srv.TokenVerifier(ctx, issue("workspace-two"), nil)
	if err != nil || info.UserID == other.UserID || info.UserID == "person" || info.UserID == token {
		t.Fatal("session identity not bound to grant and workspace")
	}
	id, ok := mcpoauth.IdentityFromTokenInfo(info)
	if !ok || id.Binding != "workspace-one" || id.GrantID == "" || id.ClientID != f.client.ID || id.Subject != "person" || id.ExpiresAt.IsZero() {
		t.Fatal("incomplete identity", id)
	}
	id.Scopes[0] = "mutated"
	again, _ := mcpoauth.IdentityFromTokenInfo(info)
	if again.Scopes[0] != "read" {
		t.Fatal("identity aliases SDK Extra")
	}
	if _, ok := mcpoauth.IdentityFromContext(context.Background()); ok {
		t.Fatal("identity from unauthenticated context")
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "local-fixture", Version: "1"}, nil)
	var permitted atomic.Bool
	var effects atomic.Int32
	var callbacks atomic.Int32
	currentAuthorization := func(ctx context.Context, id mcpoauth.Identity) error {
		callbacks.Add(1)
		if !permitted.Load() || id.Binding != "workspace-one" || id.Subject != "person" {
			return errors.New("current application authority denied")
		}
		return nil
	}
	mcp.AddTool(server, &mcp.Tool{Name: "bounded_effect", Description: "Local fixture"}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		if req.Extra == nil {
			return nil, nil, errors.New("missing authentication")
		}
		id, ok := mcpoauth.IdentityFromTokenInfo(req.Extra.TokenInfo)
		if !ok || currentAuthorization == nil {
			return nil, nil, errors.New("missing current authorization")
		}
		if err := currentAuthorization(ctx, id); err != nil {
			return nil, nil, err
		}
		effects.Add(1)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "local effect"}}}, nil, nil
	})
	stream := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, MaxRequestBodyBytes: 4096})
	protected := auth.RequireBearerToken(f.srv.TokenVerifier, &auth.RequireBearerTokenOptions{ResourceMetadataURL: issuer + "/.well-known/oauth-protected-resource", Scopes: []string{"read"}})(stream)
	mux := http.NewServeMux()
	const configuredOrigin = "https://app.example.com"
	mux.Handle("/mcp", withConfiguredOrigin(configuredOrigin, protected))
	mux.Handle("/.well-known/oauth-authorization-server", f.srv.MetadataHandler())
	mux.Handle("/.well-known/oauth-protected-resource", f.srv.ProtectedResourceHandler())
	ts := httptest.NewServer(mux)
	defer ts.Close()
	// Exercise both advertised discovery documents over the local HTTP boundary.
	for _, path := range []string{"/.well-known/oauth-authorization-server", "/.well-known/oauth-protected-resource"} {
		resp, err := ts.Client().Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		err = json.NewDecoder(resp.Body).Decode(&doc)
		resp.Body.Close()
		if resp.StatusCode != 200 || err != nil || len(doc) == 0 {
			t.Fatal("discovery", path, err)
		}
	}
	connect := func(raw string, origins ...string) (*mcp.ClientSession, error) {
		origin := ""
		if len(origins) > 0 {
			origin = origins[0]
		}
		client := mcp.NewClient(&mcp.Implementation{Name: "local-client", Version: "1"}, nil)
		return client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: ts.URL + "/mcp", HTTPClient: &http.Client{Transport: bearerTransport{origin: origin, token: raw, base: ts.Client().Transport}}}, nil)
	}
	// Invalid and duplicate Origins must fail before safe as well as unsafe
	// method handling. Even a duplicated matching value is rejected.
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
		for _, origins := range [][]string{{"https://cross-site.invalid"}, {configuredOrigin, configuredOrigin}, {configuredOrigin, "https://cross-site.invalid"}, {""}, {"null"}, {configuredOrigin + ", " + configuredOrigin}} {
			req, _ := http.NewRequestWithContext(ctx, method, ts.URL+"/mcp", strings.NewReader("{}"))
			req.Header.Set("Authorization", "Bearer "+token)
			for _, origin := range origins {
				req.Header.Add("Origin", origin)
			}
			resp, err := ts.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("%s origins %q: got %d want 403", method, origins, resp.StatusCode)
			}
			if callbacks.Load() != 0 || effects.Load() != 0 {
				t.Fatal("origin rejection reached business callback")
			}
		}
		if method != http.MethodPost {
			for _, origin := range []string{"", configuredOrigin} {
				req, _ := http.NewRequestWithContext(ctx, method, ts.URL+"/mcp", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				if origin != "" {
					req.Header.Set("Origin", origin)
				}
				resp, err := ts.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				// Origin accepted: the stateless SDK then rejects safe methods with 405.
				if resp.StatusCode != http.StatusMethodNotAllowed {
					t.Fatalf("%s allowed origin %q: got %d want SDK 405", method, origin, resp.StatusCode)
				}
			}
		}
	}
	// The official client initializes and lists tools using the configured Origin.
	// The main session below exercises absent Origin for nonbrowser clients.
	originSession, err := connect(token, configuredOrigin)
	if err != nil {
		t.Fatal(err)
	}
	originTools, err := originSession.ListTools(ctx, &mcp.ListToolsParams{})
	originSession.Close()
	if err != nil || len(originTools.Tools) != 1 {
		t.Fatal("matching configured Origin rejected", err)
	}
	for _, raw := range []string{"", "wrong"} {
		session, err := connect(raw)
		if session != nil {
			session.Close()
		}
		if err == nil {
			t.Fatal("SDK accepted absent/wrong bearer")
		}
	}
	session, err := connect(token)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	tools, err := session.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil || len(tools.Tools) != 1 || tools.Tools[0].Name != "bounded_effect" {
		t.Fatal("SDK tool discovery", tools, err)
	}
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "bounded_effect", Arguments: map[string]any{}})
	if err == nil && (result == nil || !result.IsError) {
		t.Fatal("denied application call succeeded")
	}
	if effects.Load() != 0 || callbacks.Load() != 1 {
		t.Fatal("business effect before current authority")
	}
	permitted.Store(true)
	result, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "bounded_effect", Arguments: map[string]any{}})
	if err != nil || result.IsError || effects.Load() != 1 {
		t.Fatal("SDK call", result, err)
	}
	// Origin rejection and finite body bounds are part of this composition.
	for _, tc := range []struct {
		origin, body string
		status       int
	}{{"https://cross-site.invalid", "{}", 403}, {"", strings.Repeat("x", 4097), 413}} {
		req, _ := http.NewRequestWithContext(ctx, "POST", ts.URL+"/mcp", strings.NewReader(tc.body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if tc.origin != "" {
			req.Header.Set("Origin", tc.origin)
		}
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.status {
			t.Fatalf("boundary: got %d want %d", resp.StatusCode, tc.status)
		}
	}
	// Wrong-client revocation is an indistinguishable successful no-op.
	if rr := f.form("/oauth/revoke", url.Values{"token": {token}, "client_id": {"other-client"}}); rr.Code != 200 {
		t.Fatal(rr.Code)
	}
	if _, err := f.srv.Verify(ctx, token); err != nil {
		t.Fatal("wrong client revoked token", err)
	}
	if rr := f.form("/oauth/revoke", url.Values{"token": {token}, "client_id": {f.client.ID}}); rr.Code != 200 {
		t.Fatal(rr.Code)
	}
	if _, err := f.srv.Verify(ctx, token); err == nil {
		t.Fatal("revoked token verifies")
	}
	if _, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "bounded_effect", Arguments: map[string]any{}}); err == nil {
		t.Fatal("SDK accepted revoked bearer")
	}
	if effects.Load() != 1 {
		t.Fatal("effect after revocation")
	}
}

func TestDynamicRegistrationDisabled(t *testing.T) {
	f := newFixture(t, mcpoauth.Config{Issuer: issuer, Resource: resource, Scopes: []string{"read"}, DisableDynamicRegistration: true, EnableClientIDMetadataDocuments: true})
	rr := f.do(httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil))
	var doc map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["registration_endpoint"]; ok {
		t.Fatal("disabled endpoint advertised")
	}
	if doc["client_id_metadata_document_supported"] != true {
		t.Fatal("CIMD not advertised")
	}
	for _, method := range []string{"GET", "POST", "OPTIONS"} {
		rr := f.do(httptest.NewRequest(method, "/oauth/register", nil))
		if rr.Code != 404 {
			t.Fatal(method, rr.Code)
		}
	}
	if rr := f.authorize(nil); rr.Code != 200 {
		t.Fatal("opaque clients changed", rr.Code)
	}
}

func TestHTTPRevokeClientBinding(t *testing.T) {
	for _, kind := range []string{"access_token", "refresh_token"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t, mcpoauth.Config{})
			code := f.issueCode(mcpoauth.Approval{Subject: "user"})
			rr := f.exchange(code, nil)
			var tokens map[string]any
			if err := json.Unmarshal(rr.Body.Bytes(), &tokens); err != nil {
				t.Fatal(err)
			}
			raw := tokens[kind].(string)
			access := tokens["access_token"].(string)
			for _, id := range []string{"", "bad id", "https://example.com/no?query=1"} {
				rr := f.form("/oauth/revoke", url.Values{"token": {raw}, "client_id": {id}})
				if rr.Code != 400 {
					t.Fatal("malformed client accepted", id, rr.Code)
				}
			}
			for _, pair := range []struct{ token, id string }{{raw, "other"}, {"unknown", f.client.ID}} {
				rr := f.form("/oauth/revoke", url.Values{"token": {pair.token}, "client_id": {pair.id}})
				if rr.Code != 200 || rr.Body.Len() != 0 {
					t.Fatal("distinguishable response", rr.Code, rr.Body)
				}
			}
			if _, err := f.srv.Verify(context.Background(), access); err != nil {
				t.Fatal("no-op revoked grant", err)
			}
			rr = f.form("/oauth/revoke", url.Values{"token": {raw}, "client_id": {f.client.ID}})
			if rr.Code != 200 {
				t.Fatal(rr.Code)
			}
			if _, err := f.srv.Verify(context.Background(), access); err == nil {
				t.Fatal("correct client did not revoke")
			}
		})
	}
}
