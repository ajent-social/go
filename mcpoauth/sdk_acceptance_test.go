package mcpoauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type acceptanceBearerTransport struct {
	token string
	base  http.RoundTripper
}

func (b acceptanceBearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header = r.Header.Clone()
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}

// Issue through the real authorization, consent, approval and PKCE exchange
// paths. Only the test clock is controlled; token records are not fabricated.
func issueAcceptanceBearer(t *testing.T, s *Server, scopes []string) string {
	t.Helper()
	verifier := strings.Repeat("v", 64)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"client_id": {"fixture-client"}, "redirect_uri": {cimdRedirect}, "response_type": {"code"}, "scope": {strings.Join(scopes, " ")}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	handle := ""
	authorize := s.AuthorizeHandler(func(w http.ResponseWriter, r *http.Request, h string, _ ConsentRequest) {
		handle = h
		w.WriteHeader(http.StatusOK)
	})
	rr := httptest.NewRecorder()
	authorize.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	if rr.Code != 200 || handle == "" {
		t.Fatalf("authorize status %d", rr.Code)
	}
	if _, err := s.Consent(context.Background(), handle); err != nil {
		t.Fatal(err)
	}
	redirect, err := s.Approve(context.Background(), handle, Approval{Subject: "fixture-subject", Binding: "fixture-workspace", Scopes: scopes})
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"client_id": {"fixture-client"}, "redirect_uri": {cimdRedirect}, "grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "code_verifier": {verifier}}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	s.TokenHandler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("PKCE exchange status %d", rr.Code)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(context.Background(), out.AccessToken); err != nil {
		t.Fatal("issued token was not initially valid", err)
	}
	return out.AccessToken
}

func TestSDKHTTPExpiredAndInsufficientScopeBeforeBusinessCallback(t *testing.T) {
	for _, tc := range []struct {
		name, required, denial string
		status                 int
		expire                 bool
	}{
		{name: "expired issued bearer", required: "read", denial: "invalid token", status: http.StatusUnauthorized, expire: true},
		{name: "insufficient required scope", required: "write", denial: "insufficient scope", status: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			store := newCIMDStore()
			store.clients["fixture-client"] = Client{ID: "fixture-client", Name: "Fixture", RedirectURIs: []string{cimdRedirect}}
			s, err := New(Config{Issuer: "https://mcp.example.com", Resource: "https://mcp.example.com/mcp", Scopes: []string{"read", "write"}}, store)
			if err != nil {
				t.Fatal(err)
			}
			initial := time.Now()
			var clock atomic.Int64
			clock.Store(initial.UnixNano())
			s.now = func() time.Time { return time.Unix(0, clock.Load()) }
			deniedToken := issueAcceptanceBearer(t, s, []string{"read"})
			validToken := issueAcceptanceBearer(t, s, []string{"read", "write"})
			var callbacks, effects atomic.Int32
			server := mcp.NewServer(&mcp.Implementation{Name: "acceptance-fixture", Version: "1"}, nil)
			mcp.AddTool(server, &mcp.Tool{Name: "effect"}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
				callbacks.Add(1)
				if req.Extra == nil {
					return nil, nil, errors.New("missing identity")
				}
				id, ok := IdentityFromTokenInfo(req.Extra.TokenInfo)
				if !ok || id.Binding != "fixture-workspace" {
					return nil, nil, errors.New("application authorization denied")
				}
				effects.Add(1)
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "local effect"}}}, nil, nil
			})
			stream := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, MaxRequestBodyBytes: 4096})
			handler := auth.RequireBearerToken(s.TokenVerifier, &auth.RequireBearerTokenOptions{Scopes: []string{tc.required}})(stream)
			ts := httptest.NewServer(handler)
			defer ts.Close()
			client := mcp.NewClient(&mcp.Implementation{Name: "acceptance-client", Version: "1"}, nil)
			session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: ts.URL, HTTPClient: &http.Client{Transport: acceptanceBearerTransport{token: validToken, base: ts.Client().Transport}}}, nil)
			if err != nil {
				t.Fatal("valid control connection", err)
			}
			result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "effect", Arguments: map[string]any{}})
			session.Close()
			if err != nil || result == nil || result.IsError || callbacks.Load() != 1 || effects.Load() != 1 {
				t.Fatal("valid control did not reach business effect", result, err)
			}
			callbacks.Store(0)
			effects.Store(0)
			if tc.expire {
				clock.Store(initial.Add(2 * time.Hour).UnixNano())
			}
			// Actual HTTP reaches the official SDK auth middleware. The empty body is
			// deliberately never parsed or dispatched: bearer denial must occur first.
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL, strings.NewReader(""))
			req.Header.Set("Authorization", "Bearer "+deniedToken)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			resp, err := ts.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != tc.status || !strings.Contains(string(body), tc.denial) {
				t.Fatalf("denial: status=%d body=%q; want status=%d containing %q", resp.StatusCode, body, tc.status, tc.denial)
			}
			if callbacks.Load() != 0 || effects.Load() != 0 {
				t.Fatal("denied bearer reached business callback or effect")
			}
		})
	}
}
