package mcpoauth_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ajent-social/go/mcpoauth"
)

// memStore is a test-only Store. It is deliberately not exported by the
// package: production tokens must live in durable storage. One mutex per
// call gives every method the atomicity the contract requires.
type memStore struct {
	mu       sync.Mutex
	clients  map[string]mcpoauth.Client
	consents map[string]mcpoauth.ConsentRecord
	codes    map[string]mcpoauth.CodeRecord
	tokens   map[string]mcpoauth.TokenRecord
	grants   map[string]mcpoauth.GrantRecord
	refresh  map[string]mcpoauth.RefreshRecord
	fail     error
	// policy, when set, runs inside CreateGrant and RotateRefresh like an
	// application's live issuance check.
	policy func(g mcpoauth.GrantRecord) error
	// rotations counts successful RotateRefresh commits.
	rotations int
}

func newMemStore() *memStore {
	return &memStore{
		clients: map[string]mcpoauth.Client{}, consents: map[string]mcpoauth.ConsentRecord{},
		codes: map[string]mcpoauth.CodeRecord{}, tokens: map[string]mcpoauth.TokenRecord{},
		grants: map[string]mcpoauth.GrantRecord{}, refresh: map[string]mcpoauth.RefreshRecord{},
	}
}

func (m *memStore) CreateClient(_ context.Context, c mcpoauth.Client) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return m.fail
	}
	if _, ok := m.clients[c.ID]; ok {
		return mcpoauth.ErrExists
	}
	m.clients[c.ID] = c
	return nil
}
func (m *memStore) Client(_ context.Context, id string) (mcpoauth.Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return mcpoauth.Client{}, m.fail
	}
	c, ok := m.clients[id]
	if !ok {
		return mcpoauth.Client{}, mcpoauth.ErrNotFound
	}
	return c, nil
}
func (m *memStore) CreateConsent(_ context.Context, c mcpoauth.ConsentRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return m.fail
	}
	if _, ok := m.consents[c.ID]; ok {
		return mcpoauth.ErrExists
	}
	m.consents[c.ID] = c
	return nil
}
func (m *memStore) Consent(_ context.Context, id string) (mcpoauth.ConsentRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.consents[id]
	if !ok {
		return mcpoauth.ConsentRecord{}, mcpoauth.ErrNotFound
	}
	return c, nil
}
func (m *memStore) ConsumeConsent(_ context.Context, id string) (mcpoauth.ConsentRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.consents[id]
	if !ok {
		return mcpoauth.ConsentRecord{}, mcpoauth.ErrNotFound
	}
	delete(m.consents, id)
	return c, nil
}
func (m *memStore) CreateCode(_ context.Context, c mcpoauth.CodeRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return m.fail
	}
	if _, ok := m.codes[c.ID]; ok {
		return mcpoauth.ErrExists
	}
	m.codes[c.ID] = c
	return nil
}
func (m *memStore) ConsumeCode(_ context.Context, id string) (mcpoauth.CodeRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return mcpoauth.CodeRecord{}, m.fail
	}
	c, ok := m.codes[id]
	if !ok {
		return mcpoauth.CodeRecord{}, mcpoauth.ErrNotFound
	}
	delete(m.codes, id)
	return c, nil
}
func (m *memStore) CreateGrant(_ context.Context, g mcpoauth.GrantIssue) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return m.fail
	}
	if m.policy != nil {
		if err := m.policy(g.Grant); err != nil {
			return err
		}
	}
	if _, ok := m.grants[g.Grant.ID]; ok {
		return mcpoauth.ErrExists
	}
	if _, ok := m.tokens[g.Token.ID]; ok {
		return mcpoauth.ErrExists
	}
	if g.Refresh != nil {
		if _, ok := m.refresh[g.Refresh.ID]; ok {
			return mcpoauth.ErrExists
		}
		m.refresh[g.Refresh.ID] = *g.Refresh
	}
	m.grants[g.Grant.ID] = g.Grant
	m.tokens[g.Token.ID] = g.Token
	return nil
}
func (m *memStore) Grant(_ context.Context, id string) (mcpoauth.GrantRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return mcpoauth.GrantRecord{}, m.fail
	}
	g, ok := m.grants[id]
	if !ok {
		return mcpoauth.GrantRecord{}, mcpoauth.ErrNotFound
	}
	return g, nil
}
func (m *memStore) Token(_ context.Context, id string) (mcpoauth.TokenRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return mcpoauth.TokenRecord{}, m.fail
	}
	t, ok := m.tokens[id]
	if !ok {
		return mcpoauth.TokenRecord{}, mcpoauth.ErrNotFound
	}
	return t, nil
}
func (m *memStore) Refresh(_ context.Context, id string) (mcpoauth.RefreshRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return mcpoauth.RefreshRecord{}, m.fail
	}
	r, ok := m.refresh[id]
	if !ok {
		return mcpoauth.RefreshRecord{}, mcpoauth.ErrNotFound
	}
	return r, nil
}
func (m *memStore) RotateRefresh(_ context.Context, r mcpoauth.RefreshRotation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return m.fail
	}
	old, ok := m.refresh[r.RefreshID]
	if !ok {
		return mcpoauth.ErrNotFound
	}
	if !old.UsedAt.IsZero() {
		if g, ok := m.grants[old.GrantID]; ok && g.RevokedAt.IsZero() {
			g.RevokedAt = r.At
			m.grants[g.ID] = g
		}
		return mcpoauth.ErrReused
	}
	g, ok := m.grants[old.GrantID]
	if !ok {
		return mcpoauth.ErrNotFound
	}
	if !g.RevokedAt.IsZero() {
		return mcpoauth.ErrDenied
	}
	if r.Token.GrantID != g.ID || r.Refresh.GrantID != g.ID {
		return mcpoauth.ErrInvalid
	}
	if m.policy != nil {
		if err := m.policy(g); err != nil {
			return err
		}
	}
	if _, ok := m.tokens[r.Token.ID]; ok {
		return mcpoauth.ErrExists
	}
	if _, ok := m.refresh[r.Refresh.ID]; ok {
		return mcpoauth.ErrExists
	}
	m.tokens[r.Token.ID] = r.Token
	m.refresh[r.Refresh.ID] = r.Refresh
	old.UsedAt, old.ReplacedBy = r.At, r.Refresh.ID
	m.refresh[old.ID] = old
	m.rotations++
	return nil
}
func (m *memStore) RevokeGrant(_ context.Context, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return m.fail
	}
	g, ok := m.grants[id]
	if !ok {
		return mcpoauth.ErrNotFound
	}
	if g.RevokedAt.IsZero() {
		g.RevokedAt = at
		m.grants[id] = g
	}
	return nil
}

// expireAll pushes every grant, token and refresh expiry into the past.
func (m *memStore) expireAll(t time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, g := range m.grants {
		g.ExpiresAt = t
		m.grants[k] = g
	}
	for k, tk := range m.tokens {
		tk.ExpiresAt = t
		m.tokens[k] = tk
	}
	for k, r := range m.refresh {
		r.ExpiresAt = t
		m.refresh[k] = r
	}
}

const (
	issuer   = "https://mcp.example.test"
	resource = "https://mcp.example.test/mcp"
	redirect = "https://client.example.test/callback"
	verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk_extra_padding_chars"
)

func challenge(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

type fixture struct {
	t     *testing.T
	srv   *mcpoauth.Server
	store *memStore
	mux   *http.ServeMux
	// last consent callback invocation
	handle string
	req    mcpoauth.ConsentRequest
	client mcpoauth.Client
}

func newFixture(t *testing.T, cfg mcpoauth.Config) *fixture {
	t.Helper()
	store := newMemStore()
	if cfg.Issuer == "" {
		cfg.Issuer, cfg.Resource, cfg.Scopes = issuer, resource, []string{"read", "write"}
	}
	srv, err := mcpoauth.New(cfg, store)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f := &fixture{t: t, srv: srv, store: store, mux: http.NewServeMux()}
	f.mux.Handle("GET /.well-known/oauth-authorization-server", srv.MetadataHandler())
	f.mux.Handle("GET /.well-known/oauth-protected-resource", srv.ProtectedResourceHandler())
	f.mux.Handle("/oauth/register", srv.RegisterHandler())
	f.mux.Handle("/oauth/token", srv.TokenHandler())
	f.mux.Handle("/oauth/revoke", srv.RevokeHandler())
	f.mux.Handle("/oauth/authorize", srv.AuthorizeHandler(func(w http.ResponseWriter, r *http.Request, handle string, req mcpoauth.ConsentRequest) {
		f.handle, f.req = handle, req
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("consent"))
	}))
	f.client = mcpoauth.Client{ID: "client-1", Name: "Test Client", RedirectURIs: []string{redirect}, CreatedAt: time.Now()}
	if err := store.CreateClient(context.Background(), f.client); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) do(req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	f.mux.ServeHTTP(rr, req)
	return rr
}

func (f *fixture) authorizeURL(over map[string]string) string {
	q := url.Values{
		"response_type": {"code"}, "client_id": {f.client.ID}, "redirect_uri": {redirect},
		"code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"},
		"state": {"xyz"}, "scope": {"read"}, "resource": {resource},
	}
	for k, v := range over {
		if v == "" {
			q.Del(k)
		} else {
			q.Set(k, v)
		}
	}
	return "/oauth/authorize?" + q.Encode()
}

func (f *fixture) authorize(over map[string]string) *httptest.ResponseRecorder {
	f.handle = ""
	return f.do(httptest.NewRequest(http.MethodGet, f.authorizeURL(over), nil))
}

func (f *fixture) form(path string, v url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return f.do(req)
}

func (f *fixture) tokenForm(code string, over map[string]string) url.Values {
	v := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {f.client.ID}, "redirect_uri": {redirect}, "code_verifier": {verifier}}
	for k, val := range over {
		if val == "" {
			v.Del(k)
		} else {
			v.Set(k, val)
		}
	}
	return v
}

// issueCode runs authorize + approve and returns the code from the redirect.
func (f *fixture) issueCode(a mcpoauth.Approval) string {
	f.t.Helper()
	if rr := f.authorize(nil); rr.Code != 200 || f.handle == "" {
		f.t.Fatalf("authorize: %d %s", rr.Code, rr.Body)
	}
	if len(a.Scopes) == 0 {
		request, e := f.srv.Consent(context.Background(), f.handle)
		if e != nil {
			f.t.Fatal(e)
		}
		a.Scopes = request.Scopes
	}
	loc, err := f.srv.Approve(context.Background(), f.handle, a)
	if err != nil {
		f.t.Fatalf("approve: %v", err)
	}
	u, _ := url.Parse(loc)
	if !strings.HasPrefix(loc, redirect+"?") || u.Query().Get("state") != "xyz" {
		f.t.Fatalf("unexpected redirect %s", loc)
	}
	return u.Query().Get("code")
}

func (f *fixture) exchange(code string, over map[string]string) *httptest.ResponseRecorder {
	return f.form("/oauth/token", f.tokenForm(code, over))
}

func (f *fixture) exchangeBody(code string, over map[string]string) (*httptest.ResponseRecorder, map[string]any) {
	rr := f.exchange(code, over)
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	return rr, body
}

func oauthErr(t *testing.T, rr *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if rr.Code != status || body["error"] != code {
		t.Fatalf("want %d %s, got %d %s", status, code, rr.Code, rr.Body)
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("token responses must be no-store")
	}
}

func redirectErr(t *testing.T, rr *httptest.ResponseRecorder, code string) {
	t.Helper()
	if rr.Code != http.StatusFound {
		t.Fatalf("want 302, got %d %s", rr.Code, rr.Body)
	}
	u, err := url.Parse(rr.Header().Get("Location"))
	if err != nil || !strings.HasPrefix(u.String(), redirect+"?") {
		t.Fatalf("redirect must target the registered uri: %s", rr.Header().Get("Location"))
	}
	if got := u.Query().Get("error"); got != code {
		t.Fatalf("want error %s, got %s (%s)", code, got, u)
	}
	if u.Query().Get("state") != "xyz" {
		t.Fatalf("state not echoed: %s", u)
	}
}

func TestNewConfigValidation(t *testing.T) {
	t.Parallel()
	base := func() mcpoauth.Config {
		return mcpoauth.Config{Issuer: issuer, Resource: resource, Scopes: []string{"read"}}
	}
	cases := []struct {
		name string
		mut  func(*mcpoauth.Config)
		ok   bool
	}{
		{"valid", func(*mcpoauth.Config) {}, true},
		{"http issuer", func(c *mcpoauth.Config) { c.Issuer = "http://mcp.example.test" }, false},
		{"loopback http issuer", func(c *mcpoauth.Config) { c.Issuer = "http://127.0.0.1:8080"; c.Resource = "http://127.0.0.1:8080/mcp" }, true},
		{"issuer path", func(c *mcpoauth.Config) { c.Issuer = issuer + "/" }, false},
		{"issuer query", func(c *mcpoauth.Config) { c.Issuer = issuer + "?x=1" }, false},
		{"resource fragment", func(c *mcpoauth.Config) { c.Resource = resource + "#f" }, false},
		{"no scopes", func(c *mcpoauth.Config) { c.Scopes = nil }, false},
		{"dup scopes", func(c *mcpoauth.Config) { c.Scopes = []string{"a", "a"} }, false},
		{"scope with space", func(c *mcpoauth.Config) { c.Scopes = []string{"a b"} }, false},
		{"ttl too long", func(c *mcpoauth.Config) { c.AccessTokenTTL = 48 * time.Hour }, false},
		{"code ttl too long", func(c *mcpoauth.Config) { c.CodeTTL = time.Hour }, false},
		{"negative ttl", func(c *mcpoauth.Config) { c.ConsentTTL = -1 }, false},
		{"bad path", func(c *mcpoauth.Config) { c.TokenPath = "token?x" }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := base()
			tc.mut(&cfg)
			_, err := mcpoauth.New(cfg, newMemStore())
			if (err == nil) != tc.ok {
				t.Fatalf("ok=%v err=%v", tc.ok, err)
			}
			if err != nil && !errors.Is(err, mcpoauth.ErrInvalid) {
				t.Fatalf("want ErrInvalid, got %v", err)
			}
		})
	}
	if _, err := mcpoauth.New(base(), nil); !errors.Is(err, mcpoauth.ErrInvalid) {
		t.Fatal("nil store must be rejected")
	}
}

func TestMetadataIsConfiguredNotHostDerived(t *testing.T) {
	t.Parallel()
	f := newFixture(t, mcpoauth.Config{})
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	req.Host = "evil.example.test"
	rr := f.do(req)
	var m map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil || rr.Code != 200 {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	if m["issuer"] != issuer || m["token_endpoint"] != issuer+"/oauth/token" || m["registration_endpoint"] != issuer+"/oauth/register" {
		t.Fatalf("metadata derived from host: %s", rr.Body)
	}
	if got := m["grant_types_supported"].([]any); len(got) != 2 || got[0] != "authorization_code" || got[1] != "refresh_token" {
		t.Fatalf("grant types must reflect what is served: %v", got)
	}
	off := newFixture(t, mcpoauth.Config{Issuer: issuer, Resource: resource, Scopes: []string{"read"}, DisableRefresh: true})
	rr = off.do(httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))
	if strings.Contains(rr.Body.String(), "refresh") {
		t.Fatal("refresh must not be advertised when disabled")
	}
	if got := m["code_challenge_methods_supported"].([]any); len(got) != 1 || got[0] != "S256" {
		t.Fatal("only S256 may be advertised")
	}
	rr = f.do(httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil))
	if !strings.Contains(rr.Body.String(), `"resource":"`+resource+`"`) || !strings.Contains(rr.Body.String(), `"authorization_servers":["`+issuer+`"]`) {
		t.Fatalf("resource metadata: %s", rr.Body)
	}
	rr = f.do(httptest.NewRequest(http.MethodPost, "/.well-known/oauth-protected-resource", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatal("POST must be rejected")
	}
	w := httptest.NewRecorder()
	f.srv.Challenge(w, true)
	if w.Code != 401 || w.Header().Get("WWW-Authenticate") != `Bearer resource_metadata="`+issuer+`/.well-known/oauth-protected-resource", error="invalid_token"` {
		t.Fatalf("challenge: %d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
}

func TestHappyPathAndVerify(t *testing.T) {
	t.Parallel()
	f := newFixture(t, mcpoauth.Config{})
	code := f.issueCode(mcpoauth.Approval{Subject: "user-1", Binding: "acct-9", Scopes: []string{"read"}})
	if f.req.ClientName != "Test Client" || !slices.Equal(f.req.Scopes, []string{"read"}) || f.req.Resource != resource {
		t.Fatalf("consent request: %+v", f.req)
	}
	rr, body := f.exchangeBody(code, nil)
	if rr.Code != 200 || body["token_type"] != "bearer" || body["scope"] != "read" || body["expires_in"].(float64) != 3600 {
		t.Fatalf("exchange: %d %s", rr.Code, rr.Body)
	}
	rt, _ := body["refresh_token"].(string)
	if rt == "" {
		t.Fatal("refresh token expected by default")
	}
	tok := body["access_token"].(string)
	id, err := f.srv.Verify(context.Background(), tok)
	if err != nil || id.Subject != "user-1" || id.Binding != "acct-9" || !slices.Equal(id.Scopes, []string{"read"}) || id.ClientID != f.client.ID || id.GrantID == "" {
		t.Fatalf("verify: %+v %v", id, err)
	}
	// Only digests are stored; the grant binds the family.
	for k := range f.store.tokens {
		if k == tok || strings.Contains(k, tok) || strings.Contains(k, rt) {
			t.Fatal("raw token persisted")
		}
	}
	for k, r := range f.store.refresh {
		if k == rt || strings.Contains(k, rt) || r.GrantID != id.GrantID || r.Generation != 1 {
			t.Fatalf("refresh record: %+v", r)
		}
	}
	if g := f.store.grants[id.GrantID]; g.Subject != "user-1" || g.Binding != "acct-9" || !slices.Equal(g.Scopes, []string{"read"}) || g.ClientID != f.client.ID || g.Resource != resource {
		t.Fatalf("grant record: %+v", g)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	if got, ok := mcpoauth.BearerToken(req); !ok || got != tok {
		t.Fatal("BearerToken")
	}
	req.Header.Set("Authorization", "Basic abc")
	if _, ok := mcpoauth.BearerToken(req); ok {
		t.Fatal("non-bearer accepted")
	}
	// Consent handle consumed; second approve fails.
	if _, err := f.srv.Approve(context.Background(), f.handle, mcpoauth.Approval{Scopes: []string{"read"}, Subject: "user-1"}); !errors.Is(err, mcpoauth.ErrNotFound) {
		t.Fatalf("second approve: %v", err)
	}
}

func TestCodeReplayAndBurn(t *testing.T) {
	t.Parallel()
	f := newFixture(t, mcpoauth.Config{})
	code := f.issueCode(mcpoauth.Approval{Subject: "u"})
	if rr := f.exchange(code, nil); rr.Code != 200 {
		t.Fatal(rr.Body)
	}
	oauthErr(t, f.exchange(code, nil), 400, "invalid_grant")

	// A failed PKCE attempt burns the code for the real client too.
	code = f.issueCode(mcpoauth.Approval{Subject: "u"})
	oauthErr(t, f.exchange(code, map[string]string{"code_verifier": strings.Repeat("a", 50)}), 400, "invalid_grant")
	oauthErr(t, f.exchange(code, nil), 400, "invalid_grant")
}

func TestConcurrentRedemption(t *testing.T) {
	t.Parallel()
	f := newFixture(t, mcpoauth.Config{})
	code := f.issueCode(mcpoauth.Approval{Subject: "u"})
	const n = 32
	var wg sync.WaitGroup
	results := make(chan int, n)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rr := f.exchange(code, nil)
			results <- rr.Code
		}()
	}
	wg.Wait()
	close(results)
	ok := 0
	for c := range results {
		if c == 200 {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("want exactly one success, got %d", ok)
	}
}

func TestTokenExchangeDenials(t *testing.T) {
	t.Parallel()
	f := newFixture(t, mcpoauth.Config{})
	other := mcpoauth.Client{ID: "client-2", Name: "Other", RedirectURIs: []string{redirect}}
	_ = f.store.CreateClient(context.Background(), other)
	cases := []struct {
		name   string
		over   map[string]string
		status int
		code   string
	}{
		{"wrong client", map[string]string{"client_id": "client-2"}, 400, "invalid_grant"},
		{"unknown client", map[string]string{"client_id": "nope"}, 400, "invalid_grant"},
		{"wrong redirect", map[string]string{"redirect_uri": redirect + "/x"}, 400, "invalid_grant"},
		{"wrong verifier", map[string]string{"code_verifier": strings.Repeat("b", 60)}, 400, "invalid_grant"},
		{"short verifier", map[string]string{"code_verifier": "short"}, 400, "invalid_request"},
		{"verifier bad chars", map[string]string{"code_verifier": strings.Repeat("a", 42) + "!"}, 400, "invalid_request"},
		{"resource mismatch", map[string]string{"resource": "https://other.example.test/mcp"}, 400, "invalid_target"},
		{"grant type", map[string]string{"grant_type": "client_credentials"}, 400, "unsupported_grant_type"},
		{"missing client", map[string]string{"client_id": ""}, 400, "invalid_request"},
		{"missing code", map[string]string{"code": ""}, 400, "invalid_request"},
		{"missing verifier", map[string]string{"code_verifier": ""}, 400, "invalid_request"},
		{"bogus code", map[string]string{"code": "not-a-code"}, 400, "invalid_grant"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code := f.issueCode(mcpoauth.Approval{Subject: "u"})
			oauthErr(t, f.exchange(code, tc.over), tc.status, tc.code)
		})
	}
	t.Run("explicit matching resource ok", func(t *testing.T) {
		code := f.issueCode(mcpoauth.Approval{Subject: "u"})
		if rr := f.exchange(code, map[string]string{"resource": resource}); rr.Code != 200 {
			t.Fatal(rr.Body)
		}
	})
}

func TestTokenFormHardening(t *testing.T) {
	t.Parallel()
	f := newFixture(t, mcpoauth.Config{})
	post := func(path, body, ct string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", ct)
		return f.do(req)
	}
	form := "application/x-www-form-urlencoded"
	base := f.tokenForm("abc", nil).Encode()
	oauthErr(t, post("/oauth/token", base+"&client_id=client-2", form), 400, "invalid_request")
	oauthErr(t, post("/oauth/token?client_id=x", base, form), 400, "invalid_request")
	oauthErr(t, post("/oauth/token", base, "application/json"), 400, "invalid_request")
	oauthErr(t, post("/oauth/token", base+"&pad="+strings.Repeat("a", 20<<10), form), 400, "invalid_request")
	oauthErr(t, post("/oauth/token", base+"&x="+strings.Repeat("a", 3000), form), 400, "invalid_request")
	oauthErr(t, post("/oauth/token", "code=a%0d%0ab", form), 400, "invalid_request")
	oauthErr(t, post("/oauth/token", "%zz", form), 400, "invalid_request")
	oauthErr(t, f.do(httptest.NewRequest(http.MethodGet, "/oauth/token", nil)), 405, "invalid_request")
}

func TestAuthorizeDirectErrorsNeverRedirect(t *testing.T) {
	t.Parallel()
	f := newFixture(t, mcpoauth.Config{})
	cases := []struct {
		name string
		over map[string]string
	}{
		{"missing client", map[string]string{"client_id": ""}},
		{"unknown client", map[string]string{"client_id": "nope"}},
		{"missing redirect", map[string]string{"redirect_uri": ""}},
		{"redirect prefix", map[string]string{"redirect_uri": redirect + "/../x"}},
		{"redirect extra path", map[string]string{"redirect_uri": redirect + "x"}},
		{"redirect query injection", map[string]string{"redirect_uri": redirect + "?x=1"}},
		{"redirect fragment", map[string]string{"redirect_uri": redirect + "#f"}},
		{"redirect userinfo", map[string]string{"redirect_uri": "https://client.example.test@evil.test/callback"}},
		{"redirect case", map[string]string{"redirect_uri": strings.ToUpper(redirect)}},
		{"redirect crlf", map[string]string{"redirect_uri": redirect + "%0d%0aSet-Cookie:x"}},
		{"redirect http", map[string]string{"redirect_uri": "http://client.example.test/callback"}},
		{"redirect other scheme", map[string]string{"redirect_uri": "javascript:alert(1)"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := f.authorize(tc.over)
			if rr.Code != http.StatusBadRequest || rr.Header().Get("Location") != "" || f.handle != "" {
				t.Fatalf("want direct 400 without redirect, got %d loc=%q", rr.Code, rr.Header().Get("Location"))
			}
			if len(f.store.consents) != 0 {
				t.Fatal("consent record must not be created")
			}
		})
	}
	t.Run("duplicate params rejected", func(t *testing.T) {
		rr := f.do(httptest.NewRequest(http.MethodGet, f.authorizeURL(nil)+"&redirect_uri=https://evil.test/", nil))
		if rr.Code != 400 || rr.Header().Get("Location") != "" {
			t.Fatalf("%d %q", rr.Code, rr.Header().Get("Location"))
		}
	})
	t.Run("oversized query", func(t *testing.T) {
		rr := f.do(httptest.NewRequest(http.MethodGet, f.authorizeURL(nil)+"&pad="+strings.Repeat("a", 9000), nil))
		if rr.Code != http.StatusRequestURITooLong {
			t.Fatal(rr.Code)
		}
	})
	t.Run("oversized field", func(t *testing.T) {
		rr := f.authorize(map[string]string{"scope": strings.Repeat("a", 2100)})
		if rr.Code != 400 || rr.Header().Get("Location") != "" {
			t.Fatal(rr.Code)
		}
	})
	t.Run("post rejected", func(t *testing.T) {
		if rr := f.form("/oauth/authorize", url.Values{"client_id": {"client-1"}}); rr.Code != 405 {
			t.Fatal(rr.Code)
		}
	})
	t.Run("store failure is 500 not redirect", func(t *testing.T) {
		f.store.fail = errors.New("disk")
		defer func() { f.store.fail = nil }()
		if rr := f.authorize(nil); rr.Code != 500 {
			t.Fatal(rr.Code)
		}
	})
}

func TestAuthorizeProtocolErrorsRedirect(t *testing.T) {
	t.Parallel()
	f := newFixture(t, mcpoauth.Config{})
	cases := []struct {
		name string
		over map[string]string
		code string
	}{
		{"response_type token", map[string]string{"response_type": "token"}, "unsupported_response_type"},
		{"response_type missing", map[string]string{"response_type": ""}, "unsupported_response_type"},
		{"plain pkce", map[string]string{"code_challenge_method": "plain"}, "invalid_request"},
		{"missing method", map[string]string{"code_challenge_method": ""}, "invalid_request"},
		{"missing challenge", map[string]string{"code_challenge": ""}, "invalid_request"},
		{"short challenge", map[string]string{"code_challenge": "abc"}, "invalid_request"},
		{"padded challenge", map[string]string{"code_challenge": challenge(verifier)[:42] + "="}, "invalid_request"},
		{"long state", map[string]string{"state": strings.Repeat("s", 1025)}, "invalid_request"},
		{"scope outside ceiling", map[string]string{"scope": "read admin"}, "invalid_scope"},
		{"scope duplicate", map[string]string{"scope": "read read"}, "invalid_scope"},
		{"resource mismatch", map[string]string{"resource": "https://other.example.test/mcp"}, "invalid_target"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := f.authorize(tc.over)
			if tc.name == "long state" {
				if rr.Code != 302 || !strings.HasPrefix(rr.Header().Get("Location"), redirect) {
					t.Fatal(rr.Code)
				}
				return
			}
			redirectErr(t, rr, tc.code)
			if f.handle != "" {
				t.Fatal("consent must not be requested")
			}
		})
	}
	t.Run("empty scope means full ceiling", func(t *testing.T) {
		if rr := f.authorize(map[string]string{"scope": ""}); rr.Code != 200 || !slices.Equal(f.req.Scopes, []string{"read", "write"}) {
			t.Fatalf("%d %+v", rr.Code, f.req)
		}
	})
	t.Run("state optional", func(t *testing.T) {
		if rr := f.authorize(map[string]string{"state": ""}); rr.Code != 200 {
			t.Fatal(rr.Code)
		}
	})
}

func TestApprovalCannotWidenOrReplace(t *testing.T) {
	t.Parallel()
	f := newFixture(t, mcpoauth.Config{})
	ctx := context.Background()
	f.authorize(nil) // requested scope: read
	cases := []struct {
		name string
		a    mcpoauth.Approval
	}{
		{"scope widened", mcpoauth.Approval{Subject: "u", Scopes: []string{"read", "write"}}},
		{"scope outside", mcpoauth.Approval{Subject: "u", Scopes: []string{"admin"}}},
		{"empty subject", mcpoauth.Approval{Scopes: []string{"read"}}},
		{"crlf subject", mcpoauth.Approval{Subject: "u\r\n"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := f.srv.Approve(ctx, f.handle, tc.a); !errors.Is(err, mcpoauth.ErrInvalid) {
				t.Fatalf("want ErrInvalid, got %v", err)
			}
			if _, err := f.srv.Consent(ctx, f.handle); err != nil {
				t.Fatal("rejected approval must leave the consent record intact")
			}
		})
	}
	// Approval cannot change client, redirect or PKCE: the code carries the
	// original values regardless of what the application passes.
	loc, err := f.srv.Approve(ctx, f.handle, mcpoauth.Approval{Scopes: []string{"read"}, Subject: "u", Binding: "b"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(loc, redirect+"?") {
		t.Fatal(loc)
	}
	for _, c := range f.store.codes {
		if c.ClientID != f.client.ID || c.RedirectURI != redirect || c.CodeChallenge != challenge(verifier) || !slices.Equal(c.Scopes, []string{"read"}) {
			t.Fatalf("code bound to wrong request: %+v", c)
		}
	}
	if _, err := f.srv.Approve(ctx, "bogus-handle", mcpoauth.Approval{Scopes: []string{"read"}, Subject: "u"}); !errors.Is(err, mcpoauth.ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := f.srv.Consent(ctx, ""); !errors.Is(err, mcpoauth.ErrNotFound) {
		t.Fatal(err)
	}
}

func TestDeny(t *testing.T) {
	t.Parallel()
	f := newFixture(t, mcpoauth.Config{})
	f.authorize(nil)
	loc, err := f.srv.Deny(context.Background(), f.handle)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(loc)
	if !strings.HasPrefix(loc, redirect+"?") || u.Query().Get("error") != "access_denied" || u.Query().Get("state") != "xyz" || u.Query().Get("code") != "" {
		t.Fatal(loc)
	}
	if _, err := f.srv.Deny(context.Background(), f.handle); !errors.Is(err, mcpoauth.ErrNotFound) {
		t.Fatal("deny must consume")
	}
}

func TestExpiry(t *testing.T) {
	t.Parallel()
	f := newFixture(t, mcpoauth.Config{CodeTTL: time.Minute, ConsentTTL: time.Minute, AccessTokenTTL: time.Minute})
	ctx := context.Background()
	f.authorize(nil)
	// Expire the consent record directly in the store.
	for k, c := range f.store.consents {
		c.ExpiresAt = time.Now().Add(-time.Second)
		f.store.consents[k] = c
	}
	if _, err := f.srv.Consent(ctx, f.handle); !errors.Is(err, mcpoauth.ErrExpired) {
		t.Fatalf("consent: %v", err)
	}
	if _, err := f.srv.Approve(ctx, f.handle, mcpoauth.Approval{Scopes: []string{"read"}, Subject: "u"}); !errors.Is(err, mcpoauth.ErrExpired) {
		t.Fatalf("approve: %v", err)
	}
	code := f.issueCode(mcpoauth.Approval{Subject: "u"})
	for k, c := range f.store.codes {
		c.ExpiresAt = time.Now().Add(-time.Second)
		f.store.codes[k] = c
	}
	oauthErr(t, f.exchange(code, nil), 400, "invalid_grant")
	code = f.issueCode(mcpoauth.Approval{Subject: "u"})
	_, body := f.exchangeBody(code, nil)
	tok := body["access_token"].(string)
	for k, c := range f.store.tokens {
		c.ExpiresAt = time.Now().Add(-time.Second)
		f.store.tokens[k] = c
	}
	if _, err := f.srv.Verify(ctx, tok); !errors.Is(err, mcpoauth.ErrDenied) {
		t.Fatalf("expired token: %v", err)
	}
}

func TestVerifyDeniedPaths(t *testing.T) {
	t.Parallel()
	f := newFixture(t, mcpoauth.Config{})
	ctx := context.Background()
	_, body := f.exchangeBody(f.issueCode(mcpoauth.Approval{Subject: "u"}), nil)
	tok := body["access_token"].(string)
	if _, err := f.srv.Verify(ctx, ""); !errors.Is(err, mcpoauth.ErrDenied) {
		t.Fatal(err)
	}
	if _, err := f.srv.Verify(ctx, "unknown"); !errors.Is(err, mcpoauth.ErrDenied) {
		t.Fatal(err)
	}
	// Token audience: a record for another resource is denied even if stored.
	for k, c := range f.store.tokens {
		c.Resource = "https://other.example.test/mcp"
		f.store.tokens[k] = c
	}
	if _, err := f.srv.Verify(ctx, tok); !errors.Is(err, mcpoauth.ErrDenied) {
		t.Fatalf("audience: %v", err)
	}
	for k, c := range f.store.tokens {
		c.Resource, c.Scopes = resource, []string{"read", "admin"}
		f.store.tokens[k] = c
	}
	if _, err := f.srv.Verify(ctx, tok); !errors.Is(err, mcpoauth.ErrDenied) {
		t.Fatalf("scope outside ceiling: %v", err)
	}
	for k, c := range f.store.tokens {
		c.Scopes = []string{"read"}
		f.store.tokens[k] = c
	}
	if _, err := f.srv.Verify(ctx, tok); err != nil {
		t.Fatal(err)
	}
	f.store.fail = errors.New("disk")
	if _, err := f.srv.Verify(ctx, tok); err == nil || errors.Is(err, mcpoauth.ErrDenied) {
		t.Fatalf("store failure must surface, got %v", err)
	}
	f.store.fail = nil
}

func TestRevocation(t *testing.T) {
	t.Parallel()
	f := newFixture(t, mcpoauth.Config{})
	ctx := context.Background()
	_, body := f.exchangeBody(f.issueCode(mcpoauth.Approval{Subject: "u"}), nil)
	tok := body["access_token"].(string)
	if rr := f.form("/oauth/revoke", url.Values{"token": {"unknown"}}); rr.Code != 200 || rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unknown token must be 200: %d", rr.Code)
	}
	if rr := f.form("/oauth/revoke", url.Values{"token": {tok}}); rr.Code != 200 {
		t.Fatal(rr.Code)
	}
	if _, err := f.srv.Verify(ctx, tok); !errors.Is(err, mcpoauth.ErrDenied) {
		t.Fatalf("revoked token verified: %v", err)
	}
	if rr := f.form("/oauth/revoke", url.Values{"token": {tok}}); rr.Code != 200 {
		t.Fatal("revoke must be idempotent")
	}
	if rr := f.form("/oauth/revoke", url.Values{}); rr.Code != 400 {
		t.Fatal(rr.Code)
	}
	if rr := f.do(httptest.NewRequest(http.MethodGet, "/oauth/revoke", nil)); rr.Code != 405 {
		t.Fatal(rr.Code)
	}
	f.store.fail = errors.New("disk")
	if rr := f.form("/oauth/revoke", url.Values{"token": {tok}}); rr.Code != 500 {
		t.Fatal("store failure must not be reported as success")
	}
	f.store.fail = nil
}

func TestRegistration(t *testing.T) {
	t.Parallel()
	f := newFixture(t, mcpoauth.Config{})
	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		return f.do(req)
	}
	rr := post(`{"client_name":"Agent","redirect_uris":["https://agent.example.test/cb"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","scope":"read","jwks_uri":"https://169.254.169.254/x","client_uri":"http://10.0.0.1/"}`)
	if rr.Code != 201 {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if _, ok := resp["client_secret"]; ok || resp["token_endpoint_auth_method"] != "none" {
		t.Fatalf("public client only: %s", rr.Body)
	}
	c, err := f.store.Client(context.Background(), resp["client_id"].(string))
	if err != nil || c.Name != "Agent" || !slices.Equal(c.RedirectURIs, []string{"https://agent.example.test/cb"}) {
		t.Fatalf("stored client: %+v %v", c, err)
	}
	bad := map[string]string{
		"no redirects":   `{"client_name":"x","redirect_uris":[]}`,
		"http redirect":  `{"redirect_uris":["http://agent.example.test/cb"]}`,
		"localhost":      `{"redirect_uris":["http://localhost:8080/cb"]}`,
		"loopback off":   `{"redirect_uris":["http://127.0.0.1:8080/cb"]}`,
		"custom scheme":  `{"redirect_uris":["myapp://cb"]}`,
		"userinfo":       `{"redirect_uris":["https://a@b.example.test/cb"]}`,
		"fragment":       `{"redirect_uris":["https://b.example.test/cb#f"]}`,
		"crlf":           `{"redirect_uris":["https://b.example.test/cb\r\nX"]}`,
		"duplicate":      `{"redirect_uris":["https://b.example.test/cb","https://b.example.test/cb"]}`,
		"too many":       `{"redirect_uris":[` + strings.Repeat(`"https://b.example.test/cb0",`, 10) + `"https://b.example.test/cb1"]}`,
		"long name":      `{"client_name":"` + strings.Repeat("n", 256) + `","redirect_uris":["https://b.example.test/cb"]}`,
		"control name":   `{"client_name":"a\u0000b","redirect_uris":["https://b.example.test/cb"]}`,
		"secret auth":    `{"redirect_uris":["https://b.example.test/cb"],"token_endpoint_auth_method":"client_secret_basic"}`,
		"device grant":   `{"redirect_uris":["https://b.example.test/cb"],"grant_types":["authorization_code","urn:ietf:params:oauth:grant-type:device_code"]}`,
		"implicit":       `{"redirect_uris":["https://b.example.test/cb"],"response_types":["token"]}`,
		"scope outside":  `{"redirect_uris":["https://b.example.test/cb"],"scope":"admin"}`,
		"not json":       `{`,
		"wrong shape":    `[]`,
		"oversized body": `{"client_name":"` + strings.Repeat("n", 17<<10) + `"}`,
		"oversized uri":  `{"redirect_uris":["https://b.example.test/` + strings.Repeat("p", 2100) + `"]}`,
	}
	for name, body := range bad {
		t.Run(name, func(t *testing.T) {
			before := len(f.store.clients)
			rr := post(body)
			if rr.Code != 400 {
				t.Fatalf("want 400, got %d %s", rr.Code, rr.Body)
			}
			if len(f.store.clients) != before {
				t.Fatal("rejected registration must persist nothing")
			}
		})
	}
	if rr := f.do(httptest.NewRequest(http.MethodGet, "/oauth/register", nil)); rr.Code != 405 {
		t.Fatal(rr.Code)
	}
}

func TestLoopbackRedirects(t *testing.T) {
	t.Parallel()
	f := newFixture(t, mcpoauth.Config{Issuer: issuer, Resource: resource, Scopes: []string{"read"}, AllowLoopbackRedirects: true})
	post := func(uri string) int {
		req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(`{"redirect_uris":["`+uri+`"]}`))
		return f.do(req).Code
	}
	for uri, want := range map[string]int{
		"http://127.0.0.1:8080/cb":   201,
		"http://127.0.0.1/cb":        201,
		"http://[::1]:9000/cb":       201,
		"http://127.1.2.3:8080/cb":   201,
		"http://localhost:8080/cb":   400,
		"http://127.0.0.1.evil.test": 400,
		"http://10.0.0.1:8080/cb":    400,
		"http://[::ffff:7f00:1]/cb":  201,
		"http://[fe80::1]/cb":        400,
		"http://a@127.0.0.1/cb":      400,
	} {
		if got := post(uri); got != want {
			t.Errorf("%s: want %d got %d", uri, want, got)
		}
	}
	// Exact match includes the port: a different port is not the registered URI.
	c := mcpoauth.Client{ID: "local", Name: "L", RedirectURIs: []string{"http://127.0.0.1:8080/cb"}}
	_ = f.store.CreateClient(context.Background(), c)
	f.client = c
	if rr := f.authorize(map[string]string{"redirect_uri": "http://127.0.0.1:8080/cb", "scope": ""}); rr.Code != 200 {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	if rr := f.authorize(map[string]string{"redirect_uri": "http://127.0.0.1:8081/cb", "scope": ""}); rr.Code != 400 {
		t.Fatal(rr.Code)
	}
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func mustDigest(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}
