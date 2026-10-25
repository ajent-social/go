package mcpoauth

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
)

const cimdID = "https://client.example.com/oauth.json"
const cimdRedirect = "https://client.example.com/callback"

func cimdDocument() string {
	return `{"client_id":"` + cimdID + `","client_name":"Local fixture","redirect_uris":["` + cimdRedirect + `"],"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"],"response_types":["code"]}`
}

func TestCIMDAddressPolicy(t *testing.T) {
	for _, raw := range []string{"0.0.0.0", "0.1.2.3", "10.1.2.3", "100.64.0.1", "100.127.255.254", "127.0.0.1", "169.254.1.1", "172.31.1.1", "192.0.0.9", "192.0.2.1", "192.168.1.1", "192.88.99.1", "192.31.196.1", "192.52.193.1", "192.175.48.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "255.255.255.255", "::", "::1", "::ffff:8.8.8.8", "::ffff:127.0.0.1", "fc00::1", "fd00::1", "fe80::1", "ff02::1", "64:ff9b::808:808", "100::1", "2001::1", "2001:2::1", "2001:db8::1", "2002:808:808::1", "3fff::1", "2620:4f:8000::1", "fe80::1%eth0"} {
		if publicCIMDIP(netip.MustParseAddr(raw)) {
			t.Errorf("accepted special address %s", raw)
		}
	}
	for _, raw := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "2001:4860:4860::8888"} {
		if !publicCIMDIP(netip.MustParseAddr(raw)) {
			t.Errorf("rejected public address %s", raw)
		}
	}
}

func TestCIMDCanonicalURL(t *testing.T) {
	for _, id := range []string{"http://client.example.com/a", "https://client.example.com", "https://client.example.com/a?x=1", "https://client.example.com/a?", "https://client.example.com/a#", "https://client.example.com/a#f", "https://user@client.example.com/a", "https://client.example.com:444/a", "https://CLIENT.example.com/a", "https://client.example.com./a", "https://client.example.com/%61", "https://127.0.0.1/a", "https://[::ffff:8.8.8.8]/a", "https://localhost/a", "https://client.example.com/a/../b"} {
		if _, err := cimdURL(id); err == nil {
			t.Errorf("accepted %q", id)
		}
	}
	for _, id := range []string{cimdID, "https://client.example.com:443/a", "https://[2606:4700:4700::1111]/a"} {
		if _, err := cimdURL(id); err != nil {
			t.Errorf("rejected %q", id)
		}
	}
}

func TestCIMDDocumentValidation(t *testing.T) {
	s := &Server{cfg: Config{}}
	good := cimdDocument()
	if _, err := s.parseCIMD(cimdID, []byte(good)); err != nil {
		t.Fatal(err)
	}
	cases := []string{
		strings.Replace(good, `"client_id":"`+cimdID+`"`, `"client_id":"https://other.example.com/a"`, 1),
		strings.Replace(good, `"client_name":"Local fixture"`, `"client_name":""`, 1),
		strings.Replace(good, `"none"`, `"client_secret_post"`, 1),
		strings.Replace(good, `"code"`, `"token"`, 1),
		strings.Replace(good, `"authorization_code"`, `"password"`, 1),
		strings.Replace(good, `"redirect_uris":["`+cimdRedirect+`"]`, `"redirect_uris":[]`, 1),
		strings.Replace(good, `"redirect_uris":["`+cimdRedirect+`"]`, `"redirect_uris":["https://user@client.example.com/callback"]`, 1),
		strings.Replace(good, `"client_name":"Local fixture"`, `"client_name":"`+strings.Repeat("a", maxClientName+1)+`"`, 1),
		strings.Replace(good, `"client_id":`, `"client_id":"`+cimdID+`","client_id":`, 1),
		strings.TrimSuffix(good, "}") + `,"error":null}`,
		strings.TrimSuffix(good, "}") + `,"extension":{"duplicate":1,"duplicate":2}}`,
		strings.TrimSuffix(good, "}") + `,"extension":` + strings.Repeat("[", 18) + `0` + strings.Repeat("]", 18) + `}`,
		strings.TrimSuffix(good, "}") + `,"CLIENT_ID":"` + cimdID + `"}`,
		good + ` {}`, `null`, `[]`, strings.Repeat(" ", maxCIMDBytes+1),
	}
	for i, body := range cases {
		if _, err := s.parseCIMD(cimdID, []byte(body)); err == nil {
			t.Errorf("accepted bad document %d", i)
		}
	}
	if _, err := s.parseCIMD(cimdID, []byte(strings.TrimSuffix(good, "}")+`,"extension":{"ok":[1,true]}}`)); err != nil {
		t.Fatal("safe extension rejected", err)
	}
}

// This store only implements operations exercised by the local CIMD flow.
// Embedding Store makes any unexpected operation fail loudly in the fixture.
type cimdStore struct {
	Store
	clients map[string]Client
	consent map[string]ConsentRecord
	codes   map[string]CodeRecord
	grants  map[string]GrantRecord
	tokens  map[string]TokenRecord
	refresh map[string]RefreshRecord
}

func newCIMDStore() *cimdStore {
	return &cimdStore{clients: map[string]Client{}, consent: map[string]ConsentRecord{}, codes: map[string]CodeRecord{}, grants: map[string]GrantRecord{}, tokens: map[string]TokenRecord{}, refresh: map[string]RefreshRecord{}}
}
func (m *cimdStore) Client(_ context.Context, id string) (Client, error) {
	v, ok := m.clients[id]
	if !ok {
		return v, ErrNotFound
	}
	return v, nil
}
func (m *cimdStore) CreateConsent(_ context.Context, v ConsentRecord) error {
	m.consent[v.ID] = v
	return nil
}
func (m *cimdStore) Consent(_ context.Context, id string) (ConsentRecord, error) {
	v, ok := m.consent[id]
	if !ok {
		return v, ErrNotFound
	}
	return v, nil
}
func (m *cimdStore) ConsumeConsent(ctx context.Context, id string) (ConsentRecord, error) {
	v, e := m.Consent(ctx, id)
	delete(m.consent, id)
	return v, e
}
func (m *cimdStore) CreateCode(_ context.Context, v CodeRecord) error { m.codes[v.ID] = v; return nil }
func (m *cimdStore) ConsumeCode(_ context.Context, id string) (CodeRecord, error) {
	v, ok := m.codes[id]
	delete(m.codes, id)
	if !ok {
		return v, ErrNotFound
	}
	return v, nil
}
func (m *cimdStore) CreateGrant(_ context.Context, v GrantIssue) error {
	m.grants[v.Grant.ID] = v.Grant
	m.tokens[v.Token.ID] = v.Token
	if v.Refresh != nil {
		m.refresh[v.Refresh.ID] = *v.Refresh
	}
	return nil
}
func (m *cimdStore) Token(_ context.Context, id string) (TokenRecord, error) {
	v, ok := m.tokens[id]
	if !ok {
		return v, ErrNotFound
	}
	return v, nil
}
func (m *cimdStore) Grant(_ context.Context, id string) (GrantRecord, error) {
	v, ok := m.grants[id]
	if !ok {
		return v, ErrNotFound
	}
	return v, nil
}

func localCIMD(t *testing.T, s *Server, handler http.Handler) {
	t.Helper()
	ts := httptest.NewTLSServer(handler)
	t.Cleanup(ts.Close)
	roots := x509.NewCertPool()
	roots.AddCert(ts.Certificate())
	s.cimd = &cimdFetcher{roots: roots, lookup: func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}, dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "8.8.8.8:443" {
			return nil, ErrDenied
		}
		return (&net.Dialer{}).DialContext(ctx, network, ts.Listener.Addr().String())
	}}
}

func TestCIMDFetchSafety(t *testing.T) {
	for _, answers := range [][]netip.Addr{nil, {netip.MustParseAddr("127.0.0.1")}, {netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.0.0.1")}, {netip.MustParseAddr("2606:4700:4700::1111"), netip.MustParseAddr("::ffff:8.8.8.8")}} {
		dialed := false
		s := &Server{cimd: &cimdFetcher{lookup: func(context.Context, string, string) ([]netip.Addr, error) { return answers, nil }, dial: func(context.Context, string, string) (net.Conn, error) { dialed = true; return nil, ErrDenied }}}
		if _, err := s.fetchCIMD(context.Background(), cimdID); err == nil || dialed {
			t.Fatal("unsafe DNS reached dial")
		}
	}
	for _, mode := range []string{"redirect", "status", "content-type", "oversize", "encoding", "tls-host"} {
		t.Run(mode, func(t *testing.T) {
			s := &Server{}
			localCIMD(t, s, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
					t.Error("credentials sent")
				}
				w.Header().Set("Content-Type", "application/json")
				switch mode {
				case "redirect":
					w.Header().Set("Location", "https://127.0.0.1/private")
					w.WriteHeader(302)
				case "status":
					w.WriteHeader(503)
				case "content-type":
					w.Header().Set("Content-Type", "text/html")
				case "oversize":
					_, _ = w.Write([]byte(strings.Repeat("x", maxCIMDBytes+1)))
				case "encoding":
					w.Header().Set("Content-Encoding", "gzip")
				}
				_, _ = w.Write([]byte(cimdDocument()))
			}))
			id := cimdID
			if mode == "tls-host" {
				id = "https://different.invalid/oauth.json"
			}
			if _, err := s.fetchCIMD(context.Background(), id); err == nil {
				t.Fatal("accepted unsafe response")
			}
		})
	}
}

func TestCIMDFullPKCEAndChangingRedirect(t *testing.T) {
	store := newCIMDStore()
	s, err := New(Config{Issuer: "https://mcp.example.com", Resource: "https://mcp.example.com/mcp", Scopes: []string{"read"}, EnableClientIDMetadataDocuments: true, DisableDynamicRegistration: true}, store)
	if err != nil {
		t.Fatal(err)
	}
	// A colliding store entry must never substitute for a URL document.
	store.clients[cimdID] = Client{ID: cimdID, RedirectURIs: []string{"https://attacker.example.com/cb"}}
	var mu sync.Mutex
	body := cimdDocument()
	lookups := 0
	localCIMD(t, s, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	baseLookup := s.cimd.lookup
	s.cimd.lookup = func(ctx context.Context, n, h string) ([]netip.Addr, error) { lookups++; return baseLookup(ctx, n, h) }
	v := strings.Repeat("v", 64)
	sum := sha256.Sum256([]byte(v))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	var handle string
	authorize := s.AuthorizeHandler(func(w http.ResponseWriter, r *http.Request, h string, _ ConsentRequest) {
		handle = h
		w.WriteHeader(200)
	})
	start := func(redirect string) *httptest.ResponseRecorder {
		t.Helper()
		handle = ""
		q := url.Values{"client_id": {cimdID}, "redirect_uri": {redirect}, "response_type": {"code"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}, "scope": {"read"}}
		rr := httptest.NewRecorder()
		authorize.ServeHTTP(rr, httptest.NewRequest("GET", "/authorize?"+q.Encode(), nil))
		return rr
	}
	if rr := start("https://attacker.example.com/cb"); rr.Code != 400 || rr.Header().Get("Location") != "" {
		t.Fatal("store collision trusted")
	}
	if rr := start(cimdRedirect); rr.Code != 200 || handle == "" {
		t.Fatalf("authorize: %d", rr.Code)
	}
	if _, err := s.Consent(context.Background(), handle); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	body = strings.Replace(cimdDocument(), cimdRedirect, "https://client.example.com/changed", 1)
	mu.Unlock()
	if _, err := s.Consent(context.Background(), handle); !errors.Is(err, ErrDenied) {
		t.Fatal("stale consent accepted", err)
	}
	if _, err := s.Approve(context.Background(), handle, Approval{Subject: "user", Binding: "workspace", Scopes: []string{"read"}}); !errors.Is(err, ErrDenied) {
		t.Fatal("stale approval accepted", err)
	}
	mu.Lock()
	body = cimdDocument()
	mu.Unlock()
	if rr := start(cimdRedirect); rr.Code != 200 {
		t.Fatal(rr.Code)
	}
	loc, err := s.Approve(context.Background(), handle, Approval{Subject: "user", Binding: "workspace", Scopes: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(loc)
	before := lookups
	// No metadata fetch is needed after the code is bound, even on DNS rebinding.
	s.cimd.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		lookups++
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	form := url.Values{"client_id": {cimdID}, "redirect_uri": {cimdRedirect}, "grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "code_verifier": {v}}
	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	s.TokenHandler().ServeHTTP(rr, req)
	if rr.Code != 200 || lookups != before {
		t.Fatalf("token exchange: %d, lookups %d -> %d", rr.Code, before, lookups)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	id, err := s.Verify(context.Background(), out.AccessToken)
	if err != nil || id.Binding != "workspace" || id.ClientID != cimdID {
		t.Fatal("issued identity", id, err)
	}
	if _, err := s.resolveClient(context.Background(), cimdID); !errors.Is(err, ErrDenied) {
		t.Fatal("rebound DNS accepted", err)
	}
	mu.Lock()
	body = `{"error":"invalid_client"}`
	mu.Unlock()
	s.cimd.lookup = baseLookup
	if rr := start(cimdRedirect); rr.Code != 400 || rr.Header().Get("Location") != "" {
		t.Fatal("bad metadata redirected")
	}
	// Original opaque collision was never overwritten with fetched metadata.
	if len(store.clients) != 1 || store.clients[cimdID].RedirectURIs[0] != "https://attacker.example.com/cb" {
		t.Fatal("CIMD persisted")
	}
}

func TestCIMDCheckedDestinationIsPinned(t *testing.T) {
	s := &Server{}
	calls := 0
	localCIMD(t, s, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "client.example.com" || r.TLS.ServerName != "client.example.com" {
			t.Error("original authority not preserved")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(cimdDocument()))
	}))
	original := s.cimd.lookup
	s.cimd.lookup = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		calls++
		if calls > 1 {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return original(ctx, network, host)
	}
	if _, err := s.fetchCIMD(context.Background(), cimdID); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("DNS re-resolved during dial", calls)
	}
	if _, err := s.fetchCIMD(context.Background(), cimdID); !errors.Is(err, ErrDenied) {
		t.Fatal("rebound address accepted", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.fetchCIMD(ctx, cimdID); err == nil {
		t.Fatal("canceled fetch succeeded")
	}
}
