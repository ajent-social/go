package mcpoauth_test

import (
	"context"
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

// issueTokens runs the full code flow and returns access and refresh tokens.
func (f *fixture) issueTokens(a mcpoauth.Approval) (access, refresh string) {
	f.t.Helper()
	rr, body := f.exchangeBody(f.issueCode(a), nil)
	if rr.Code != 200 {
		f.t.Fatalf("exchange: %d %s", rr.Code, rr.Body)
	}
	access, _ = body["access_token"].(string)
	refresh, _ = body["refresh_token"].(string)
	return access, refresh
}

func (f *fixture) refreshForm(rt string, over map[string]string) url.Values {
	v := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {f.client.ID}}
	for k, val := range over {
		if val == "" {
			v.Del(k)
		} else {
			v.Set(k, val)
		}
	}
	return v
}

func (f *fixture) refresh(rt string, over map[string]string) (*httptest.ResponseRecorder, map[string]any) {
	rr := f.form("/oauth/token", f.refreshForm(rt, over))
	body := map[string]any{}
	_ = jsonUnmarshal(rr.Body.Bytes(), &body)
	return rr, body
}

func (f *fixture) grantOf(access string) mcpoauth.GrantRecord {
	f.t.Helper()
	id, err := f.srv.Verify(context.Background(), access)
	if err != nil {
		f.t.Fatalf("verify: %v", err)
	}
	f.store.mu.Lock()
	defer f.store.mu.Unlock()
	return f.store.grants[id.GrantID]
}

func TestRefreshRotationKeepsGrantAndBindings(t *testing.T) {
	t.Parallel()
	f := newFixture(t, mcpoauth.Config{})
	ctx := context.Background()
	access1, refresh1 := f.issueTokens(mcpoauth.Approval{Subject: "user-1", Binding: "acct-9", Scopes: []string{"read"}})
	id1, err := f.srv.Verify(ctx, access1)
	if err != nil {
		t.Fatal(err)
	}
	rr, body := f.refresh(refresh1, nil)
	if rr.Code != 200 || rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("refresh: %d %s", rr.Code, rr.Body)
	}
	access2, refresh2 := body["access_token"].(string), body["refresh_token"].(string)
	if access2 == access1 || refresh2 == refresh1 || refresh2 == "" {
		t.Fatal("rotation must issue fresh secrets")
	}
	if body["scope"] != "read" || body["expires_in"].(float64) != 3600 || body["token_type"] != "bearer" {
		t.Fatalf("body: %s", rr.Body)
	}
	id2, err := f.srv.Verify(ctx, access2)
	if err != nil {
		t.Fatal(err)
	}
	if id2.GrantID != id1.GrantID || id2.Subject != "user-1" || id2.Binding != "acct-9" || id2.ClientID != f.client.ID || !slices.Equal(id2.Scopes, []string{"read"}) {
		t.Fatalf("identity changed across refresh: %+v vs %+v", id1, id2)
	}
	// The previous access token stays valid until its own expiry.
	if _, err := f.srv.Verify(ctx, access1); err != nil {
		t.Fatalf("previous access token: %v", err)
	}
	// Old refresh record marked used and linked; new one is generation 2.
	f.store.mu.Lock()
	var gens []int
	for _, r := range f.store.refresh {
		gens = append(gens, r.Generation)
		if r.Generation == 1 && (r.UsedAt.IsZero() || r.ReplacedBy == "") {
			t.Errorf("old refresh not marked used: %+v", r)
		}
		if r.Generation == 2 && (!r.UsedAt.IsZero() || r.GrantID != id1.GrantID) {
			t.Errorf("new refresh wrong: %+v", r)
		}
	}
	f.store.mu.Unlock()
	slices.Sort(gens)
	if !slices.Equal(gens, []int{1, 2}) {
		t.Fatalf("generations: %v", gens)
	}
	// Raw secrets never appear as keys.
	f.store.mu.Lock()
	for k := range f.store.refresh {
		if strings.Contains(k, refresh1) || strings.Contains(k, refresh2) {
			t.Fatal("raw refresh token persisted")
		}
	}
	f.store.mu.Unlock()
}

func TestRefreshReuseRevokesWholeFamily(t *testing.T) {
	t.Parallel()
	f := newFixture(t, mcpoauth.Config{})
	ctx := context.Background()
	access1, refresh1 := f.issueTokens(mcpoauth.Approval{Subject: "u"})
	rr, body := f.refresh(refresh1, nil)
	if rr.Code != 200 {
		t.Fatal(rr.Body)
	}
	access2, refresh2 := body["access_token"].(string), body["refresh_token"].(string)
	rr, body = f.refresh(refresh2, nil)
	if rr.Code != 200 {
		t.Fatal(rr.Body)
	}
	access3, refresh3 := body["access_token"].(string), body["refresh_token"].(string)
	for _, a := range []string{access1, access2, access3} {
		if _, err := f.srv.Verify(ctx, a); err != nil {
			t.Fatalf("pre-reuse verify: %v", err)
		}
	}
	// Replay an old generation: whole family dies, including the newest
	// unused refresh token and every access token.
	oauthErr(t, f.form("/oauth/token", f.refreshForm(refresh1, nil)), 400, "invalid_grant")
	for _, a := range []string{access1, access2, access3} {
		if _, err := f.srv.Verify(ctx, a); !errors.Is(err, mcpoauth.ErrDenied) {
			t.Fatalf("access token survived family revocation: %v", err)
		}
	}
	oauthErr(t, f.form("/oauth/token", f.refreshForm(refresh3, nil)), 400, "invalid_grant")
	oauthErr(t, f.form("/oauth/token", f.refreshForm(refresh2, nil)), 400, "invalid_grant")
	f.store.mu.Lock()
	for _, g := range f.store.grants {
		if g.RevokedAt.IsZero() {
			t.Fatal("grant not revoked")
		}
	}
	f.store.mu.Unlock()
}

func TestRefreshWrongClientNeverIssuesAndDoesNotRevoke(t *testing.T) {
	t.Parallel()
	f := newFixture(t, mcpoauth.Config{})
	ctx := context.Background()
	other := mcpoauth.Client{ID: "client-2", Name: "Other", RedirectURIs: []string{redirect}, CreatedAt: time.Now()}
	if err := f.store.CreateClient(ctx, other); err != nil {
		t.Fatal(err)
	}
	access1, refresh1 := f.issueTokens(mcpoauth.Approval{Subject: "u"})
	// Unused token, wrong client: denied, still unused.
	oauthErr(t, f.form("/oauth/token", f.refreshForm(refresh1, map[string]string{"client_id": "client-2"})), 400, "invalid_grant")
	oauthErr(t, f.form("/oauth/token", f.refreshForm(refresh1, map[string]string{"client_id": "nobody"})), 400, "invalid_grant")
	oauthErr(t, f.form("/oauth/token", f.refreshForm(refresh1, map[string]string{"client_id": ""})), 400, "invalid_request")
	rr, body := f.refresh(refresh1, nil)
	if rr.Code != 200 {
		t.Fatalf("legitimate client must still be able to rotate: %s", rr.Body)
	}
	refresh2 := body["refresh_token"].(string)
	// Used token, wrong client: denied without revoking the legitimate family.
	oauthErr(t, f.form("/oauth/token", f.refreshForm(refresh1, map[string]string{"client_id": "client-2"})), 400, "invalid_grant")
	if _, err := f.srv.Verify(ctx, access1); err != nil {
		t.Fatalf("wrong-client guess revoked a legitimate family: %v", err)
	}
	if rr, _ := f.refresh(refresh2, nil); rr.Code != 200 {
		t.Fatalf("family should be intact: %s", rr.Body)
	}
	if f.store.rotations != 2 {
		t.Fatalf("rotations: %d", f.store.rotations)
	}
}

func TestRefreshNeverWidensScopeOrLifetime(t *testing.T) {
	t.Parallel()
	f := newFixture(t, mcpoauth.Config{RefreshTTL: 2 * time.Hour})
	ctx := context.Background()
	_, refresh1 := f.issueTokens(mcpoauth.Approval{Subject: "u", Scopes: []string{"read"}})
	// Widening beyond the grant is rejected and does not consume the token.
	oauthErr(t, f.form("/oauth/token", f.refreshForm(refresh1, map[string]string{"scope": "read write"})), 400, "invalid_grant")
	oauthErr(t, f.form("/oauth/token", f.refreshForm(refresh1, map[string]string{"scope": "write"})), 400, "invalid_grant")
	oauthErr(t, f.form("/oauth/token", f.refreshForm(refresh1, map[string]string{"scope": "read read"})), 400, "invalid_grant")
	oauthErr(t, f.form("/oauth/token", f.refreshForm(refresh1, map[string]string{"resource": "https://other.example.test/mcp"})), 400, "invalid_target")
	// Empty scope keeps the grant's scopes; the grant record is unchanged.
	rr, body := f.refresh(refresh1, nil)
	if rr.Code != 200 || body["scope"] != "read" {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	access2 := body["access_token"].(string)
	g := f.grantOf(access2)
	if !slices.Equal(g.Scopes, []string{"read"}) {
		t.Fatalf("grant scopes changed: %v", g.Scopes)
	}
	// Access token expiry is capped by the grant's absolute lifetime and the
	// refresh token inherits it exactly.
	f.store.mu.Lock()
	for _, tk := range f.store.tokens {
		if tk.ExpiresAt.After(g.ExpiresAt) {
			t.Fatal("access token outlives grant")
		}
	}
	for _, r := range f.store.refresh {
		if !r.ExpiresAt.Equal(g.ExpiresAt) {
			t.Fatal("refresh token expiry must equal the grant's absolute expiry")
		}
	}
	// Move the grant close to expiry: the next access token is truncated.
	soon := time.Now().Add(90 * time.Second)
	for k, gr := range f.store.grants {
		gr.ExpiresAt = soon
		f.store.grants[k] = gr
	}
	f.store.mu.Unlock()
	rr, body = f.refresh(body["refresh_token"].(string), nil)
	if rr.Code != 200 || body["expires_in"].(float64) > 90 {
		t.Fatalf("expiry not capped: %d %s", rr.Code, rr.Body)
	}
	if _, err := f.srv.Verify(ctx, body["access_token"].(string)); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshExpiredFamilyAndRevocation(t *testing.T) {
	t.Parallel()
	f := newFixture(t, mcpoauth.Config{})
	ctx := context.Background()
	access, refresh := f.issueTokens(mcpoauth.Approval{Subject: "u"})
	f.store.expireAll(time.Now().Add(-time.Second))
	oauthErr(t, f.form("/oauth/token", f.refreshForm(refresh, nil)), 400, "invalid_grant")
	if _, err := f.srv.Verify(ctx, access); !errors.Is(err, mcpoauth.ErrDenied) {
		t.Fatal(err)
	}
	if f.store.rotations != 0 {
		t.Fatal("expired token must not rotate")
	}

	// Revoking by refresh token kills the access token and vice versa.
	access, refresh = f.issueTokens(mcpoauth.Approval{Subject: "u"})
	if rr := f.form("/oauth/revoke", url.Values{"token": {refresh}, "token_type_hint": {"refresh_token"}}); rr.Code != 200 {
		t.Fatal(rr.Code)
	}
	if _, err := f.srv.Verify(ctx, access); !errors.Is(err, mcpoauth.ErrDenied) {
		t.Fatalf("access token survived refresh revocation: %v", err)
	}
	oauthErr(t, f.form("/oauth/token", f.refreshForm(refresh, nil)), 400, "invalid_grant")

	access, refresh = f.issueTokens(mcpoauth.Approval{Subject: "u"})
	if err := f.srv.Revoke(ctx, access); err != nil {
		t.Fatal(err)
	}
	oauthErr(t, f.form("/oauth/token", f.refreshForm(refresh, nil)), 400, "invalid_grant")
	if f.store.rotations != 0 {
		t.Fatal("revoked family must not rotate")
	}
	// Unknown refresh token; malformed forms.
	oauthErr(t, f.form("/oauth/token", f.refreshForm("nope", nil)), 400, "invalid_grant")
	oauthErr(t, f.form("/oauth/token", f.refreshForm(refresh, map[string]string{"refresh_token": ""})), 400, "invalid_request")
	dup := f.refreshForm(refresh, nil)
	dup["refresh_token"] = append(dup["refresh_token"], refresh)
	oauthErr(t, f.form("/oauth/token", dup), 400, "invalid_request")
	// Store failure surfaces as 500, never as issuance.
	access, refresh = f.issueTokens(mcpoauth.Approval{Subject: "u"})
	f.store.fail = errors.New("disk")
	oauthErr(t, f.form("/oauth/token", f.refreshForm(refresh, nil)), 500, "server_error")
	f.store.fail = nil
	if _, err := f.srv.Verify(ctx, access); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyChecksGrantEveryTime(t *testing.T) {
	t.Parallel()
	f := newFixture(t, mcpoauth.Config{})
	ctx := context.Background()
	access, _ := f.issueTokens(mcpoauth.Approval{Subject: "u", Binding: "b"})
	id, err := f.srv.Verify(ctx, access)
	if err != nil {
		t.Fatal(err)
	}
	mutate := func(fn func(*mcpoauth.GrantRecord)) {
		f.store.mu.Lock()
		g := f.store.grants[id.GrantID]
		fn(&g)
		f.store.grants[id.GrantID] = g
		f.store.mu.Unlock()
	}
	deny := func(what string) {
		t.Helper()
		if _, err := f.srv.Verify(ctx, access); !errors.Is(err, mcpoauth.ErrDenied) {
			t.Fatalf("%s: want denied, got %v", what, err)
		}
	}
	// Grant missing: fail closed.
	f.store.mu.Lock()
	saved := f.store.grants[id.GrantID]
	delete(f.store.grants, id.GrantID)
	f.store.mu.Unlock()
	deny("missing grant")
	f.store.mu.Lock()
	f.store.grants[id.GrantID] = saved
	f.store.mu.Unlock()
	// Grant/token binding mismatch: fail closed.
	mutate(func(g *mcpoauth.GrantRecord) { g.Binding = "other" })
	deny("binding mismatch")
	mutate(func(g *mcpoauth.GrantRecord) { g.Binding = "b"; g.Subject = "someone-else" })
	deny("subject mismatch")
	mutate(func(g *mcpoauth.GrantRecord) { g.Subject = "u"; g.Scopes = []string{"admin"} })
	deny("grant scope outside ceiling")
	mutate(func(g *mcpoauth.GrantRecord) { g.Scopes = []string{"read", "write"}; g.RevokedAt = time.Now() })
	deny("revoked")
	mutate(func(g *mcpoauth.GrantRecord) { g.RevokedAt = time.Time{} })
	if _, err := f.srv.Verify(ctx, access); err != nil {
		t.Fatal(err)
	}
	// Grant store failure is an error, not a denial and not a success.
	f.store.fail = errors.New("disk")
	if _, err := f.srv.Verify(ctx, access); err == nil || errors.Is(err, mcpoauth.ErrDenied) {
		t.Fatal(err)
	}
	f.store.fail = nil
}

func TestConcurrentRefreshExactlyOneWinsThenFamilyRevoked(t *testing.T) {
	t.Parallel()
	f := newFixture(t, mcpoauth.Config{})
	ctx := context.Background()
	access, refresh := f.issueTokens(mcpoauth.Approval{Subject: "u"})
	const n = 32
	var wg sync.WaitGroup
	codes := make(chan int, n)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rr := f.form("/oauth/token", f.refreshForm(refresh, nil))
			codes <- rr.Code
		}()
	}
	wg.Wait()
	close(codes)
	ok := 0
	for c := range codes {
		if c == 200 {
			ok++
		}
	}
	if ok != 1 || f.store.rotations != 1 {
		t.Fatalf("want exactly one rotation, got %d successes, %d rotations", ok, f.store.rotations)
	}
	// The losers were reuse: the family is revoked, including the winner's
	// new tokens. This is the documented cost of concurrent refresh.
	if _, err := f.srv.Verify(ctx, access); !errors.Is(err, mcpoauth.ErrDenied) {
		t.Fatalf("family should be revoked after concurrent reuse: %v", err)
	}
}

func TestIssuancePolicyDeniesAtomically(t *testing.T) {
	t.Parallel()
	f := newFixture(t, mcpoauth.Config{})
	ctx := context.Background()
	_, refresh := f.issueTokens(mcpoauth.Approval{Subject: "u", Binding: "acct.1"})
	f.store.mu.Lock()
	f.store.policy = func(g mcpoauth.GrantRecord) error {
		if g.Binding != "acct.2" {
			return mcpoauth.ErrDenied
		}
		return nil
	}
	f.store.mu.Unlock()
	// Rotation denied by live policy: nothing written, token still unused.
	oauthErr(t, f.form("/oauth/token", f.refreshForm(refresh, nil)), 400, "invalid_grant")
	f.store.mu.Lock()
	for _, r := range f.store.refresh {
		if !r.UsedAt.IsZero() {
			t.Fatal("policy denial must not consume the refresh token")
		}
	}
	tokens := len(f.store.tokens)
	f.store.mu.Unlock()
	// Initial issuance denied by live policy: no grant, no tokens.
	code := f.issueCode(mcpoauth.Approval{Subject: "u", Binding: "acct.1"})
	oauthErr(t, f.exchange(code, nil), 400, "invalid_grant")
	f.store.mu.Lock()
	if len(f.store.tokens) != tokens || len(f.store.grants) != 1 {
		t.Fatal("denied issuance must write nothing")
	}
	f.store.policy = nil
	f.store.mu.Unlock()
	if rr, _ := f.refresh(refresh, nil); rr.Code != 200 {
		t.Fatalf("after policy clears, the unused token rotates: %s", rr.Body)
	}
	_ = ctx
}

func TestDisableRefresh(t *testing.T) {
	t.Parallel()
	f := newFixture(t, mcpoauth.Config{Issuer: issuer, Resource: resource, Scopes: []string{"read"}, DisableRefresh: true})
	ctx := context.Background()
	rr, body := f.exchangeBody(f.issueCode(mcpoauth.Approval{Subject: "u"}), nil)
	if rr.Code != 200 {
		t.Fatal(rr.Body)
	}
	if _, ok := body["refresh_token"]; ok {
		t.Fatal("refresh token issued while disabled")
	}
	access := body["access_token"].(string)
	id, err := f.srv.Verify(ctx, access)
	if err != nil || id.GrantID == "" {
		t.Fatalf("grant id must exist without refresh: %+v %v", id, err)
	}
	g := f.grantOf(access)
	if !g.ExpiresAt.Equal(f.store.tokens[mustDigest(access)].ExpiresAt) {
		t.Fatal("grant should expire with its single access token")
	}
	oauthErr(t, f.form("/oauth/token", f.refreshForm("anything", nil)), 400, "unsupported_grant_type")
	// Registration asking for refresh_token is rejected while disabled and
	// accepted when enabled.
	post := func(fx *fixture, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		return fx.do(req)
	}
	reg := `{"redirect_uris":["https://b.example.test/cb"],"grant_types":["authorization_code","refresh_token"]}`
	if rr := post(f, reg); rr.Code != 400 {
		t.Fatalf("disabled server must reject refresh registration: %d %s", rr.Code, rr.Body)
	}
	on := newFixture(t, mcpoauth.Config{})
	if rr := post(on, reg); rr.Code != 201 || !strings.Contains(rr.Body.String(), `"refresh_token"`) {
		t.Fatalf("enabled server must accept refresh registration: %d %s", rr.Code, rr.Body)
	}
	// Config bounds.
	if _, err := mcpoauth.New(mcpoauth.Config{Issuer: issuer, Resource: resource, Scopes: []string{"read"}, RefreshTTL: 100 * 24 * time.Hour}, newMemStore()); err == nil {
		t.Fatal("refresh ttl over max accepted")
	}
	if _, err := mcpoauth.New(mcpoauth.Config{Issuer: issuer, Resource: resource, Scopes: []string{"read"}, RefreshTTL: time.Minute, AccessTokenTTL: time.Hour}, newMemStore()); err == nil {
		t.Fatal("refresh ttl shorter than access ttl accepted")
	}
}
