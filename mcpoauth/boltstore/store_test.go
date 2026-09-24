package boltstore_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ajent-social/go/mcpoauth"
	"github.com/ajent-social/go/mcpoauth/boltstore"
)

func open(t *testing.T, path string) *boltstore.Store {
	t.Helper()
	s, err := boltstore.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestOpenRejectsSharedDirectory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := boltstore.Open(context.Background(), filepath.Join(dir, "oauth.db")); !errors.Is(err, mcpoauth.ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}
	if _, err := boltstore.Open(context.Background(), ""); !errors.Is(err, mcpoauth.ErrInvalid) {
		t.Fatal(err)
	}
}

func TestLifecycleSurvivesRestart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "oauth.db")
	now := time.Now().UTC().Truncate(time.Second)
	s := open(t, path)
	client := mcpoauth.Client{ID: "c1", Name: "C", RedirectURIs: []string{"https://c.example.test/cb"}, CreatedAt: now}
	if err := s.CreateClient(ctx, client); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateClient(ctx, client); !errors.Is(err, mcpoauth.ErrExists) {
		t.Fatalf("duplicate client: %v", err)
	}
	consent := mcpoauth.ConsentRecord{ID: "h1", ClientID: "c1", RedirectURI: client.RedirectURIs[0], CodeChallenge: "x", State: "s", Resource: "r", Scopes: []string{"read"}, CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	code := mcpoauth.CodeRecord{ID: "k1", ClientID: "c1", RedirectURI: client.RedirectURIs[0], CodeChallenge: "x", Subject: "u", Binding: "b", Resource: "r", Scopes: []string{"read"}, CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	grant := mcpoauth.GrantRecord{ID: "g1", ClientID: "c1", Subject: "u", Binding: "b", Resource: "r", Scopes: []string{"read"}, CreatedAt: now, ExpiresAt: now.Add(48 * time.Hour)}
	token := mcpoauth.TokenRecord{ID: "t1", GrantID: "g1", ClientID: "c1", Subject: "u", Binding: "b", Resource: "r", Scopes: []string{"read"}, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	refresh := mcpoauth.RefreshRecord{ID: "r1", GrantID: "g1", ClientID: "c1", Generation: 1, CreatedAt: now, ExpiresAt: grant.ExpiresAt}
	issue := mcpoauth.GrantIssue{Grant: grant, Token: token, Refresh: &refresh}
	for _, err := range []error{s.CreateConsent(ctx, consent), s.CreateCode(ctx, code), s.CreateGrant(ctx, issue)} {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CreateGrant(ctx, issue); !errors.Is(err, mcpoauth.ErrExists) {
		t.Fatal(err)
	}
	// A collision on any member rolls the whole issue back.
	partial := mcpoauth.GrantIssue{Grant: grant, Token: token, Refresh: &refresh}
	partial.Grant.ID, partial.Token.GrantID, partial.Refresh.GrantID = "g2", "g2", "g2"
	partial.Token.ID = "t2"
	if err := s.CreateGrant(ctx, partial); !errors.Is(err, mcpoauth.ErrExists) {
		t.Fatalf("refresh collision: %v", err)
	}
	if _, err := s.Grant(ctx, "g2"); !errors.Is(err, mcpoauth.ErrNotFound) {
		t.Fatal("partial grant persisted")
	}
	if _, err := s.Token(ctx, "t2"); !errors.Is(err, mcpoauth.ErrNotFound) {
		t.Fatal("partial token persisted")
	}
	mismatch := issue
	mismatch.Grant.ID = "g3"
	if err := s.CreateGrant(ctx, mismatch); !errors.Is(err, mcpoauth.ErrInvalid) {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Client(ctx, "c1"); err == nil {
		t.Fatal("closed store must fail")
	}

	// Restart.
	s = open(t, path)
	if got, err := s.Client(ctx, "c1"); err != nil || got.Name != "C" || got.RedirectURIs[0] != client.RedirectURIs[0] {
		t.Fatalf("client after restart: %+v %v", got, err)
	}
	if got, err := s.Consent(ctx, "h1"); err != nil || got.CodeChallenge != "x" || !got.ExpiresAt.Equal(consent.ExpiresAt) {
		t.Fatalf("consent after restart: %+v %v", got, err)
	}
	if got, err := s.ConsumeConsent(ctx, "h1"); err != nil || got.State != "s" {
		t.Fatalf("consume consent: %v", err)
	}
	if _, err := s.ConsumeConsent(ctx, "h1"); !errors.Is(err, mcpoauth.ErrNotFound) {
		t.Fatalf("second consume: %v", err)
	}
	if _, err := s.Consent(ctx, "h1"); !errors.Is(err, mcpoauth.ErrNotFound) {
		t.Fatal(err)
	}
	if got, err := s.ConsumeCode(ctx, "k1"); err != nil || got.Subject != "u" || got.Binding != "b" {
		t.Fatalf("consume code: %+v %v", got, err)
	}
	if _, err := s.ConsumeCode(ctx, "k1"); !errors.Is(err, mcpoauth.ErrNotFound) {
		t.Fatal(err)
	}
	if got, err := s.Token(ctx, "t1"); err != nil || got.GrantID != "g1" {
		t.Fatalf("token: %+v %v", got, err)
	}
	if got, err := s.Refresh(ctx, "r1"); err != nil || !got.UsedAt.IsZero() || got.Generation != 1 {
		t.Fatalf("refresh: %+v %v", got, err)
	}
	// Rotate, then restart, then verify the rotation is durable.
	rot := mcpoauth.RefreshRotation{RefreshID: "r1", At: now.Add(time.Minute),
		Token:   mcpoauth.TokenRecord{ID: "t2", GrantID: "g1", ClientID: "c1", Subject: "u", Binding: "b", Resource: "r", Scopes: []string{"read"}, CreatedAt: now, ExpiresAt: now.Add(2 * time.Hour)},
		Refresh: mcpoauth.RefreshRecord{ID: "r2", GrantID: "g1", ClientID: "c1", Generation: 2, CreatedAt: now, ExpiresAt: grant.ExpiresAt}}
	if err := s.RotateRefresh(ctx, rot); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = open(t, path)
	if got, err := s.Refresh(ctx, "r1"); err != nil || !got.UsedAt.Equal(rot.At) || got.ReplacedBy != "r2" {
		t.Fatalf("rotation not durable: %+v %v", got, err)
	}
	if got, err := s.Refresh(ctx, "r2"); err != nil || !got.UsedAt.IsZero() {
		t.Fatalf("new refresh: %+v %v", got, err)
	}
	if _, err := s.Token(ctx, "t2"); err != nil {
		t.Fatal(err)
	}
	// Reuse: family revoked and the write commits despite the error.
	reuse := rot
	reuse.Token.ID, reuse.Refresh.ID, reuse.At = "t3", "r3", now.Add(2*time.Minute)
	if err := s.RotateRefresh(ctx, reuse); !errors.Is(err, mcpoauth.ErrReused) {
		t.Fatalf("reuse: %v", err)
	}
	if _, err := s.Token(ctx, "t3"); !errors.Is(err, mcpoauth.ErrNotFound) {
		t.Fatal("reuse must not issue")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = open(t, path)
	if got, err := s.Grant(ctx, "g1"); err != nil || !got.RevokedAt.Equal(reuse.At) || got.Subject != "u" {
		t.Fatalf("family revocation not durable: %+v %v", got, err)
	}
	// Revoked grant: the still-unused r2 cannot rotate; ErrReused on r1 stays idempotent.
	next := mcpoauth.RefreshRotation{RefreshID: "r2", At: now.Add(3 * time.Minute), Token: reuse.Token, Refresh: reuse.Refresh}
	if err := s.RotateRefresh(ctx, next); !errors.Is(err, mcpoauth.ErrDenied) {
		t.Fatalf("revoked grant rotated: %v", err)
	}
	if err := s.RotateRefresh(ctx, reuse); !errors.Is(err, mcpoauth.ErrReused) {
		t.Fatal(err)
	}
	if got, _ := s.Grant(ctx, "g1"); !got.RevokedAt.Equal(reuse.At) {
		t.Fatal("RevokedAt must not move on repeated reuse")
	}
	if err := s.RevokeGrant(ctx, "g1", now.Add(time.Hour)); err != nil {
		t.Fatal("revoke must be idempotent")
	}
	if err := s.RevokeGrant(ctx, "missing", now); !errors.Is(err, mcpoauth.ErrNotFound) {
		t.Fatal(err)
	}
	if err := s.RevokeGrant(ctx, "g1", time.Time{}); !errors.Is(err, mcpoauth.ErrInvalid) {
		t.Fatal(err)
	}
	if err := s.RotateRefresh(ctx, mcpoauth.RefreshRotation{RefreshID: "nope", At: now, Token: reuse.Token, Refresh: reuse.Refresh}); !errors.Is(err, mcpoauth.ErrNotFound) {
		t.Fatal(err)
	}
	wrong := next
	wrong.RefreshID, wrong.Token.GrantID = "r2", "other"
	if err := s.RotateRefresh(ctx, wrong); errors.Is(err, nil) {
		t.Fatal("grant mismatch must fail")
	}
	// Sweep tokens first (2 tokens expire within 2h; grant and refresh live 48h).
	n, err := s.Sweep(ctx, now.Add(3*time.Hour))
	if err != nil || n != 2 {
		t.Fatalf("sweep: %d %v", n, err)
	}
	if _, err := s.Token(ctx, "t1"); !errors.Is(err, mcpoauth.ErrNotFound) {
		t.Fatal("swept token still present")
	}
	if _, err := s.Grant(ctx, "g1"); err != nil {
		t.Fatal("grant swept before expiry")
	}
	if n, err = s.Sweep(ctx, now.Add(72*time.Hour)); err != nil || n != 3 {
		t.Fatalf("sweep grant+refresh: %d %v", n, err)
	}
	if _, err := s.Grant(ctx, "g1"); !errors.Is(err, mcpoauth.ErrNotFound) {
		t.Fatal("grant not swept")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.Client(cancelled, "c1"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestConcurrentConsumeExactlyOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s := open(t, filepath.Join(dir, "oauth.db"))
	if err := s.CreateCode(ctx, mcpoauth.CodeRecord{ID: "k", ClientID: "c", Subject: "u", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	const n = 16
	var wg sync.WaitGroup
	wins := make(chan struct{}, n)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.ConsumeCode(ctx, "k"); err == nil {
				wins <- struct{}{}
			} else if !errors.Is(err, mcpoauth.ErrNotFound) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	close(wins)
	if len(wins) != 1 {
		t.Fatalf("want exactly one winner, got %d", len(wins))
	}
}

// TestServerOverBolt runs the full flow on the durable adapter with a
// restart between code issuance and exchange, and between issue and verify.
func TestServerOverBolt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "oauth.db")
	const redirect = "https://c.example.test/cb"
	cfg := mcpoauth.Config{Issuer: "https://mcp.example.test", Resource: "https://mcp.example.test/mcp", Scopes: []string{"read", "write"}}
	verifier := strings.Repeat("v", 64)
	sum := sha256.Sum256([]byte(verifier))
	chal := base64.RawURLEncoding.EncodeToString(sum[:])

	boot := func() (*boltstore.Store, *mcpoauth.Server) {
		s := open(t, path)
		srv, err := mcpoauth.New(cfg, s)
		if err != nil {
			t.Fatal(err)
		}
		return s, srv
	}
	s, srv := boot()
	if err := s.CreateClient(ctx, mcpoauth.Client{ID: "c1", Name: "C", RedirectURIs: []string{redirect}}); err != nil {
		t.Fatal(err)
	}
	var handle string
	h := srv.AuthorizeHandler(func(w http.ResponseWriter, r *http.Request, hd string, req mcpoauth.ConsentRequest) { handle = hd })
	q := url.Values{"response_type": {"code"}, "client_id": {"c1"}, "redirect_uri": {redirect}, "code_challenge": {chal}, "code_challenge_method": {"S256"}, "state": {"st"}, "scope": {"read write"}}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))
	if rr.Code != 200 || handle == "" {
		t.Fatalf("authorize: %d", rr.Code)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, srv = boot()
	loc, err := srv.Approve(ctx, handle, mcpoauth.Approval{Subject: "u", Binding: "b", Scopes: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(loc)
	code := u.Query().Get("code")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, srv = boot()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"c1"}, "redirect_uri": {redirect}, "code_verifier": {verifier}}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	srv.TokenHandler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("token: %d %s", rr.Code, rr.Body)
	}
	var body struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || body.Scope != "read" {
		t.Fatalf("body: %s", rr.Body)
	}
	req = httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	srv.TokenHandler().ServeHTTP(rr, req)
	if rr.Code != 400 {
		t.Fatal("replay after restart must fail")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, srv = boot()
	id, err := srv.Verify(ctx, body.AccessToken)
	if err != nil || id.Subject != "u" || id.Binding != "b" || len(id.Scopes) != 1 || id.GrantID == "" {
		t.Fatalf("verify after restart: %+v %v", id, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Refresh across a restart; the grant id is stable.
	s, srv = boot()
	rform := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {body.RefreshToken}, "client_id": {"c1"}}
	rr = tokenPost(srv, rform)
	if rr.Code != 200 {
		t.Fatalf("refresh: %d %s", rr.Code, rr.Body)
	}
	var second struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &second); err != nil || second.RefreshToken == "" {
		t.Fatalf("body: %s", rr.Body)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, srv = boot()
	id2, err := srv.Verify(ctx, second.AccessToken)
	if err != nil || id2.GrantID != id.GrantID {
		t.Fatalf("grant id changed across refresh+restart: %+v %v", id2, err)
	}
	// Replay of the first refresh token after restart revokes the family.
	if rr = tokenPost(srv, rform); rr.Code != 400 {
		t.Fatal("refresh replay must fail")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	_, srv = boot()
	for _, tok := range []string{body.AccessToken, second.AccessToken} {
		if _, err := srv.Verify(ctx, tok); !errors.Is(err, mcpoauth.ErrDenied) {
			t.Fatalf("family revocation not durable: %v", err)
		}
	}
	rform.Set("refresh_token", second.RefreshToken)
	if rr = tokenPost(srv, rform); rr.Code != 400 {
		t.Fatal("newest refresh token must be dead after reuse")
	}
}

func tokenPost(srv *mcpoauth.Server, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.TokenHandler().ServeHTTP(rr, req)
	return rr
}

func TestConcurrentRotateExactlyOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s := open(t, filepath.Join(dir, "oauth.db"))
	now := time.Now().UTC()
	grant := mcpoauth.GrantRecord{ID: "g", ClientID: "c", Subject: "u", Resource: "r", Scopes: []string{"read"}, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := s.CreateGrant(ctx, mcpoauth.GrantIssue{Grant: grant,
		Token:   mcpoauth.TokenRecord{ID: "t0", GrantID: "g", ClientID: "c", Subject: "u", Resource: "r", Scopes: []string{"read"}, CreatedAt: now, ExpiresAt: now.Add(time.Hour)},
		Refresh: &mcpoauth.RefreshRecord{ID: "r0", GrantID: "g", ClientID: "c", Generation: 1, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	const n = 16
	var wg sync.WaitGroup
	results := make(chan error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- s.RotateRefresh(ctx, mcpoauth.RefreshRotation{RefreshID: "r0", At: now,
				Token:   mcpoauth.TokenRecord{ID: fmt.Sprintf("t%d", i+1), GrantID: "g", ClientID: "c", Subject: "u", Resource: "r", Scopes: []string{"read"}, CreatedAt: now, ExpiresAt: now.Add(time.Hour)},
				Refresh: mcpoauth.RefreshRecord{ID: fmt.Sprintf("r%d", i+1), GrantID: "g", ClientID: "c", Generation: 2, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}})
		}()
	}
	wg.Wait()
	close(results)
	ok, reused := 0, 0
	for err := range results {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, mcpoauth.ErrReused):
			reused++
		default:
			t.Fatalf("unexpected: %v", err)
		}
	}
	if ok != 1 || reused != n-1 {
		t.Fatalf("ok=%d reused=%d", ok, reused)
	}
	if g, err := s.Grant(ctx, "g"); err != nil || g.RevokedAt.IsZero() {
		t.Fatalf("family must be revoked after concurrent reuse: %+v %v", g, err)
	}
}
