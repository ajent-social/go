package sqlstore_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/ajent-social/go/mcpoauth"
	"github.com/ajent-social/go/mcpoauth/sqlstore"
	_ "github.com/lib/pq"
)

func dsn(t *testing.T) (string, bool) {
	t.Helper()
	if v := os.Getenv("AMSL_SQLSTORE_TEST_DSN"); v != "" {
		return v, true
	}
	if v := os.Getenv("AMSL_PGSTORE_TEST_DSN"); v != "" {
		return v, true
	}
	return "host=/tmp dbname=amsl_servicecred_test sslmode=disable", false
}

func open(t *testing.T) *sqlstore.Store {
	t.Helper()
	dsn, required := dsn(t)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		if required {
			t.Fatalf("postgres required: %v", err)
		}
		t.Skipf("postgres unavailable: %v", err)
	}
	store, err := sqlstore.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{
		"amsl_mcpoauth_refresh", "amsl_mcpoauth_tokens", "amsl_mcpoauth_grants",
		"amsl_mcpoauth_codes", "amsl_mcpoauth_consents", "amsl_mcpoauth_clients",
	} {
		_, _ = db.ExecContext(ctx, "TRUNCATE "+table)
	}
	return store
}

func TestSQLOAuthLifecycleAndReuse(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	now := time.Now().UTC().Truncate(time.Second)
	client := mcpoauth.Client{ID: "c1", Name: "C", RedirectURIs: []string{"https://c.example.test/cb"}, CreatedAt: now}
	if err := s.CreateClient(ctx, client); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateClient(ctx, client); !errors.Is(err, mcpoauth.ErrExists) {
		t.Fatalf("dup: %v", err)
	}
	consent := mcpoauth.ConsentRecord{
		ID: "h1", ClientID: "c1", RedirectURI: client.RedirectURIs[0], CodeChallenge: "x",
		State: "s", Resource: "r", Scopes: []string{"read"}, CreatedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	if err := s.CreateConsent(ctx, consent); err != nil {
		t.Fatal(err)
	}
	got, err := s.ConsumeConsent(ctx, "h1")
	if err != nil || got.ClientID != "c1" {
		t.Fatalf("%#v %v", got, err)
	}
	if _, err := s.Consent(ctx, "h1"); !errors.Is(err, mcpoauth.ErrNotFound) {
		t.Fatalf("consumed: %v", err)
	}
	grant := mcpoauth.GrantRecord{
		ID: "g1", ClientID: "c1", Subject: "u", Binding: "b", Resource: "r",
		Scopes: []string{"read"}, CreatedAt: now, ExpiresAt: now.Add(48 * time.Hour),
	}
	token := mcpoauth.TokenRecord{
		ID: "t1", GrantID: "g1", ClientID: "c1", Subject: "u", Binding: "b", Resource: "r",
		Scopes: []string{"read"}, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	refresh := mcpoauth.RefreshRecord{
		ID: "r1", GrantID: "g1", ClientID: "c1", Generation: 1, CreatedAt: now, ExpiresAt: grant.ExpiresAt,
	}
	if err := s.CreateGrant(ctx, mcpoauth.GrantIssue{Grant: grant, Token: token, Refresh: &refresh}); err != nil {
		t.Fatal(err)
	}
	rot := mcpoauth.RefreshRotation{
		RefreshID: "r1", At: now.Add(time.Minute),
		Token: mcpoauth.TokenRecord{
			ID: "t2", GrantID: "g1", ClientID: "c1", Subject: "u", Binding: "b", Resource: "r",
			Scopes: []string{"read"}, CreatedAt: now.Add(time.Minute), ExpiresAt: now.Add(2 * time.Hour),
		},
		Refresh: mcpoauth.RefreshRecord{
			ID: "r2", GrantID: "g1", ClientID: "c1", Generation: 2,
			CreatedAt: now.Add(time.Minute), ExpiresAt: grant.ExpiresAt,
		},
	}
	if err := s.RotateRefresh(ctx, rot); err != nil {
		t.Fatal(err)
	}
	reuse := rot
	reuse.At = now.Add(2 * time.Minute)
	reuse.Token.ID = "t3"
	reuse.Refresh.ID = "r3"
	reuse.Refresh.Generation = 3
	if err := s.RotateRefresh(ctx, reuse); !errors.Is(err, mcpoauth.ErrReused) {
		t.Fatalf("reuse: %v", err)
	}
	g, err := s.Grant(ctx, "g1")
	if err != nil || g.RevokedAt.IsZero() {
		t.Fatalf("revoked after reuse: %#v %v", g, err)
	}
}
