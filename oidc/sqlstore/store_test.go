package sqlstore_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/ajent-social/go/oidc"
	"github.com/ajent-social/go/oidc/sqlstore"
	_ "github.com/lib/pq"
)

func open(t *testing.T) *sqlstore.Store {
	t.Helper()
	dsn := os.Getenv("AMSL_SQLSTORE_TEST_DSN")
	if dsn == "" {
		dsn = "host=/tmp dbname=amsl_servicecred_test sslmode=disable"
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	store, err := sqlstore.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = db.ExecContext(ctx, `TRUNCATE amsl_oidc_pending, amsl_oidc_bindings`)
	return store
}

func TestPendingAndBinding(t *testing.T) {
	store := open(t)
	ctx := context.Background()
	dig := sha256.Sum256([]byte("state"))
	now := time.Now().UTC()
	if err := store.PutPending(ctx, oidc.Pending{
		StateDigest: dig, Provider: "google", Nonce: "n",
		ExpiresAt: now.Add(time.Minute), CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := store.TakePending(ctx, dig)
	if err != nil || got.Provider != "google" {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := store.TakePending(ctx, dig); err != oidc.ErrNotFound {
		t.Fatalf("expected not found, got %v", err)
	}
	b := oidc.Binding{Provider: "google", Subject: "sub1", AccountID: "a1", CreatedAt: now}
	if err := store.PutBinding(ctx, b); err != nil {
		t.Fatal(err)
	}
	if err := store.PutBinding(ctx, b); err != nil {
		t.Fatal(err)
	}
	conflict := b
	conflict.AccountID = "a2"
	if err := store.PutBinding(ctx, conflict); err != oidc.ErrExists {
		t.Fatalf("expected exists, got %v", err)
	}
}
