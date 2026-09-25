package sqlstore_test

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/ajent-social/go/tenant"
	"github.com/ajent-social/go/tenant/sqlstore"
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
	_, _ = db.ExecContext(ctx, `TRUNCATE amsl_tenant_instances`)
	return store
}

func TestCreateLookupApply(t *testing.T) {
	store := open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	in := tenant.Instance{
		ID: "t1", AccountID: "a1", Slug: "demo", Status: tenant.StatusRequested,
		Hostname: "demo.example.com", LeaseEpoch: 1, CreatedAt: now, UpdatedAt: now,
	}
	if err := store.Create(ctx, in); err != nil {
		t.Fatal(err)
	}
	got, err := store.LookupBySlug(ctx, "demo")
	if err != nil || got.AccountID != "a1" {
		t.Fatalf("lookup: %+v %v", got, err)
	}
	next := got
	next.Status = tenant.StatusReady
	next.UpdatedAt = now
	if err := store.Apply(ctx, "t1", 1, next); err != nil {
		t.Fatal(err)
	}
	got, err = store.Lookup(ctx, "t1")
	if err != nil || got.LeaseEpoch != 2 || got.Status != tenant.StatusReady {
		t.Fatalf("after apply: %+v %v", got, err)
	}
}
