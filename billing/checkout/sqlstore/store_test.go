package sqlstore_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/ajent-social/go/billing/checkout"
	"github.com/ajent-social/go/billing/checkout/sqlstore"
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
	_, _ = db.ExecContext(ctx, `TRUNCATE amsl_billing_customers, amsl_billing_attempts`)
	return store
}

func TestSQLCheckoutLifecycle(t *testing.T) {
	ctx := context.Background()
	store := open(t)
	now := time.Now().UTC()
	if err := store.InsertCustomer(ctx, checkout.CustomerBinding{Account: "a1", CustomerRef: "cus_1", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := store.InsertCustomer(ctx, checkout.CustomerBinding{Account: "a1", CustomerRef: "cus_x", CreatedAt: now}); !errors.Is(err, checkout.ErrExists) {
		t.Fatalf("dup: %v", err)
	}
	rec, err := store.ClaimAttempt(ctx, checkout.AttemptClaim{
		Account: "a1", Attempt: "t1", Kind: checkout.KindCheckout,
		RequestHash: "h1", IdempotencyKey: "k1", Now: now,
	})
	if err != nil || rec.LeaseEpoch != 1 {
		t.Fatalf("%#v %v", rec, err)
	}
	if err := store.CommitAttempt(ctx, checkout.AttemptCommit{
		Account: "a1", Attempt: "t1", LeaseEpoch: 1, Status: checkout.StatusSucceeded,
		ProviderRef: "cs_1", CheckoutURL: "https://pay.test", Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := store.LookupAttempt(ctx, "a1", "t1")
	if err != nil || got.Status != checkout.StatusSucceeded || got.CheckoutURL == "" {
		t.Fatalf("%#v %v", got, err)
	}
}
