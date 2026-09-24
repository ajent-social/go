package sqlstore_test

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/ajent-social/go/billing/subscription"
	"github.com/ajent-social/go/billing/subscription/sqlstore"
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
	_, _ = db.ExecContext(ctx, `TRUNCATE amsl_billing_subscription_projections, amsl_billing_subscription_events`)
	return store
}

func TestSQLSubscriptionIdempotent(t *testing.T) {
	ctx := context.Background()
	store := open(t)
	svc, err := subscription.New(store)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	ev := subscription.VerifiedEvent{
		ID: "evt_sql_1", Livemode: false, Type: "customer.subscription.updated",
		CustomerRef: "cus_1", SubscriptionRef: "sub_1", Status: "active",
		PeriodEnd: now.Add(24 * time.Hour), PayloadHash: "h1", ReceivedAt: now,
	}
	if err := svc.AcceptVerifiedEvent(ctx, ev); err != nil {
		t.Fatal(err)
	}
	if err := svc.AcceptVerifiedEvent(ctx, ev); err != nil {
		t.Fatal(err)
	}
	got, err := svc.GetProjection(ctx, "cus_1")
	if err != nil || got.Status != "active" {
		t.Fatalf("%#v %v", got, err)
	}
}
