package sqlstore_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/ajent-social/go/accounts"
	"github.com/ajent-social/go/accounts/sqlstore"
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
	_, _ = db.ExecContext(ctx, `TRUNCATE amsl_accounts`)
	return store
}

func TestSQLAccountsLifecycle(t *testing.T) {
	ctx := context.Background()
	store := open(t)
	svc, err := accounts.New(store)
	if err != nil {
		t.Fatal(err)
	}
	a, err := svc.Create(ctx, accounts.CreateInput{Email: "ada@example.com", DisplayName: "Ada"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Create(ctx, accounts.CreateInput{Email: "ada@example.com", DisplayName: "Dup"}); !errors.Is(err, accounts.ErrExists) {
		t.Fatalf("dup email: %v", err)
	}
	got, err := svc.GetByEmail(ctx, "ada@example.com")
	if err != nil || got.ID != a.ID {
		t.Fatalf("%#v %v", got, err)
	}
	if err := svc.Disable(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RequireActive(ctx, a.ID); !errors.Is(err, accounts.ErrDenied) {
		t.Fatalf("got %v", err)
	}
}
