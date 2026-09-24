package sqlstore_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/ajent-social/go/magiclink"
	"github.com/ajent-social/go/magiclink/sqlstore"
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
	_, _ = db.ExecContext(ctx, `TRUNCATE amsl_magiclink_challenges`)
	return store
}

func TestSQLMagicConsumeOnce(t *testing.T) {
	ctx := context.Background()
	store := open(t)
	svc, err := magiclink.New(magiclink.Config{BaseURL: "https://app.example/m"}, store, nil)
	if err != nil {
		t.Fatal(err)
	}
	iss, err := svc.Issue(ctx, magiclink.IssueInput{
		Email: "ada@example.com", Purpose: magiclink.PurposeLogin, SubjectID: "a1",
	})
	if err != nil {
		t.Fatal(err)
	}
	ch, err := svc.Consume(ctx, iss.Token)
	if err != nil || ch.SubjectID != "a1" {
		t.Fatalf("%#v %v", ch, err)
	}
	if _, err := svc.Consume(ctx, iss.Token); !errors.Is(err, magiclink.ErrNotFound) {
		t.Fatalf("replay: %v", err)
	}
}
