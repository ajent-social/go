package sqlstore_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/ajent-social/go/humanauth"
	"github.com/ajent-social/go/humanauth/sqlstore"
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

func openDB(t *testing.T) *sql.DB {
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
	return db
}

func open(t *testing.T) *sqlstore.Store {
	t.Helper()
	db := openDB(t)
	ctx := context.Background()
	store, err := sqlstore.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = db.ExecContext(ctx, `TRUNCATE amsl_humanauth_sessions`)
	return store
}

func record(token, subjectID string, created, expires time.Time) humanauth.Record {
	return humanauth.Record{
		TokenDigest: sha256.Sum256([]byte(token)),
		Subject:     humanauth.Subject{ID: subjectID, Name: "a@example.com", DisplayName: "Example Person"},
		Method:      humanauth.MethodMagicLink,
		CSRF:        "csrf-" + token,
		CreatedAt:   created,
		ExpiresAt:   expires,
	}
}

func TestStoreSQL(t *testing.T) {
	ctx := context.Background()
	store := open(t)
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	older := record("t1", "subj-a", base, base.Add(time.Hour))
	newer := record("t2", "subj-a", base.Add(time.Minute), base.Add(2*time.Hour))
	other := record("t3", "subj-b", base, base.Add(time.Hour))
	expired := record("t4", "subj-b", base.Add(-2*time.Hour), base.Add(-time.Hour))
	for _, rec := range []humanauth.Record{older, newer, other, expired} {
		if err := store.Create(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Create(ctx, older); err == nil {
		t.Fatal("duplicate digest accepted")
	}

	got, err := store.Get(ctx, newer.TokenDigest)
	if err != nil {
		t.Fatal(err)
	}
	if got != newer {
		t.Fatalf("Get = %#v, want %#v", got, newer)
	}
	if _, err := store.Get(ctx, sha256.Sum256([]byte("missing"))); !errors.Is(err, humanauth.ErrNotFound) {
		t.Fatalf("missing Get: %v", err)
	}

	list, err := store.ListSubject(ctx, "subj-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].TokenDigest != newer.TokenDigest || list[1].TokenDigest != older.TokenDigest {
		t.Fatalf("ListSubject order: %#v", list)
	}

	if n, err := store.DeleteExpired(ctx, base); err != nil || n != 1 {
		t.Fatalf("DeleteExpired = %d, %v", n, err)
	}
	if _, err := store.Get(ctx, expired.TokenDigest); !errors.Is(err, humanauth.ErrNotFound) {
		t.Fatalf("expired record survived: %v", err)
	}

	if err := store.Delete(ctx, older.TokenDigest); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, older.TokenDigest); err != nil {
		t.Fatalf("Delete not idempotent: %v", err)
	}
	if _, err := store.Get(ctx, older.TokenDigest); !errors.Is(err, humanauth.ErrNotFound) {
		t.Fatalf("deleted record survived: %v", err)
	}

	if n, err := store.DeleteSubject(ctx, "subj-a"); err != nil || n != 1 {
		t.Fatalf("DeleteSubject = %d, %v", n, err)
	}
	if list, err := store.ListSubject(ctx, "subj-a"); err != nil || len(list) != 0 {
		t.Fatalf("after DeleteSubject: %#v %v", list, err)
	}
	if _, err := store.Get(ctx, other.TokenDigest); err != nil {
		t.Fatalf("other subject touched: %v", err)
	}
}

func TestOpenIdempotentSQL(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	if _, err := sqlstore.Open(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err := sqlstore.Open(ctx, db); err != nil {
		t.Fatalf("second Open: %v", err)
	}
	if _, err := sqlstore.Open(ctx, nil); !errors.Is(err, humanauth.ErrInvalid) {
		t.Fatalf("nil db: %v", err)
	}
}
