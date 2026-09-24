package sqlstore_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/ajent-social/go/passkey"
	"github.com/ajent-social/go/passkey/sqlstore"
	wa "github.com/go-webauthn/webauthn/webauthn"
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
	_, _ = db.ExecContext(ctx, `TRUNCATE amsl_passkey_ceremonies, amsl_passkey_credentials`)
	return store
}

func TestSQLPasskeyCeremonyAndCredential(t *testing.T) {
	ctx := context.Background()
	store := open(t)
	digest := sha256.Sum256([]byte("handle-1"))
	if err := store.PutCeremony(ctx, passkey.Ceremony{
		HandleDigest: digest, Kind: passkey.KindRegister, SubjectID: "u1", Name: "Ada",
		SessionJSON: []byte(`{}`), ExpiresAt: time.Now().UTC().Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	got, err := store.TakeCeremony(ctx, digest)
	if err != nil || got.SubjectID != "u1" {
		t.Fatalf("%#v %v", got, err)
	}
	if _, err := store.TakeCeremony(ctx, digest); !errors.Is(err, passkey.ErrNotFound) {
		t.Fatalf("replay: %v", err)
	}
	cred := wa.Credential{ID: []byte("cred-1")}
	if err := store.PutCredential(ctx, passkey.CredentialRecord{
		SubjectID: "u1", Credential: cred, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	n, err := store.CountCredentials(ctx, "u1")
	if err != nil || n != 1 {
		t.Fatalf("count %d %v", n, err)
	}
	list, err := store.ListCredentials(ctx, "u1")
	if err != nil || len(list) != 1 {
		t.Fatalf("%#v %v", list, err)
	}
}
