package pgstore_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ajent-social/go/servicecred"
	"github.com/ajent-social/go/servicecred/pgstore"
	_ "github.com/lib/pq"
)

func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("AMSL_PGSTORE_TEST_DSN")
	if dsn == "" {
		dsn = "host=/tmp dbname=amsl_servicecred_test sslmode=disable"
	}
	return dsn
}

func openStore(t *testing.T) (*servicecred.Service, *pgstore.Store, *sql.DB) {
	t.Helper()
	db, err := sql.Open("postgres", testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	// Isolate concurrent tests with a truncated table after schema apply.
	store, err := pgstore.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `TRUNCATE amsl_service_credentials`); err != nil {
		t.Fatal(err)
	}
	svc, err := servicecred.New(store)
	if err != nil {
		t.Fatal(err)
	}
	return svc, store, db
}

func grant() servicecred.Grant {
	return servicecred.Grant{
		Access:    servicecred.Access{Owner: "owner", Resource: "api", Scopes: []string{"read", "write"}},
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
}

func TestPostgresLifecycle(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := openStore(t)
	g := grant()
	secret, meta, err := svc.Issue(ctx, g, g)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Verify(ctx, secret.Reveal(), g.Access); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Verify(ctx, secret.Reveal(), servicecred.Access{Owner: "other", Resource: g.Resource, Scopes: []string{"read"}}); !errors.Is(err, servicecred.ErrDenied) {
		t.Fatalf("cross-owner: %v", err)
	}
	if err := svc.Revoke(ctx, "other", g.Resource, meta.ID); !errors.Is(err, servicecred.ErrDenied) {
		t.Fatalf("cross-owner revoke: %v", err)
	}
	if err := svc.Revoke(ctx, g.Owner, g.Resource, meta.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.Revoke(ctx, g.Owner, g.Resource, meta.ID); err != nil {
		t.Fatalf("idempotent revoke: %v", err)
	}
	if _, err := svc.Verify(ctx, secret.Reveal(), g.Access); !errors.Is(err, servicecred.ErrDenied) {
		t.Fatalf("revoked still accepted: %v", err)
	}
	listed, err := svc.List(ctx, g.Owner, g.Resource)
	if err != nil || len(listed) != 1 || listed[0].RevokedAt.IsZero() {
		t.Fatalf("list revoked: %#v %v", listed, err)
	}
}

func TestPostgresCreateCollision(t *testing.T) {
	ctx := context.Background()
	_, store, _ := openStore(t)
	now := time.Now().UTC()
	r := servicecred.Record{
		Metadata: servicecred.Metadata{
			ID: "0123456789abcdef0123456789abcdef",
			Grant: servicecred.Grant{
				Access:    servicecred.Access{Owner: "o", Resource: "r", Scopes: []string{"s"}},
				ExpiresAt: now.Add(time.Hour),
			},
			CreatedAt: now,
		},
	}
	copy(r.Digest[:], []byte("0123456789abcdef0123456789abcdef"))
	if err := store.Create(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, r); !errors.Is(err, servicecred.ErrExists) {
		t.Fatalf("want exists, got %v", err)
	}
}

func TestPostgresConcurrentRevokeAndVerify(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := openStore(t)
	g := grant()
	secret, meta, err := svc.Issue(ctx, g, g)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 32; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, err := svc.Verify(ctx, secret.Reveal(), g.Access)
			errs <- err
		}()
		go func() {
			defer wg.Done()
			errs <- svc.Revoke(ctx, g.Owner, g.Resource, meta.ID)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil && !errors.Is(err, servicecred.ErrDenied) {
			t.Fatal(err)
		}
	}
	if _, err := svc.Verify(ctx, secret.Reveal(), g.Access); !errors.Is(err, servicecred.ErrDenied) {
		t.Fatalf("post-concurrent verify: %v", err)
	}
}

func TestOpenNilDB(t *testing.T) {
	_, err := pgstore.Open(context.Background(), nil)
	if !errors.Is(err, servicecred.ErrInvalid) {
		t.Fatalf("got %v", err)
	}
}
