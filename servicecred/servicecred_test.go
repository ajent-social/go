//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package servicecred_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ajent-social/go/servicecred"
	"github.com/ajent-social/go/servicecred/boltstore"
)

func setup(t *testing.T) (*servicecred.Service, *boltstore.Store, string, servicecred.Grant) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "credentials.db")
	store, err := boltstore.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := servicecred.New(store)
	if err != nil {
		t.Fatal(err)
	}
	grant := servicecred.Grant{Access: servicecred.Access{Owner: "owner", Resource: "browser", Scopes: []string{"read", "act"}}, ExpiresAt: time.Now().Add(time.Hour)}
	return svc, store, path, grant
}
func TestLifecycleAndDeniedBindings(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc, _, path, g := setup(t)
	secret, meta, err := svc.Issue(ctx, g, g)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Verify(ctx, secret.Reveal(), g.Access); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		access servicecred.Access
		raw    string
	}{
		{"wrong owner", servicecred.Access{Owner: "other", Resource: g.Resource, Scopes: []string{"read"}}, secret.Reveal()},
		{"wrong resource", servicecred.Access{Owner: g.Owner, Resource: "other", Scopes: []string{"read"}}, secret.Reveal()},
		{"missing scope", servicecred.Access{Owner: g.Owner, Resource: g.Resource, Scopes: []string{"admin"}}, secret.Reveal()},
		{"wrong secret", g.Access, secret.Reveal()[:39] + strings.Repeat("0", 64)},
		{"malformed", g.Access, "nonsense"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := svc.Verify(ctx, tc.raw, tc.access); !errors.Is(err, servicecred.ErrDenied) {
				t.Fatalf("want denied, got %v", err)
			}
		})
	}
	if err := svc.Revoke(ctx, "other", g.Resource, meta.ID); !errors.Is(err, servicecred.ErrDenied) {
		t.Fatalf("cross owner revoke: %v", err)
	}
	if _, err := svc.Verify(ctx, secret.Reveal(), g.Access); err != nil {
		t.Fatal(err)
	}
	listed, err := svc.List(ctx, g.Owner, g.Resource)
	if err != nil || len(listed) != 1 {
		t.Fatalf("list: %v %v", listed, err)
	}
	encoded, _ := json.Marshal(listed)
	secretJSON, _ := json.Marshal(secret)
	type wrapped struct{ secret servicecred.Secret }
	var logs strings.Builder
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	logger.Info("test", "secret", secret)
	for _, out := range []string{string(encoded), string(secretJSON), fmt.Sprintf("%v %+v %#v %d %s %q %x %X %p", secret, secret, secret, secret, secret, secret, secret, secret, secret), fmt.Sprintf("%+v", wrapped{secret}), logs.String()} {
		if strings.Contains(out, secret.Reveal()) || strings.Contains(out, "digest") {
			t.Fatal("secret/verifier disclosure")
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret.Reveal()) {
		t.Fatal("plaintext secret on disk")
	}
	if err := svc.Revoke(ctx, g.Owner, g.Resource, meta.ID); err != nil {
		t.Fatal(err)
	}
	revoked, err := svc.List(ctx, g.Owner, g.Resource)
	if err != nil || len(revoked) != 1 || revoked[0].RevokedAt.IsZero() {
		t.Fatalf("revoked metadata: %#v %v", revoked, err)
	}
	revokedJSON, err := json.Marshal(revoked[0])
	if err != nil || !strings.Contains(string(revokedJSON), "revoked_at") {
		t.Fatalf("nonzero revocation timestamp missing from JSON: %s %v", revokedJSON, err)
	}
	zeroJSON, err := json.Marshal(listed[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(zeroJSON), "revoked_at") {
		t.Fatal("zero revocation timestamp should be omitted")
	}
	reopened, err := boltstore.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := servicecred.New(reopened)
	if _, err := again.Verify(ctx, secret.Reveal(), g.Access); !errors.Is(err, servicecred.ErrDenied) {
		t.Fatalf("revocation lost across reopen: %v", err)
	}
	if err := svc.Revoke(ctx, g.Owner, g.Resource, meta.ID); err != nil {
		t.Fatal("idempotent revoke", err)
	}
}
func TestIssuanceCannotEscalate(t *testing.T) {
	t.Parallel()
	svc, _, _, g := setup(t)
	for _, tc := range []struct {
		name   string
		change func(*servicecred.Grant)
	}{
		{"scope", func(r *servicecred.Grant) { r.Scopes = []string{"admin"} }},
		{"owner", func(r *servicecred.Grant) { r.Owner = "other" }},
		{"resource", func(r *servicecred.Grant) { r.Resource = "other" }},
		{"lifetime", func(r *servicecred.Grant) { r.ExpiresAt = g.ExpiresAt.Add(time.Second) }},
		{"no expiry", func(r *servicecred.Grant) { r.ExpiresAt = time.Time{} }},
		{"empty scope", func(r *servicecred.Grant) { r.Scopes = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := g
			tc.change(&r)
			secret, _, err := svc.Issue(context.Background(), g, r)
			if err == nil || secret.Reveal() != "" {
				t.Fatal("invalid issuance succeeded")
			}
		})
	}
}
func TestExpiryAndCorruptStorageDeny(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc, store, path, g := setup(t)
	secret, m, err := svc.Issue(ctx, g, g)
	if err != nil {
		t.Fatal(err)
	}
	r, err := store.Lookup(ctx, m.ID)
	if err != nil {
		t.Fatal(err)
	}
	// A committed expired record is rejected without relying on wall-clock sleeps.
	r.ExpiresAt = time.Now().Add(-time.Hour)
	r.CreatedAt = r.ExpiresAt.Add(-time.Hour)
	// Use another store implementation to preserve the original token's ID/digest.
	expired := r
	expired.ID = m.ID
	e, _ := servicecred.New(recordStore{record: expired})
	if _, err := e.Verify(ctx, secret.Reveal(), g.Access); !errors.Is(err, servicecred.ErrDenied) {
		t.Fatalf("expired: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Verify(ctx, secret.Reveal(), g.Access); err == nil {
		t.Fatal("missing storage accepted")
	}
	if err := os.WriteFile(path, []byte("corrupt database"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Verify(ctx, secret.Reveal(), g.Access); err == nil {
		t.Fatal("corrupt storage accepted")
	}
}

type recordStore struct {
	record servicecred.Record
	err    error
}

func (s recordStore) Create(context.Context, servicecred.Record) error { return s.err }
func (s recordStore) Lookup(context.Context, string) (servicecred.Record, error) {
	return s.record, s.err
}
func (s recordStore) Revoke(context.Context, string, string, string, time.Time) error { return s.err }
func (s recordStore) List(context.Context, string, string) ([]servicecred.Metadata, error) {
	return nil, s.err
}
func TestStorageFailureAndCancellation(t *testing.T) {
	t.Parallel()
	svc, _, _, g := setup(t)
	ctx := context.Background()
	secret, _, err := svc.Issue(ctx, g, g)
	if err != nil {
		t.Fatal(err)
	}
	failed, _ := servicecred.New(recordStore{err: errors.New("unavailable")})
	if _, err := failed.Verify(ctx, secret.Reveal(), g.Access); err == nil {
		t.Fatal("failed store accepted")
	}
	out, _, err := failed.Issue(ctx, g, g)
	if err == nil || out.Reveal() != "" {
		t.Fatal("failed issuance disclosed secret")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := svc.Verify(cancelled, secret.Reveal(), g.Access); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
}
func TestConcurrentRevocationVisibleToOtherStores(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc, _, path, g := setup(t)
	secret, m, err := svc.Issue(ctx, g, g)
	if err != nil {
		t.Fatal(err)
	}
	otherStore, err := boltstore.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := servicecred.New(otherStore)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := other.Revoke(ctx, g.Owner, g.Resource, m.ID)
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if _, err := svc.Verify(ctx, secret.Reveal(), g.Access); !errors.Is(err, servicecred.ErrDenied) {
		t.Fatalf("stale reader: %v", err)
	}
}

func TestRevokeMakesProgressDuringContinuousVerify(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc, _, _, g := setup(t)
	secret, meta, err := svc.Issue(ctx, g, g)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	stop := make(chan struct{})
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = svc.Verify(ctx, secret.Reveal(), g.Access)
				}
			}
		}()
	}
	close(start)
	time.Sleep(30 * time.Millisecond)
	revokeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := svc.Revoke(revokeCtx, g.Owner, g.Resource, meta.ID); err != nil {
		close(stop)
		wg.Wait()
		t.Fatalf("revoke starved by readers: %v", err)
	}
	close(stop)
	wg.Wait()
	if _, err := svc.Verify(ctx, secret.Reveal(), g.Access); !errors.Is(err, servicecred.ErrDenied) {
		t.Fatalf("revocation not visible: %v", err)
	}
}

func TestRevokeMakesProgressAgainstAnotherProcess(t *testing.T) {
	ctx := context.Background()
	svc, _, path, g := setup(t)
	secret, meta, err := svc.Issue(ctx, g, g)
	if err != nil {
		t.Fatal(err)
	}
	ready := filepath.Join(t.TempDir(), "ready")
	cmd := exec.Command(os.Args[0], "-test.run=^TestVerifySubprocessHelper$")
	cmd.Env = append(os.Environ(), "SERVICECRED_HELPER=1", "SERVICECRED_DB="+path, "SERVICECRED_TOKEN="+secret.Reveal(), "SERVICECRED_READY="+ready)
	var output strings.Builder
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	finished := false
	defer func() {
		if !finished {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("helper did not become ready: %s", output.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	revokeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	err = svc.Revoke(revokeCtx, g.Owner, g.Resource, meta.ID)
	cancel()
	if err != nil {
		t.Fatalf("cross-process revoke starved by readers: %v; helper: %s", err, output.String())
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("verify helper failed: %v; output: %s", err, output.String())
	}
	finished = true
}

func TestVerifySubprocessHelper(t *testing.T) {
	if os.Getenv("SERVICECRED_HELPER") != "1" {
		return
	}
	store, err := boltstore.Open(context.Background(), os.Getenv("SERVICECRED_DB"))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := servicecred.New(store)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("SERVICECRED_READY"), []byte("ready"), 0600); err != nil {
		t.Fatal(err)
	}
	required := servicecred.Access{Owner: "owner", Resource: "browser", Scopes: []string{"read", "act"}}
	for {
		_, err := svc.Verify(context.Background(), os.Getenv("SERVICECRED_TOKEN"), required)
		if errors.Is(err, servicecred.ErrDenied) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestStoreRevokeRejectsZeroTimeAndHidesBindingMismatch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc, store, _, g := setup(t)
	_, meta, err := svc.Issue(ctx, g, g)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke(ctx, meta.ID, g.Owner, g.Resource, time.Time{}); !errors.Is(err, servicecred.ErrInvalid) {
		t.Fatalf("zero revoke time: %v", err)
	}
	if err := store.Revoke(ctx, meta.ID, "other", g.Resource, time.Now()); !errors.Is(err, servicecred.ErrNotFound) {
		t.Fatalf("binding mismatch should be indistinguishable from missing: %v", err)
	}
}

func TestIssueReturnsIndependentMetadataScopes(t *testing.T) {
	store := &memoryStore{}
	svc, err := servicecred.New(store)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	grant := servicecred.Grant{Access: servicecred.Access{Owner: "owner", Resource: "resource", Scopes: []string{"read"}}, ExpiresAt: now.Add(time.Hour)}
	secret, metadata, err := svc.Issue(context.Background(), grant, grant)
	if err != nil {
		t.Fatal(err)
	}
	metadata.Scopes[0] = "admin"
	if _, err := svc.Verify(context.Background(), secret.Reveal(), grant.Access); err != nil {
		t.Fatalf("returned metadata mutated stored grant: %v", err)
	}
}

type memoryStore struct{ record servicecred.Record }

func (s *memoryStore) Create(_ context.Context, r servicecred.Record) error {
	s.record = r
	return nil
}
func (s *memoryStore) Lookup(context.Context, string) (servicecred.Record, error) {
	return s.record, nil
}
func (s *memoryStore) Revoke(context.Context, string, string, string, time.Time) error {
	return nil
}
func (s *memoryStore) List(context.Context, string, string) ([]servicecred.Metadata, error) {
	return nil, nil
}

func TestOpenResolvesRelativeDatabasePath(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(old); err != nil {
			t.Error(err)
		}
	})
	if _, err := boltstore.Open(context.Background(), "credentials.db"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "credentials.db")); err != nil {
		t.Fatalf("database was not created at resolved path: %v", err)
	}
}

func TestExistingStoreCanVerifyReadOnly(t *testing.T) {
	ctx := context.Background()
	svc, _, path, grant := setup(t)
	secret, _, err := svc.Issue(ctx, grant, grant)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(path), 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(filepath.Dir(path), 0700)
		_ = os.Chmod(path, 0600)
	})
	readOnly, err := boltstore.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	readOnlyService, err := servicecred.New(readOnly)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readOnlyService.Verify(ctx, secret.Reveal(), grant.Access); err != nil {
		t.Fatalf("read-only verification failed: %v", err)
	}
}

func TestStoreCreateDoesNotOverwriteAndPermissions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc, store, path, g := setup(t)
	secret, m, err := svc.Issue(ctx, g, g)
	if err != nil {
		t.Fatal(err)
	}
	r, err := store.Lookup(ctx, m.ID)
	if err != nil {
		t.Fatal(err)
	}
	r.Owner = "attacker"
	if err := store.Create(ctx, r); !errors.Is(err, servicecred.ErrExists) {
		t.Fatalf("overwrite: %v", err)
	}
	if _, err := svc.Verify(ctx, secret.Reveal(), g.Access); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Verify(ctx, secret.Reveal(), g.Access); err == nil {
		t.Fatal("accepted insecure database permissions")
	}
}
func FuzzMalformedToken(f *testing.F) {
	f.Add("")
	f.Add("amsl1_")
	f.Add(strings.Repeat("a", 103))
	svc, _ := servicecred.New(recordStore{err: servicecred.ErrNotFound})
	f.Fuzz(func(t *testing.T, raw string) {
		_, err := svc.Verify(context.Background(), raw, servicecred.Access{Owner: "o", Resource: "r", Scopes: []string{"s"}})
		if !errors.Is(err, servicecred.ErrDenied) {
			t.Fatalf("malformed/unknown token accepted: %v", err)
		}
	})
}
