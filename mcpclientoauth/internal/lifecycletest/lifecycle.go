// Package lifecycletest exercises the coordinator against actual store adapters.
package lifecycletest

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	oauth "github.com/ajent-social/go/mcpclientoauth"
)

// Run requires two adapters sharing the same authoritative storage. It never
// substitutes a fixture for the SQL adapter supplied by its SQL test caller.
func Run(t *testing.T, a, b oauth.LifecycleStore) {
	t.Helper()
	for _, scenario := range []string{"refresh-disconnect", "refresh-reconnect", "callback-disconnect", "callback-reconnect", "concurrent-refresh", "ambiguous-refresh"} {
		t.Run(scenario, func(t *testing.T) { run(t, a, b, scenario) })
	}
}

func wait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("operation did not reach barrier")
	}
}
func result(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("operation did not finish")
		return nil
	}
}

type readBarrier struct {
	oauth.LifecycleStore
	arrived chan<- struct{}
	release <-chan struct{}
}

func (s readBarrier) LookupToken(ctx context.Context, owner, server string) (oauth.TokenRecord, error) {
	rec, err := s.LifecycleStore.LookupToken(ctx, owner, server)
	if err == nil {
		s.arrived <- struct{}{}
		select {
		case <-s.release:
		case <-ctx.Done():
			return oauth.TokenRecord{}, ctx.Err()
		}
	}
	return rec, err
}

func run(t *testing.T, a, b oauth.LifecycleStore, scenario string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	var refreshes atomic.Int32
	var codes atomic.Int32
	callback := scenario == "callback-disconnect" || scenario == "callback-reconnect"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		if r.Form.Get("resource") != "https://resource.example/mcp" {
			t.Error("missing resource on token POST")
		}
		refresh := r.Form.Get("grant_type") == "refresh_token"
		if refresh {
			refreshes.Add(1)
			if r.Form.Get("refresh_token") != "old-refresh" {
				t.Error("unexpected refresh token")
			}
		} else {
			codes.Add(1)
		}
		if refresh || callback && codes.Load() == 1 {
			entered <- struct{}{}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		if scenario == "ambiguous-refresh" && refresh {
			// Provider consumed the refresh, but its response is lost on the wire.
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = conn.Close()
			return
		}
		access, rt, expiry := "old-access", "old-refresh", 60
		if refresh {
			access, rt, expiry = "new-access", "new-refresh", 3600
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": access, "refresh_token": rt, "expires_in": expiry})
	}))
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
		srv.Close()
	}()
	cfg := oauth.Config{Servers: []oauth.ServerConfig{{ID: "server", AuthURL: srv.URL + "/auth", TokenURL: srv.URL + "/token", ClientID: "client", RedirectURL: "http://127.0.0.1/cb", Resource: "https://resource.example/mcp"}}}
	newService := func(store oauth.Store) *oauth.Service {
		s, err := oauth.New(cfg, store, oauth.PlainSeal, oauth.PlainOpen)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	first, second := newService(a), newService(b)
	owner := t.Name() + "/" + rand.Text() // unique rows; never truncate shared databases
	start, err := first.Start(ctx, owner, "server")
	if err != nil {
		t.Fatal(err)
	}
	exchange := func(s *oauth.Service, state string) error {
		return s.Exchange(ctx, oauth.ExchangeInput{OwnerID: owner, State: state, Code: "code"})
	}
	if callback {
		done := make(chan error, 1)
		go func() { done <- exchange(first, start.State) }()
		wait(t, entered)
		if err := second.Revoke(ctx, owner, "server"); err != nil {
			t.Fatal(err)
		}
		if scenario == "callback-reconnect" {
			next, err := second.Start(ctx, owner, "server")
			if err != nil {
				t.Fatal(err)
			}
			if err := exchange(second, next.State); err != nil {
				t.Fatal(err)
			}
		}
		close(release)
		if err := result(t, done); !errors.Is(err, oauth.ErrConflict) {
			t.Fatalf("stale callback: %v", err)
		}
		if scenario == "callback-disconnect" {
			assertAbsent(t, ctx, a, owner)
		} else {
			assertReady(t, ctx, a, owner, "old-access")
		}
		return
	}
	if err := exchange(first, start.State); err != nil {
		t.Fatal(err)
	}
	if scenario == "concurrent-refresh" {
		arrived := make(chan struct{}, 2)
		readersRelease := make(chan struct{})
		first = newService(readBarrier{a, arrived, readersRelease})
		second = newService(readBarrier{b, arrived, readersRelease})
		done := make(chan error, 2)
		go func() { _, err := first.ValidToken(ctx, owner, "server"); done <- err }()
		go func() { _, err := second.ValidToken(ctx, owner, "server"); done <- err }()
		wait(t, arrived)
		wait(t, arrived)
		close(readersRelease)
		wait(t, entered)
		if err := result(t, done); !errors.Is(err, oauth.ErrConflict) {
			t.Fatalf("losing claim: %v", err)
		}
		close(release)
		if err := result(t, done); err != nil {
			t.Fatal(err)
		}
		if refreshes.Load() != 1 {
			t.Fatalf("duplicate refresh POSTs: %d", refreshes.Load())
		}
		assertReady(t, ctx, a, owner, "new-access")
		return
	}
	done := make(chan error, 1)
	go func() { _, err := first.ValidToken(ctx, owner, "server"); done <- err }()
	wait(t, entered)
	if scenario != "ambiguous-refresh" {
		if err := second.Revoke(ctx, owner, "server"); err != nil {
			t.Fatal(err)
		}
		if scenario == "refresh-reconnect" {
			next, err := second.Start(ctx, owner, "server")
			if err != nil {
				t.Fatal(err)
			}
			if err := exchange(second, next.State); err != nil {
				t.Fatal(err)
			}
		}
	}
	close(release)
	err = result(t, done)
	if scenario == "ambiguous-refresh" {
		if err == nil {
			t.Fatal("lost response succeeded")
		}
		for i := 0; i < 2; i++ {
			if _, err := second.ValidToken(ctx, owner, "server"); !errors.Is(err, oauth.ErrRefreshUncertain) {
				t.Fatalf("uncertain: %v", err)
			}
		}
		if refreshes.Load() != 1 {
			t.Fatal("ambiguous refresh replayed")
		}
	} else {
		if !errors.Is(err, oauth.ErrConflict) {
			t.Fatalf("stale refresh: %v", err)
		}
		if scenario == "refresh-disconnect" {
			assertAbsent(t, ctx, a, owner)
		} else {
			assertReady(t, ctx, a, owner, "old-access")
		}
	}
}
func assertAbsent(t *testing.T, ctx context.Context, s oauth.Store, owner string) {
	t.Helper()
	if _, err := s.LookupToken(ctx, owner, "server"); !errors.Is(err, oauth.ErrNotFound) {
		t.Fatalf("disconnected token: %v", err)
	}
}
func assertReady(t *testing.T, ctx context.Context, s oauth.Store, owner, access string) {
	t.Helper()
	rec, err := s.LookupToken(ctx, owner, "server")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := oauth.PlainOpen(rec.Ciphertext)
	if err != nil || tok.AccessToken != access {
		t.Fatalf("wrong persisted token: %v", err)
	}
}
