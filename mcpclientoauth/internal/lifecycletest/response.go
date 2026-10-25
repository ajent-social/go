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

// responseCases verifies that malformed rotating responses cannot make a binding
// ready, while genuine omission preserves the existing refresh credential.
func responseCases(t *testing.T, a, b oauth.LifecycleStore) {
	for _, tc := range []struct{ name, field, value string }{
		{"refresh-null", "refresh_token", `null`},
		{"refresh-number", "refresh_token", `123`},
		{"refresh-object", "refresh_token", `{}`},
		{"refresh-array", "refresh_token", `[]`},
		{"refresh-bool", "refresh_token", `false`},
		{"refresh-empty", "refresh_token", `""`},
		{"refresh-control", "refresh_token", `"invalid\nrefresh"`},
		{"refresh-nonascii", "refresh_token", `"\u00e9"`},
		{"type-null", "token_type", `null`},
		{"type-number", "token_type", `123`},
		{"type-object", "token_type", `{}`},
		{"type-empty", "token_type", `""`},
		{"type-invalid-name", "token_type", `"Bearer token"`},
		{"access-null", "access_token", `null`},
		{"access-number", "access_token", `123`},
		{"access-empty", "access_token", `""`},
		{"scope-null", "scope", `null`},
		{"scope-array", "scope", `["read"]`},
		{"omitted-refresh", "", ""},
		{"replacement-refresh", "refresh_token", `"new-refresh"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var posts, oldPosts atomic.Int32
			valid := tc.name == "omitted-refresh" || tc.name == "replacement-refresh"
			collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				posts.Add(1)
				if err := r.ParseForm(); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				if r.Form.Get("refresh_token") == "old-refresh" {
					oldPosts.Add(1)
				} else {
					t.Error("unexpected refresh credential")
				}
				// Model a provider that may already have consumed/rotated the old token.
				response := map[string]json.RawMessage{"access_token": json.RawMessage(`"new-access"`), "token_type": json.RawMessage(`"Bearer"`), "expires_in": json.RawMessage(`3600`)}
				if tc.field != "" {
					response[tc.field] = json.RawMessage(tc.value)
				}
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer collector.Close()
			cfg := oauth.Config{Servers: []oauth.ServerConfig{{ID: "server", AuthURL: collector.URL + "/auth", TokenURL: collector.URL + "/token", ClientID: "client", RedirectURL: "http://127.0.0.1/cb"}}}
			newService := func(store oauth.Store) *oauth.Service {
				s, err := oauth.New(cfg, store, oauth.PlainSeal, oauth.PlainOpen)
				if err != nil {
					t.Fatal(err)
				}
				return s
			}
			owner, generation := t.Name()+"/"+rand.Text(), rand.Text()
			if err := a.BeginConnection(ctx, owner, "server", generation); err != nil {
				t.Fatal(err)
			}
			ct, err := oauth.PlainSeal(oauth.TokenSecrets{AccessToken: "old-access", RefreshToken: "old-refresh", TokenType: "Bearer"})
			if err != nil {
				t.Fatal(err)
			}
			if err := a.CompleteToken(ctx, oauth.TokenRecord{OwnerID: owner, ServerID: "server", Generation: generation, Ciphertext: ct, ExpiresAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
				t.Fatal(err)
			}
			first, second := newService(a), newService(b)
			token, err := first.ValidToken(ctx, owner, "server")
			if !valid {
				if !errors.Is(err, oauth.ErrDenied) || token.AccessToken != "" {
					t.Fatalf("malformed response accepted: %v", err)
				}
				if _, err := b.LookupToken(ctx, owner, "server"); !errors.Is(err, oauth.ErrRefreshUncertain) {
					t.Fatalf("malformed response left binding ready: %v", err)
				}
				for i := 0; i < 2; i++ {
					if _, err := second.ValidToken(ctx, owner, "server"); !errors.Is(err, oauth.ErrRefreshUncertain) {
						t.Fatalf("malformed response permitted reuse: %v", err)
					}
				}
			} else {
				want := "old-refresh"
				if tc.name == "replacement-refresh" {
					want = "new-refresh"
				}
				if err != nil || token.AccessToken != "new-access" || token.RefreshToken != want {
					t.Fatalf("valid response: err=%v", err)
				}
				rec, err := b.LookupToken(ctx, owner, "server")
				if err != nil {
					t.Fatal(err)
				}
				stored, err := oauth.PlainOpen(rec.Ciphertext)
				if err != nil || stored.RefreshToken != want || stored.AccessToken != "new-access" {
					t.Fatal("incorrect stored credentials")
				}
				cached, err := second.ValidToken(ctx, owner, "server")
				if err != nil || cached.RefreshToken != want {
					t.Fatalf("ready token unavailable: %v", err)
				}
			}
			if posts.Load() != 1 || oldPosts.Load() != 1 {
				t.Fatalf("unexpected replay: total POSTs=%d old-token POSTs=%d", posts.Load(), oldPosts.Load())
			}
		})
	}
}
