package mcpclientoauth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	oauth "github.com/ajent-social/go/mcpclientoauth"
	"github.com/ajent-social/go/mcpclientoauth/memory"
)

func config(endpoint string) oauth.Config {
	return oauth.Config{Servers: []oauth.ServerConfig{{ID: "server", AuthURL: endpoint + "/auth", TokenURL: endpoint + "/token", RevokeURL: endpoint + "/revoke", ClientID: "client", ClientSecret: "client-secret", RedirectURL: "http://127.0.0.1/cb"}}}
}
func service(t *testing.T, cfg oauth.Config, store oauth.Store) *oauth.Service {
	t.Helper()
	s, err := oauth.New(cfg, store, oauth.PlainSeal, oauth.PlainOpen)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCredentialPOSTRedirectsDenied(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		for _, operation := range []string{"code", "refresh", "revoke"} {
			t.Run(strconv.Itoa(status)+"/"+operation, func(t *testing.T) {
				var collected, posted atomic.Int32
				collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { collected.Add(1) }))
				defer collector.Close()
				endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					posted.Add(1)
					if err := r.ParseForm(); err != nil {
						t.Error(err)
					}
					if r.Form.Get("client_secret") != "client-secret" {
						t.Error("test did not submit credentials")
					}
					http.Redirect(w, r, collector.URL+"/capture", status)
				}))
				defer endpoint.Close()
				client := endpoint.Client() // retains this test's trusted TLS transport
				originalRedirect := func(*http.Request, []*http.Request) error { t.Error("caller redirect policy invoked"); return nil }
				client.CheckRedirect = originalRedirect
				client.Timeout = 0
				cfg := config(endpoint.URL)
				cfg.HTTPClient = client
				store := memory.New()
				svc := service(t, cfg, store)
				ctx := context.Background()
				if operation == "code" {
					start, err := svc.Start(ctx, "owner", "server")
					if err != nil {
						t.Fatal(err)
					}
					if err := svc.Exchange(ctx, oauth.ExchangeInput{OwnerID: "owner", State: start.State, Code: "code-secret"}); err == nil {
						t.Fatal("redirect accepted")
					}
				} else {
					if err := store.BeginConnection(ctx, "owner", "server", "generation"); err != nil {
						t.Fatal(err)
					}
					ct, _ := oauth.PlainSeal(oauth.TokenSecrets{AccessToken: "access-secret", RefreshToken: "refresh-secret"})
					if err := store.CompleteToken(ctx, oauth.TokenRecord{OwnerID: "owner", ServerID: "server", Generation: "generation", Ciphertext: ct, ExpiresAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
						t.Fatal(err)
					}
					if operation == "refresh" {
						if _, err := svc.ValidToken(ctx, "owner", "server"); err == nil {
							t.Fatal("redirect accepted")
						}
					} else {
						if err := svc.Revoke(ctx, "owner", "server"); err != nil {
							t.Fatal(err)
						}
					}
				}
				if posted.Load() != 1 || collected.Load() != 0 {
					t.Fatalf("posts=%d collector=%d", posted.Load(), collected.Load())
				}
				if client.Timeout != 0 || client.CheckRedirect == nil {
					t.Fatal("caller client mutated")
				}
			})
		}
	}
}

func TestResourceValidationAndAuthorization(t *testing.T) {
	for _, raw := range []string{"http://remote.example/mcp", "https://user:pass@resource.example/mcp", "https://resource.example/mcp#fragment", "https://resource.example/mcp#", "https://RESOURCE.example/mcp", "https://resource.example:443/mcp", "https://resource.example/a/../mcp", "https://resource.example/%2e%2e/mcp", "relative"} {
		cfg := config("https://issuer.example")
		cfg.Servers[0].Resource = raw
		if _, err := oauth.New(cfg, memory.New(), oauth.PlainSeal, oauth.PlainOpen); !errors.Is(err, oauth.ErrInvalid) {
			t.Errorf("resource %q: %v", raw, err)
		}
	}
	cfg := config("https://issuer.example")
	cfg.Servers[0].Resource = "https://resource.example/mcp"
	s := service(t, cfg, memory.New())
	start, err := s.Start(context.Background(), "owner", "server")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(start.AuthURL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("resource") != cfg.Servers[0].Resource {
		t.Fatal("authorization audience missing")
	}
	// Empty audience remains supported for explicitly generic OAuth callers.
	cfg.Servers[0].Resource = ""
	service(t, cfg, memory.New())
}

func TestExpectedIssuerBeforeCodePOST(t *testing.T) {
	for _, issuer := range []string{"", "https://foreign.example", "https://issuer.example"} {
		t.Run("issuer="+issuer, func(t *testing.T) {
			var posts atomic.Int32
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				posts.Add(1)
				_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
			}))
			defer endpoint.Close()
			cfg := config(endpoint.URL)
			cfg.Servers[0].ExpectedIssuer = "https://issuer.example"
			svc := service(t, cfg, memory.New())
			start, err := svc.Start(context.Background(), "owner", "server")
			if err != nil {
				t.Fatal(err)
			}
			err = svc.Exchange(context.Background(), oauth.ExchangeInput{OwnerID: "owner", State: start.State, Code: "code", Issuer: issuer})
			if issuer == cfg.Servers[0].ExpectedIssuer {
				if err != nil || posts.Load() != 1 {
					t.Fatalf("matching issuer: %v", err)
				}
			} else if !errors.Is(err, oauth.ErrDenied) || posts.Load() != 0 {
				t.Fatalf("issuer accepted or posted: %v posts=%d", err, posts.Load())
			}
		})
	}
}

// Embedding only the original contract intentionally hides lifecycle capability.
type legacyStore struct{ oauth.Store }

func TestUnsupportedStoreFailsClosed(t *testing.T) {
	_, err := oauth.New(config("https://issuer.example"), legacyStore{memory.New()}, oauth.PlainSeal, oauth.PlainOpen)
	if !errors.Is(err, oauth.ErrUnsupportedStore) {
		t.Fatalf("unsupported: %v", err)
	}
	if err := memory.New().PutToken(context.Background(), oauth.TokenRecord{}); !errors.Is(err, oauth.ErrUnsupportedStore) {
		t.Fatalf("unconditional write: %v", err)
	}
}
