package mcpclientoauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ajent-social/go/mcpclientoauth"
	"github.com/ajent-social/go/mcpclientoauth/memory"
)

func TestRejectsHTTPRedirect(t *testing.T) {
	_, err := mcpclientoauth.New(mcpclientoauth.Config{
		Servers: []mcpclientoauth.ServerConfig{{
			ID: "s", AuthURL: "https://idp.example/auth", TokenURL: "https://idp.example/token",
			ClientID: "c", RedirectURL: "http://evil.example/cb",
		}},
	}, memory.New(), mcpclientoauth.PlainSeal, mcpclientoauth.PlainOpen)
	if !errors.Is(err, mcpclientoauth.ErrInvalid) {
		t.Fatalf("got %v", err)
	}
}

func TestStartExchangeRefreshRevoke(t *testing.T) {
	ctx := context.Background()
	var sawRefresh bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		switch {
		case strings.HasSuffix(r.URL.Path, "/token") && r.Form.Get("grant_type") == "authorization_code":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "at1", "refresh_token": "rt1", "expires_in": 60, "token_type": "Bearer",
			})
		case strings.HasSuffix(r.URL.Path, "/token") && r.Form.Get("grant_type") == "refresh_token":
			sawRefresh = true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "at2", "refresh_token": "rt2", "expires_in": 3600, "token_type": "Bearer",
			})
		case strings.HasSuffix(r.URL.Path, "/revoke"):
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	store := memory.New()
	svc, err := mcpclientoauth.New(mcpclientoauth.Config{
		Servers: []mcpclientoauth.ServerConfig{{
			ID: "mcp1", AuthURL: srv.URL + "/auth", TokenURL: srv.URL + "/token",
			RevokeURL: srv.URL + "/revoke", ClientID: "cid",
			RedirectURL: "http://127.0.0.1:8080/cb", Scopes: []string{"tools"},
		}},
		// expires_in=60s from mock; margin 2m forces refresh on ValidToken
		RefreshMargin: 2 * time.Minute,
		HTTPClient:    srv.Client(),
	}, store, mcpclientoauth.PlainSeal, mcpclientoauth.PlainOpen)
	if err != nil {
		t.Fatal(err)
	}
	start, err := svc.Start(ctx, "owner1", "mcp1")
	if err != nil || start.State == "" || !strings.Contains(start.AuthURL, "code_challenge") {
		t.Fatalf("%#v %v", start, err)
	}
	u, _ := url.Parse(start.AuthURL)
	if u.Query().Get("code_challenge_method") != "S256" {
		t.Fatal("expected S256")
	}
	if err := svc.Exchange(ctx, mcpclientoauth.ExchangeInput{
		OwnerID: "owner1", State: start.State, Code: "code1",
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Exchange(ctx, mcpclientoauth.ExchangeInput{
		OwnerID: "owner1", State: start.State, Code: "code1",
	}); !errors.Is(err, mcpclientoauth.ErrNotFound) {
		t.Fatalf("replay: %v", err)
	}
	tok, err := svc.ValidToken(ctx, "owner1", "mcp1")
	if err != nil || tok.AccessToken != "at2" || !sawRefresh {
		t.Fatalf("%#v refresh=%v err=%v", tok, sawRefresh, err)
	}
	if err := svc.Revoke(ctx, "owner1", "mcp1"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ValidToken(ctx, "owner1", "mcp1"); !errors.Is(err, mcpclientoauth.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}
