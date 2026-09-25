package github_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ajent-social/go/oidc"
	"github.com/ajent-social/go/oidc/github"
	"github.com/ajent-social/go/oidc/memory"
)

func TestGitHubFlow(t *testing.T) {
	ctx := context.Background()
	mux := http.NewServeMux()
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "ghat"})
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id": 42, "login": "octo", "name": "Octo"})
	})
	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"email": "u@example.com", "primary": true, "verified": true},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	svc, err := github.New(github.Config{
		ClientID: "cid", ClientSecret: "sec",
		RedirectURI: "http://127.0.0.1/cb",
		AuthURL: srv.URL + "/login/oauth/authorize",
		TokenURL: srv.URL + "/login/oauth/access_token",
		UserURL: srv.URL + "/user", EmailURL: srv.URL + "/user/emails",
		HTTPClient: srv.Client(),
	}, memory.New())
	if err != nil {
		t.Fatal(err)
	}
	start, err := svc.Start(ctx)
	if err != nil || !strings.Contains(start.AuthURL, "client_id=cid") {
		t.Fatalf("%#v %v", start, err)
	}
	id, err := svc.Accept(ctx, start.State, "code")
	if err != nil || id.Subject != "42" || id.Email != "u@example.com" || !id.EmailVerified {
		t.Fatalf("%#v %v", id, err)
	}
	if err := svc.LinkBinding(ctx, id.Subject, "acct1"); err != nil {
		t.Fatal(err)
	}
	if err := svc.LinkBinding(ctx, id.Subject, "acct2"); !errors.Is(err, oidc.ErrExists) {
		t.Fatalf("got %v", err)
	}
}

func TestRejectsBadRedirect(t *testing.T) {
	_, err := github.New(github.Config{
		ClientID: "c", ClientSecret: "s", RedirectURI: "http://evil.example/cb",
	}, memory.New())
	if !errors.Is(err, oidc.ErrInvalid) {
		t.Fatalf("got %v", err)
	}
}
