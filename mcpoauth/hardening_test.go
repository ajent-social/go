package mcpoauth_test

import (
	"context"
	"errors"
	"github.com/ajent-social/go/mcpoauth"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEmptyApprovalRequiresExplicitConsent(t *testing.T) {
	f := newFixture(t, mcpoauth.Config{})
	f.authorize(nil)
	if _, err := f.srv.Approve(context.Background(), f.handle, mcpoauth.Approval{Subject: "u"}); !errors.Is(err, mcpoauth.ErrInvalid) {
		t.Fatalf("empty approval: %v", err)
	}
	if _, err := f.srv.Consent(context.Background(), f.handle); err != nil {
		t.Fatal("invalid approval consumed request")
	}
}
func TestStoredEmptyScopesFailClosed(t *testing.T) {
	for _, kind := range []string{"code", "token", "grant"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t, mcpoauth.Config{})
			code := f.issueCode(mcpoauth.Approval{Subject: "u", Scopes: []string{"read"}})
			if kind == "code" {
				for id, r := range f.store.codes {
					r.Scopes = nil
					f.store.codes[id] = r
				}
				oauthErr(t, f.exchange(code, nil), 400, "invalid_grant")
				return
			}
			_, body := f.exchangeBody(code, nil)
			raw := body["access_token"].(string)
			if kind == "token" {
				for id, r := range f.store.tokens {
					r.Scopes = nil
					f.store.tokens[id] = r
				}
			} else {
				for id, r := range f.store.grants {
					r.Scopes = nil
					f.store.grants[id] = r
				}
			}
			if _, err := f.srv.Verify(context.Background(), raw); !errors.Is(err, mcpoauth.ErrDenied) {
				t.Fatalf("empty stored %s accepted: %v", kind, err)
			}
		})
	}
}
func TestStoredConsentCannotCreateOpenRedirect(t *testing.T) {
	for _, deny := range []bool{false, true} {
		f := newFixture(t, mcpoauth.Config{})
		f.authorize(nil)
		for id, r := range f.store.consents {
			r.RedirectURI = "https://attacker.example/callback"
			f.store.consents[id] = r
		}
		var target string
		var err error
		if deny {
			target, err = f.srv.Deny(context.Background(), f.handle)
		} else {
			target, err = f.srv.Approve(context.Background(), f.handle, mcpoauth.Approval{Subject: "u", Scopes: []string{"read"}})
		}
		if err == nil || target != "" {
			t.Fatal("stored redirect was trusted without registration")
		}
	}
}
func TestMalformedAuthorizeQueryIsNotDropped(t *testing.T) {
	f := newFixture(t, mcpoauth.Config{})
	for _, suffix := range []string{"&scope=%zz", "&resource=%zz", "&ignored=a;b"} {
		rr := f.do(httptest.NewRequest(http.MethodGet, f.authorizeURL(nil)+suffix, nil))
		if rr.Code != 400 || rr.Header().Get("Location") != "" {
			t.Fatalf("malformed query: %d %s", rr.Code, rr.Header().Get("Location"))
		}
	}
}

func TestDuplicateRegistrationFieldsAreRejected(t *testing.T) {
	f := newFixture(t, mcpoauth.Config{})
	req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(`{"client_name":"first","client_name":"second","redirect_uris":["https://client.example/callback"]}`))
	req.Header.Set("Content-Type", "application/json")
	oauthErr(t, f.do(req), 400, "invalid_client_metadata")
}

func TestLocalhostCallbackRequiresExplicitCompatibilityPolicy(t *testing.T) {
	f := newFixture(t, mcpoauth.Config{Issuer: issuer, Resource: resource, Scopes: []string{"read"}, AllowLocalhostRedirects: true})
	for uri, want := range map[string]int{
		"http://localhost:8080/callback":           201,
		"http://localhost/callback":                400,
		"http://localhost:0/callback":              400,
		"http://localhost:65536/callback":          400,
		"http://LOCALHOST:8080/callback":           400,
		"http://localhost.:8080/callback":          400,
		"http://localhost.evil.test:8080/callback": 400,
		"http://evil.localhost:8080/callback":      400,
		"http://user@localhost:8080/callback":      400,
		"http://127.0.0.1:8080/callback":           400,
	} {
		req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(`{"redirect_uris":["`+uri+`"]}`))
		if got := f.do(req).Code; got != want {
			t.Errorf("%s: got %d want %d", uri, got, want)
		}
	}
	c := mcpoauth.Client{ID: "localhost-client", Name: "Local client", RedirectURIs: []string{"http://localhost:8080/callback"}}
	if err := f.store.CreateClient(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	f.client = c
	if rr := f.authorize(map[string]string{"redirect_uri": c.RedirectURIs[0], "scope": "read"}); rr.Code != 200 {
		t.Fatalf("authorize: %d %s", rr.Code, rr.Body)
	}
	if rr := f.authorize(map[string]string{"redirect_uri": "http://localhost:8081/callback", "scope": "read"}); rr.Code != 400 {
		t.Fatalf("changed port: %d", rr.Code)
	}
	if _, err := mcpoauth.New(mcpoauth.Config{Issuer: "http://localhost:8080", Resource: resource, Scopes: []string{"read"}, AllowLocalhostRedirects: true}, f.store); err == nil {
		t.Fatal("callback option weakened issuer policy")
	}
}
