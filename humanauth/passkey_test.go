package humanauth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ajent-social/go/humanauth"
	"github.com/ajent-social/go/humanauth/internal/testauthn"
	"github.com/ajent-social/go/passkey"
)

func (h *harness) csrf(c *http.Client) string {
	h.t.Helper()
	return h.svc.CSRFToken(h.browserRequest(c, http.MethodGet, "/", "", ""))
}

func (h *harness) postJSON(c *http.Client, path, body string, opts ...reqOpt) (*http.Response, string) {
	h.t.Helper()
	return h.do(c, h.newRequest(http.MethodPost, path, "application/json", body, opts...))
}

// registerPasskey runs register/begin → authenticator → register/finish.
func (h *harness) registerPasskey(c *http.Client, a *testauthn.Authenticator) {
	h.t.Helper()
	csrf := withHeader("X-CSRF-Token", h.csrf(c))
	resp, opts := h.postJSON(c, "/auth/passkey/register/begin", "{}", csrf)
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("register/begin %d: %s", resp.StatusCode, opts)
	}
	cer := findCookie(resp, "session_ceremony")
	if cer == nil || cer.Path != "/auth/passkey" || !cer.HttpOnly || !cer.Secure || cer.SameSite != http.SameSiteStrictMode || cer.MaxAge != 300 {
		h.t.Fatalf("ceremony cookie: %#v", cer)
	}
	cred, err := a.Create([]byte(opts))
	if err != nil {
		h.t.Fatal(err)
	}
	resp, body := h.postJSON(c, "/auth/passkey/register/finish", string(cred), csrf)
	if resp.StatusCode != http.StatusNoContent {
		h.t.Fatalf("register/finish %d: %s", resp.StatusCode, body)
	}
	if ck := findCookie(resp, "session_ceremony"); ck == nil || ck.MaxAge >= 0 {
		h.t.Fatal("ceremony cookie not cleared")
	}
}

// loginBegin runs login/begin and returns the options JSON.
func (h *harness) loginBegin(c *http.Client) string {
	h.t.Helper()
	resp, opts := h.postJSON(c, "/auth/passkey/login/begin", "{}")
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("login/begin %d: %s", resp.StatusCode, opts)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		h.t.Fatalf("login/begin content type %q", resp.Header.Get("Content-Type"))
	}
	return opts
}

func TestPasskeyRegisterThenLogin(t *testing.T) {
	h := newHarness(t)
	a, err := testauthn.New(h.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	h.signIn(h.client)

	h.registerPasskey(h.client, a)
	if kinds := h.passkeys.Kinds(); len(kinds) != 1 || kinds[0] != passkey.KindRegister {
		t.Fatalf("first ceremony kinds %v", kinds)
	}
	if n, _ := h.passkeys.CountCredentials(context.Background(), testSubject.ID); n != 1 {
		t.Fatalf("credentials = %d", n)
	}
	h.registerPasskey(h.client, a)
	if kinds := h.passkeys.Kinds(); len(kinds) != 2 || kinds[1] != passkey.KindAdd {
		t.Fatalf("second ceremony kinds %v", kinds)
	}

	fresh := h.newClient()
	opts := h.loginBegin(fresh)
	assertion, err := a.Get([]byte(opts))
	if err != nil {
		t.Fatal(err)
	}
	resp, body := h.postJSON(fresh, "/auth/passkey/login/finish", string(assertion))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login/finish %d: %s", resp.StatusCode, body)
	}
	var out struct{ Redirect string }
	if err := json.Unmarshal([]byte(body), &out); err != nil || out.Redirect != "/" {
		t.Fatalf("finish body %q", body)
	}
	sess, err := h.svc.Session(h.browserRequest(fresh, http.MethodGet, "/", "", ""))
	if err != nil {
		t.Fatal(err)
	}
	if sess.Subject != testSubject || sess.Method != humanauth.MethodPasskey {
		t.Fatalf("passkey session %#v", sess)
	}
}

func TestPasskeyCeremonyConsumed(t *testing.T) {
	h := newHarness(t)
	a, err := testauthn.New(h.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	h.signIn(h.client)
	h.registerPasskey(h.client, a)

	fresh := h.newClient()
	opts := h.loginBegin(fresh)
	var handle string
	for _, ck := range fresh.Jar.Cookies(mustURL(t, h.srv.URL+"/auth/passkey/login/finish")) {
		if ck.Name == "session_ceremony" {
			handle = ck.Value
		}
	}
	if handle == "" {
		t.Fatal("no ceremony cookie in jar")
	}
	resp, body := h.postJSON(fresh, "/auth/passkey/login/finish", `{"garbage":true}`)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "passkey sign-in failed") {
		t.Fatalf("garbage finish %d: %s", resp.StatusCode, body)
	}

	// Replay the same ceremony cookie with a valid assertion.
	assertion, err := a.Get([]byte(opts))
	if err != nil {
		t.Fatal(err)
	}
	replay := h.newClient()
	r := h.newRequest(http.MethodPost, "/auth/passkey/login/finish", "application/json", string(assertion))
	r.AddCookie(&http.Cookie{Name: "session_ceremony", Value: handle})
	resp, _ = h.do(replay, r)
	if resp.StatusCode != http.StatusBadRequest || findCookie(resp, "__Host-session") != nil {
		t.Fatalf("replay %d", resp.StatusCode)
	}
	if list, _ := h.sessions.ListSubject(context.Background(), testSubject.ID); len(list) != 1 {
		t.Fatalf("sessions = %d, want only the magic-link one", len(list))
	}

	// Oversized body is refused.
	h.loginBegin(fresh)
	resp, _ = h.postJSON(fresh, "/auth/passkey/login/finish", `{"x":"`+strings.Repeat("a", 70<<10)+`"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized finish %d", resp.StatusCode)
	}
}

func TestPasskeyRegisterRequiresSession(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{"/auth/passkey/register/begin", "/auth/passkey/register/finish"} {
		resp, _ := h.postJSON(h.newClient(), path, "{}")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s without session = %d", path, resp.StatusCode)
		}
	}
	h.signIn(h.client)
	for _, path := range []string{"/auth/passkey/register/begin", "/auth/passkey/register/finish"} {
		resp, _ := h.postJSON(h.client, path, "{}")
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s without CSRF = %d", path, resp.StatusCode)
		}
		resp, _ = h.postJSON(h.client, path, "{}", withHeader("X-CSRF-Token", "wrong"))
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s with wrong CSRF = %d", path, resp.StatusCode)
		}
	}
	if kinds := h.passkeys.Kinds(); len(kinds) != 0 {
		t.Fatalf("ceremonies stored: %v", kinds)
	}
}

func TestPasskeyAdmitRefused(t *testing.T) {
	h := newHarness(t)
	a, err := testauthn.New(h.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	h.signIn(h.client)
	h.registerPasskey(h.client, a)
	h.policy.RefuseAdmit(true)

	fresh := h.newClient()
	assertion, err := a.Get([]byte(h.loginBegin(fresh)))
	if err != nil {
		t.Fatal(err)
	}
	resp, body := h.postJSON(fresh, "/auth/passkey/login/finish", string(assertion))
	if resp.StatusCode != http.StatusBadRequest || findCookie(resp, "__Host-session") != nil {
		t.Fatalf("admit-refused finish %d: %s", resp.StatusCode, body)
	}
	if list, _ := h.sessions.ListSubject(context.Background(), testSubject.ID); len(list) != 1 {
		t.Fatalf("sessions = %d, want only the magic-link one", len(list))
	}
}
