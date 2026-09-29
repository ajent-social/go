package humanauth_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ajent-social/go/humanauth"
	"github.com/ajent-social/go/humanauth/memory"
	mlmemory "github.com/ajent-social/go/magiclink/memory"
	pkmemory "github.com/ajent-social/go/passkey/memory"
)

type stubMailer struct{}

func (stubMailer) SendMagicLink(context.Context, string, string) error { return nil }

func TestNewValidatesConfig(t *testing.T) {
	good := func() (humanauth.Config, humanauth.Deps) {
		return humanauth.Config{
				PublicURL:     "https://app.example",
				RPDisplayName: "Example App",
			}, humanauth.Deps{
				Sessions:   memory.New(),
				MagicLinks: mlmemory.New(),
				Mailer:     stubMailer{},
				Passkeys:   pkmemory.New(),
				Policy:     &fakePolicy{},
			}
	}
	if _, err := humanauth.New(good()); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for _, ok := range []string{"http://localhost", "http://localhost:8080", "http://127.0.0.1:9000", "http://[::1]:8080"} {
		cfg, d := good()
		cfg.PublicURL = ok
		cfg.CookieName = "session"
		if _, err := humanauth.New(cfg, d); err != nil {
			t.Errorf("%s rejected: %v", ok, err)
		}
	}

	tests := []struct {
		name  string
		field string
		edit  func(*humanauth.Config, *humanauth.Deps)
	}{
		{"http non-local", "PublicURL", func(c *humanauth.Config, _ *humanauth.Deps) { c.PublicURL = "http://app.example"; c.CookieName = "s" }},
		{"no scheme", "PublicURL", func(c *humanauth.Config, _ *humanauth.Deps) { c.PublicURL = "app.example" }},
		{"empty", "PublicURL", func(c *humanauth.Config, _ *humanauth.Deps) { c.PublicURL = "" }},
		{"ftp", "PublicURL", func(c *humanauth.Config, _ *humanauth.Deps) { c.PublicURL = "ftp://app.example" }},
		{"path", "PublicURL", func(c *humanauth.Config, _ *humanauth.Deps) { c.PublicURL = "https://app.example/app" }},
		{"trailing slash", "PublicURL", func(c *humanauth.Config, _ *humanauth.Deps) { c.PublicURL = "https://app.example/" }},
		{"query", "PublicURL", func(c *humanauth.Config, _ *humanauth.Deps) { c.PublicURL = "https://app.example?x=1" }},
		{"fragment", "PublicURL", func(c *humanauth.Config, _ *humanauth.Deps) { c.PublicURL = "https://app.example#x" }},
		{"userinfo", "PublicURL", func(c *humanauth.Config, _ *humanauth.Deps) { c.PublicURL = "https://u@app.example" }},
		{"prefix no slash", "Prefix", func(c *humanauth.Config, _ *humanauth.Deps) { c.Prefix = "auth" }},
		{"prefix trailing", "Prefix", func(c *humanauth.Config, _ *humanauth.Deps) { c.Prefix = "/auth/" }},
		{"prefix root", "Prefix", func(c *humanauth.Config, _ *humanauth.Deps) { c.Prefix = "/" }},
		{"prefix dotdot", "Prefix", func(c *humanauth.Config, _ *humanauth.Deps) { c.Prefix = "/a/../b" }},
		{"prefix wildcard", "Prefix", func(c *humanauth.Config, _ *humanauth.Deps) { c.Prefix = "/{x}" }},
		{"rp name", "RPDisplayName", func(c *humanauth.Config, _ *humanauth.Deps) { c.RPDisplayName = "" }},
		{"sessions", "Sessions", func(_ *humanauth.Config, d *humanauth.Deps) { d.Sessions = nil }},
		{"magiclinks", "MagicLinks", func(_ *humanauth.Config, d *humanauth.Deps) { d.MagicLinks = nil }},
		{"mailer", "Mailer", func(_ *humanauth.Config, d *humanauth.Deps) { d.Mailer = nil }},
		{"passkeys", "Passkeys", func(_ *humanauth.Config, d *humanauth.Deps) { d.Passkeys = nil }},
		{"policy", "Policy", func(_ *humanauth.Config, d *humanauth.Deps) { d.Policy = nil }},
		{"session ttl high", "SessionTTL", func(c *humanauth.Config, _ *humanauth.Deps) { c.SessionTTL = 91 * 24 * time.Hour }},
		{"session ttl negative", "SessionTTL", func(c *humanauth.Config, _ *humanauth.Deps) { c.SessionTTL = -time.Second }},
		{"magic ttl negative", "MagicLinkTTL", func(c *humanauth.Config, _ *humanauth.Deps) { c.MagicLinkTTL = -time.Second }},
		{"magic ttl high", "MagicLinkTTL", func(c *humanauth.Config, _ *humanauth.Deps) { c.MagicLinkTTL = 2 * time.Hour }},
		{"ceremony ttl negative", "CeremonyTTL", func(c *humanauth.Config, _ *humanauth.Deps) { c.CeremonyTTL = -time.Second }},
		{"ceremony ttl high", "CeremonyTTL", func(c *humanauth.Config, _ *humanauth.Deps) { c.CeremonyTTL = time.Hour }},
		{"after login absolute", "AfterLogin", func(c *humanauth.Config, _ *humanauth.Deps) { c.AfterLogin = "https://evil.example/" }},
		{"after login scheme-relative", "AfterLogin", func(c *humanauth.Config, _ *humanauth.Deps) { c.AfterLogin = "//evil.example" }},
		{"after logout", "AfterLogout", func(c *humanauth.Config, _ *humanauth.Deps) { c.AfterLogout = `/\evil.example` }},
		{"stylesheet", "Stylesheet", func(c *humanauth.Config, _ *humanauth.Deps) { c.Stylesheet = "https://cdn.example/x.css" }},
		{"host cookie on http", "CookieName", func(c *humanauth.Config, _ *humanauth.Deps) { c.PublicURL = "http://localhost:8080" }},
		{"secure cookie on http", "CookieName", func(c *humanauth.Config, _ *humanauth.Deps) {
			c.PublicURL = "http://localhost:8080"
			c.CookieName = "__Secure-s"
		}},
		{"bad cookie name", "CookieName", func(c *humanauth.Config, _ *humanauth.Deps) { c.CookieName = "a b" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, d := good()
			tt.edit(&cfg, &d)
			_, err := humanauth.New(cfg, d)
			if !errors.Is(err, humanauth.ErrInvalid) {
				t.Fatalf("want ErrInvalid, got %v", err)
			}
			if !strings.Contains(err.Error(), tt.field) {
				t.Fatalf("error %q does not name %s", err, tt.field)
			}
		})
	}
}

func TestMagicLinkLogin(t *testing.T) {
	h := newHarness(t)
	token := h.requestLink(h.client, testEmail, "")
	if got, want := h.mailer.Last(t), h.srv.URL+"/auth/magic#"+token; got != want {
		t.Fatalf("link = %q, want %q", got, want)
	}

	resp, body := h.do(h.client, h.newRequest(http.MethodGet, "/auth/magic", "", ""))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /auth/magic = %d", resp.StatusCode)
	}
	if !strings.Contains(body, `<script src="/auth/magic.js"></script>`) {
		t.Fatalf("redeem page lacks script tag:\n%s", body)
	}
	if strings.Contains(body, "<script>") || !strings.Contains(body, `action="/auth/magic"`) || !strings.Contains(body, `name="token"`) {
		t.Fatalf("redeem page shape:\n%s", body)
	}

	before := h.clock.Now()
	resp, _ = h.redeem(h.client, token)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Fatalf("redeem = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	c := findCookie(resp, "__Host-session")
	if c == nil {
		t.Fatal("no session cookie")
	}
	if c.Path != "/" || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Domain != "" || c.MaxAge != 0 {
		t.Fatalf("cookie attributes: %#v", c)
	}
	if want := before.Add(30 * 24 * time.Hour); c.Expires.Sub(want).Abs() > 2*time.Second {
		t.Fatalf("cookie expires %v, want %v", c.Expires, want)
	}
	raw := resp.Header.Values("Set-Cookie")
	if len(raw) != 1 || !strings.Contains(raw[0], "Expires=") {
		t.Fatalf("Set-Cookie: %q", raw)
	}

	sess, err := h.svc.Session(h.browserRequest(h.client, http.MethodGet, "/", "", ""))
	if err != nil {
		t.Fatal(err)
	}
	if sess.Subject != testSubject || sess.Method != humanauth.MethodMagicLink || sess.CSRF == "" {
		t.Fatalf("session: %#v", sess)
	}
	rec, err := h.sessions.Get(context.Background(), digestOf(c.Value))
	if err != nil {
		t.Fatalf("store does not hold sha256(cookie): %v", err)
	}
	if bytes.Contains(rec.TokenDigest[:], []byte(c.Value)) || rec.CSRF == c.Value {
		t.Fatal("cookie value stored")
	}
	list, _ := h.sessions.ListSubject(context.Background(), testSubject.ID)
	if len(list) != 1 {
		t.Fatalf("records: %d", len(list))
	}
}

func TestMagicLinkNoEnumeration(t *testing.T) {
	h := newHarness(t)
	allowed, allowedBody := h.postForm(h.client, "/auth/magic/request", url.Values{"email": {testEmail}})
	if h.mailer.Count() != 1 {
		t.Fatalf("allowed email mails = %d", h.mailer.Count())
	}
	for _, email := range []string{"b@example.com", "", "not-an-email"} {
		refused, refusedBody := h.postForm(h.client, "/auth/magic/request", url.Values{"email": {email}})
		if refused.StatusCode != allowed.StatusCode || refused.Header.Get("Location") != allowed.Header.Get("Location") || refusedBody != allowedBody {
			t.Fatalf("%q distinguishable: %d %q %q vs %d %q %q", email,
				refused.StatusCode, refused.Header.Get("Location"), refusedBody,
				allowed.StatusCode, allowed.Header.Get("Location"), allowedBody)
		}
		if len(refused.Cookies()) != len(allowed.Cookies()) {
			t.Fatalf("%q cookie count differs", email)
		}
	}
	if allowed.StatusCode != http.StatusSeeOther || allowed.Header.Get("Location") != "/auth/magic/sent" {
		t.Fatalf("request response %d %q", allowed.StatusCode, allowed.Header.Get("Location"))
	}
	if h.mailer.Count() != 1 {
		t.Fatalf("mailer called for refused email: %d", h.mailer.Count())
	}

	h.policy.RefuseAdmit(true)
	resp, body := h.postForm(h.client, "/auth/magic/request", url.Values{"email": {testEmail}})
	if resp.StatusCode != allowed.StatusCode || body != allowedBody || h.mailer.Count() != 1 {
		t.Fatalf("admit-refused request distinguishable or mailed: %d %d", resp.StatusCode, h.mailer.Count())
	}
}

func TestMagicLinkSingleUse(t *testing.T) {
	h := newHarness(t)
	token := h.requestLink(h.client, testEmail, "")
	if resp, _ := h.redeem(h.client, token); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("first redeem %d", resp.StatusCode)
	}
	other := h.newClient()
	resp, body := h.redeem(other, token)
	if resp.StatusCode != http.StatusBadRequest || findCookie(resp, "__Host-session") != nil {
		t.Fatalf("second redeem %d cookies=%v", resp.StatusCode, resp.Cookies())
	}
	if !strings.Contains(body, "invalid or") {
		t.Fatalf("generic page expected:\n%s", body)
	}
}

func TestMagicLinkExpired(t *testing.T) {
	h := newHarness(t)
	token := h.requestLink(h.client, testEmail, "")
	h.clock.Advance(15*time.Minute + time.Second)
	resp, _ := h.redeem(h.client, token)
	if resp.StatusCode != http.StatusBadRequest || findCookie(resp, "__Host-session") != nil {
		t.Fatalf("expired redeem %d", resp.StatusCode)
	}
}

func TestMagicLinkAdmitRefused(t *testing.T) {
	h := newHarness(t)
	token := h.requestLink(h.client, testEmail, "")
	h.policy.RefuseAdmit(true)
	resp, _ := h.redeem(h.client, token)
	if resp.StatusCode != http.StatusBadRequest || findCookie(resp, "__Host-session") != nil {
		t.Fatalf("admit-refused redeem %d", resp.StatusCode)
	}
	if list, _ := h.sessions.ListSubject(context.Background(), testSubject.ID); len(list) != 0 {
		t.Fatalf("record created: %#v", list)
	}
}

func TestNextSanitized(t *testing.T) {
	h := newHarness(t, func(c *humanauth.Config) { c.AfterLogin = "/home" })
	cases := map[string]string{
		"/p/1":                 "/p/1",
		"/p/1?q=a&c=%2F":       "/p/1?q=a&c=%2F",
		"//evil.example":       "/home",
		`/\evil`:               "/home",
		"https://evil.example": "/home",
		"javascript:x":         "/home",
		"/a\r\nb":              "/home",
		"/\t/evil.example":     "/home",
		"":                     "/home",
	}
	for next, want := range cases {
		c := h.newClient()
		token := h.requestLink(c, testEmail, next)
		resp, _ := h.redeem(c, token)
		if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != want {
			t.Errorf("next %q → %d %q, want %q", next, resp.StatusCode, resp.Header.Get("Location"), want)
		}
		if want != "/home" {
			if ck := findCookie(resp, "session_next"); ck == nil || ck.MaxAge >= 0 {
				t.Errorf("next %q: _next cookie not cleared", next)
			}
		}
	}
}

func hexOf(d [32]byte) string { return hex.EncodeToString(d[:]) }

func TestNextCookieAttributes(t *testing.T) {
	h := newHarness(t)
	resp, _ := h.postForm(h.client, "/auth/magic/request", url.Values{"email": {testEmail}, "next": {"/p/1"}})
	c := findCookie(resp, "session_next")
	if c == nil {
		t.Fatal("no _next cookie")
	}
	if c.Path != "/auth" || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.MaxAge != int((15*time.Minute).Seconds()) {
		t.Fatalf("_next cookie: %#v", c)
	}
	resp, _ = h.postForm(h.client, "/auth/magic/request", url.Values{"email": {testEmail}, "next": {"//evil.example"}})
	if findCookie(resp, "session_next") != nil {
		t.Fatal("unsafe next stored")
	}
}

func TestCrossOriginRejected(t *testing.T) {
	h := newHarness(t)
	h.signIn(h.client)
	mails := h.mailer.Count()
	ceremonies := len(h.passkeys.Kinds())
	csrf := h.svc.CSRFToken(h.browserRequest(h.client, http.MethodGet, "/", "", ""))

	token := h.requestLinkNoCheck()
	for _, path := range []string{
		"/auth/magic/request",
		"/auth/magic",
		"/auth/passkey/login/begin",
		"/auth/passkey/login/finish",
		"/auth/passkey/register/begin",
		"/auth/passkey/register/finish",
		"/auth/logout",
	} {
		form := url.Values{"email": {testEmail}, "token": {token}, "csrf_token": {csrf}}
		resp, _ := h.do(h.client, h.newRequest(http.MethodPost, path, "application/x-www-form-urlencoded", form.Encode(),
			crossSite, withHeader("X-CSRF-Token", csrf)))
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s cross-site → %d, want 403", path, resp.StatusCode)
		}
		if findCookie(resp, "__Host-session") != nil || findCookie(resp, "session_ceremony") != nil {
			t.Errorf("%s set cookies on cross-site request", path)
		}
	}
	if h.mailer.Count() != mails+1 {
		t.Fatalf("mailer called by cross-site request: %d", h.mailer.Count()-mails)
	}
	if got := len(h.passkeys.Kinds()); got != ceremonies {
		t.Fatalf("ceremony stored by cross-site request: %d", got-ceremonies)
	}
	// The link token survived the cross-site redeem attempt.
	if resp, _ := h.redeem(h.newClient(), token); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("token burned by cross-site redeem: %d", resp.StatusCode)
	}
	// And the session survived the cross-site logout attempt.
	if _, err := h.svc.Session(h.browserRequest(h.client, http.MethodGet, "/", "", "")); err != nil {
		t.Fatalf("session lost: %v", err)
	}
}

// requestLinkNoCheck issues a link with a separate client.
func (h *harness) requestLinkNoCheck() string {
	return h.requestLink(h.newClient(), testEmail, "")
}

func TestSessionExpiry(t *testing.T) {
	h := newHarness(t)
	h.signIn(h.client)
	r := h.browserRequest(h.client, http.MethodGet, "/", "", "")
	if _, err := h.svc.Session(r); err != nil {
		t.Fatal(err)
	}
	digest := digestOf(h.sessionCookie(h.client))
	h.clock.Advance(30*24*time.Hour + time.Second)
	if _, err := h.svc.Session(r); !errors.Is(err, humanauth.ErrNoSession) {
		t.Fatalf("expired session: %v", err)
	}
	if _, err := h.sessions.Get(context.Background(), digest); !errors.Is(err, humanauth.ErrNotFound) {
		t.Fatalf("expired record not deleted: %v", err)
	}
	if h.svc.CSRFToken(r) != "" {
		t.Fatal("CSRF token without session")
	}
}

func TestSessionWithoutCookie(t *testing.T) {
	h := newHarness(t)
	r := h.newRequest(http.MethodGet, "/", "", "")
	if _, err := h.svc.Session(r); !errors.Is(err, humanauth.ErrNoSession) {
		t.Fatalf("no cookie: %v", err)
	}
	r.AddCookie(&http.Cookie{Name: "__Host-session", Value: strings.Repeat("A", 43)})
	if _, err := h.svc.Session(r); !errors.Is(err, humanauth.ErrNoSession) {
		t.Fatalf("unknown cookie: %v", err)
	}
}

func TestCheckCSRF(t *testing.T) {
	h := newHarness(t)
	h.signIn(h.client)
	token := h.svc.CSRFToken(h.browserRequest(h.client, http.MethodGet, "/", "", ""))
	if token == "" {
		t.Fatal("no CSRF token")
	}
	other := h.newClient()
	h.signIn(other)
	otherToken := h.svc.CSRFToken(h.browserRequest(other, http.MethodGet, "/", "", ""))
	if otherToken == "" || otherToken == token {
		t.Fatal("second session token")
	}

	multipartBody := func(field string) (string, string) {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		_ = mw.WriteField("csrf_token", field)
		_ = mw.Close()
		return mw.FormDataContentType(), buf.String()
	}
	mpType, mpBody := multipartBody(token)

	cases := []struct {
		name string
		r    *http.Request
		ok   bool
	}{
		{"GET", h.browserRequest(h.client, http.MethodGet, "/x", "", ""), true},
		{"HEAD", h.browserRequest(h.client, http.MethodHead, "/x", "", ""), true},
		{"POST no token", h.browserRequest(h.client, http.MethodPost, "/x", "", ""), false},
		{"header", h.browserRequest(h.client, http.MethodPost, "/x", "", "", withHeader("X-CSRF-Token", token)), true},
		{"form field", h.browserRequest(h.client, http.MethodPost, "/x", "application/x-www-form-urlencoded", url.Values{"csrf_token": {token}}.Encode()), true},
		{"form field with charset", h.browserRequest(h.client, http.MethodPost, "/x", "application/x-www-form-urlencoded; charset=utf-8", url.Values{"csrf_token": {token}}.Encode()), true},
		{"form field ignored when header present", h.browserRequest(h.client, http.MethodPost, "/x", "application/x-www-form-urlencoded", url.Values{"csrf_token": {token}}.Encode(), withHeader("X-CSRF-Token", "wrong")), false},
		{"multipart field only", h.browserRequest(h.client, http.MethodPost, "/x", mpType, mpBody), false},
		{"multipart with header", h.browserRequest(h.client, http.MethodPost, "/x", mpType, mpBody, withHeader("X-CSRF-Token", token)), true},
		{"other session's token", h.browserRequest(h.client, http.MethodPost, "/x", "", "", withHeader("X-CSRF-Token", otherToken)), false},
		{"cross-site", h.browserRequest(h.client, http.MethodPost, "/x", "", "", withHeader("X-CSRF-Token", token), crossSite), false},
		{"no session", h.newRequest(http.MethodPost, "/x", "", "", withHeader("X-CSRF-Token", token)), false},
	}
	for _, tt := range cases {
		err := h.svc.CheckCSRF(tt.r)
		if tt.ok && err != nil {
			t.Errorf("%s: %v", tt.name, err)
		}
		if !tt.ok && !errors.Is(err, humanauth.ErrCSRF) {
			t.Errorf("%s: want ErrCSRF, got %v", tt.name, err)
		}
	}
}

func TestLogout(t *testing.T) {
	h := newHarness(t, func(c *humanauth.Config) { c.AfterLogout = "/bye" })
	h.signIn(h.client)
	cookie := h.sessionCookie(h.client)
	token := h.svc.CSRFToken(h.browserRequest(h.client, http.MethodGet, "/", "", ""))

	resp, _ := h.postForm(h.client, "/auth/logout", url.Values{})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("logout without CSRF = %d", resp.StatusCode)
	}
	if _, err := h.sessions.Get(context.Background(), digestOf(cookie)); err != nil {
		t.Fatalf("session removed without CSRF: %v", err)
	}

	resp, _ = h.postForm(h.client, "/auth/logout", url.Values{"csrf_token": {token}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/bye" {
		t.Fatalf("logout = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	c := findCookie(resp, "__Host-session")
	if c == nil || c.MaxAge >= 0 || c.Path != "/" {
		t.Fatalf("session cookie not expired: %#v", c)
	}
	if _, err := h.sessions.Get(context.Background(), digestOf(cookie)); !errors.Is(err, humanauth.ErrNotFound) {
		t.Fatalf("record survives: %v", err)
	}
	r := h.newRequest(http.MethodGet, "/", "", "")
	r.AddCookie(&http.Cookie{Name: "__Host-session", Value: cookie})
	if _, err := h.svc.Session(r); !errors.Is(err, humanauth.ErrNoSession) {
		t.Fatalf("Session after logout: %v", err)
	}

	// Without a session, logout clears the cookie and redirects anyway.
	resp, _ = h.postForm(h.newClient(), "/auth/logout", url.Values{})
	if resp.StatusCode != http.StatusSeeOther || findCookie(resp, "__Host-session") == nil {
		t.Fatalf("anonymous logout = %d", resp.StatusCode)
	}
}

func TestSessionsAndRevoke(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	first := h.newClient()
	h.signIn(first)
	h.clock.Advance(time.Minute)
	second := h.newClient()
	h.signIn(second)

	list, err := h.svc.Sessions(ctx, testSubject.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || !list[0].CreatedAt.After(list[1].CreatedAt) {
		t.Fatalf("not newest first: %#v", list)
	}
	for _, s := range list {
		if s.CSRF != "" || s.Subject != testSubject || len(s.ID) != 64 {
			t.Fatalf("listed session: %#v", s)
		}
	}
	secondDigest := digestOf(h.sessionCookie(second))
	if got := list[0].ID; got != hexOf(secondDigest) {
		t.Fatalf("newest id %s", got)
	}

	if err := h.svc.Revoke(ctx, "someone-else", list[0].ID); !errors.Is(err, humanauth.ErrNotFound) {
		t.Fatalf("revoke other subject: %v", err)
	}
	if err := h.svc.Revoke(ctx, testSubject.ID, "zz"); !errors.Is(err, humanauth.ErrNotFound) {
		t.Fatalf("revoke bad id: %v", err)
	}
	if err := h.svc.Revoke(ctx, testSubject.ID, list[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Session(h.browserRequest(second, http.MethodGet, "/", "", "")); !errors.Is(err, humanauth.ErrNoSession) {
		t.Fatalf("revoked session alive: %v", err)
	}
	if _, err := h.svc.Session(h.browserRequest(first, http.MethodGet, "/", "", "")); err != nil {
		t.Fatalf("other session revoked: %v", err)
	}
	if n, err := h.svc.RevokeSubject(ctx, testSubject.ID); err != nil || n != 1 {
		t.Fatalf("RevokeSubject = %d %v", n, err)
	}

	// Sweep deletes only expired records.
	h.signIn(first)
	long := humanauth.Record{
		TokenDigest: digestOf("long-lived"),
		Subject:     testSubject,
		Method:      humanauth.MethodPasskey,
		CSRF:        "x",
		CreatedAt:   h.clock.Now(),
		ExpiresAt:   h.clock.Now().Add(60 * 24 * time.Hour),
	}
	if err := h.sessions.Create(ctx, long); err != nil {
		t.Fatal(err)
	}
	h.clock.Advance(31 * 24 * time.Hour)
	if n, err := h.svc.Sweep(ctx); err != nil || n != 1 {
		t.Fatalf("Sweep = %d %v", n, err)
	}
	if list, _ := h.svc.Sessions(ctx, testSubject.ID); len(list) != 1 || list[0].ID != hexOf(long.TokenDigest) {
		t.Fatalf("after sweep: %#v", list)
	}
}

func TestSignInReplacesBrowserSession(t *testing.T) {
	h := newHarness(t)
	h.signIn(h.client)
	old := h.sessionCookie(h.client)
	h.signIn(h.client)
	if _, err := h.sessions.Get(context.Background(), digestOf(old)); !errors.Is(err, humanauth.ErrNotFound) {
		t.Fatalf("previous browser session kept: %v", err)
	}
}

func TestHandlerHeaders(t *testing.T) {
	h := newHarness(t, func(c *humanauth.Config) { c.Stylesheet = "/static/app.css" })
	routes := []struct{ method, path string }{
		{"POST", "/auth/magic/request"},
		{"GET", "/auth/magic/sent"},
		{"GET", "/auth/magic"},
		{"GET", "/auth/magic.js"},
		{"POST", "/auth/magic"},
		{"GET", "/auth/passkey.js"},
		{"POST", "/auth/passkey/login/begin"},
		{"POST", "/auth/passkey/login/finish"},
		{"POST", "/auth/passkey/register/begin"},
		{"POST", "/auth/passkey/register/finish"},
		{"POST", "/auth/logout"},
		{"GET", "/auth/nope"},
	}
	for _, rt := range routes {
		resp, body := h.do(h.newClient(), h.newRequest(rt.method, rt.path, "application/x-www-form-urlencoded", "x=1"))
		hd := resp.Header
		want := map[string]string{
			"X-Frame-Options":         "DENY",
			"Referrer-Policy":         "no-referrer",
			"Content-Security-Policy": "default-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
			"Cache-Control":           "no-store",
		}
		if strings.HasSuffix(rt.path, ".js") {
			want["Cache-Control"] = "public, max-age=3600"
			if ct := hd.Get("Content-Type"); !strings.HasPrefix(ct, "text/javascript") {
				t.Errorf("%s content type %q", rt.path, ct)
			}
		}
		for k, v := range want {
			if got := hd.Get(k); got != v {
				t.Errorf("%s %s: %s = %q, want %q", rt.method, rt.path, k, got, v)
			}
		}
		if strings.Contains(hd.Get("Content-Type"), "text/html") {
			if strings.Contains(body, "<script>") || strings.Contains(body, "<script type") || strings.Contains(body, "style=") || strings.Contains(body, "<style") {
				t.Errorf("%s inline script or style:\n%s", rt.path, body)
			}
			if strings.Contains(body, "<script") && !strings.Contains(body, "<script src=") {
				t.Errorf("%s script without src", rt.path)
			}
			if strings.Contains(body, "<html") && !strings.Contains(body, `<link rel="stylesheet" href="/static/app.css">`) {
				t.Errorf("%s missing stylesheet link", rt.path)
			}
		}
	}
}

func TestPaths(t *testing.T) {
	h := newHarness(t, func(c *humanauth.Config) { c.Prefix = "/account/auth" })
	want := []string{
		"/account/auth/logout",
		"/account/auth/magic",
		"/account/auth/magic.js",
		"/account/auth/magic/request",
		"/account/auth/magic/sent",
		"/account/auth/passkey.js",
		"/account/auth/passkey/login/begin",
		"/account/auth/passkey/login/finish",
		"/account/auth/passkey/register/begin",
		"/account/auth/passkey/register/finish",
	}
	got := h.svc.Paths()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("Paths =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, p := range got {
		resp, _ := h.do(h.newClient(), h.newRequest(http.MethodGet, p, "", ""))
		if resp.StatusCode == http.StatusNotFound {
			t.Errorf("%s not served", p)
		}
	}
}
