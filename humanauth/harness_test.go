package humanauth_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ajent-social/go/humanauth"
	"github.com/ajent-social/go/humanauth/memory"
	"github.com/ajent-social/go/passkey"
	pkmemory "github.com/ajent-social/go/passkey/memory"

	mlmemory "github.com/ajent-social/go/magiclink/memory"
)

const testEmail = "a@example.com"

var testSubject = humanauth.Subject{ID: "subj-a", Name: testEmail, DisplayName: "Example Person"}

// clock is a settable time source.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fakeMailer captures issued links.
type fakeMailer struct {
	mu   sync.Mutex
	urls []string
	err  error
}

func (m *fakeMailer) SendMagicLink(_ context.Context, _, url string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.urls = append(m.urls, url)
	return m.err
}

func (m *fakeMailer) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.urls)
}

func (m *fakeMailer) Last(t *testing.T) string {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.urls) == 0 {
		t.Fatal("no mail sent")
	}
	return m.urls[len(m.urls)-1]
}

// fakePolicy allows only testEmail and can be switched to refuse Admit.
type fakePolicy struct {
	mu          sync.Mutex
	refuseAdmit bool
}

func (p *fakePolicy) SubjectForEmail(_ context.Context, email string) (humanauth.Subject, error) {
	if email != testEmail {
		return humanauth.Subject{}, errors.New("not allowed")
	}
	return testSubject, nil
}

func (p *fakePolicy) Admit(_ context.Context, subjectID string) (humanauth.Subject, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.refuseAdmit || subjectID != testSubject.ID {
		return humanauth.Subject{}, errors.New("disabled")
	}
	return testSubject, nil
}

func (p *fakePolicy) RefuseAdmit(v bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refuseAdmit = v
}

// recordingPasskeys records the Kind of every stored ceremony.
type recordingPasskeys struct {
	*pkmemory.Store
	mu    sync.Mutex
	kinds []passkey.Kind
}

func (r *recordingPasskeys) PutCeremony(ctx context.Context, c passkey.Ceremony) error {
	r.mu.Lock()
	r.kinds = append(r.kinds, c.Kind)
	r.mu.Unlock()
	return r.Store.PutCeremony(ctx, c)
}

func (r *recordingPasskeys) Kinds() []passkey.Kind {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]passkey.Kind(nil), r.kinds...)
}

type harness struct {
	t        *testing.T
	srv      *httptest.Server
	svc      *humanauth.Service
	sessions *memory.Store
	passkeys *recordingPasskeys
	mailer   *fakeMailer
	policy   *fakePolicy
	clock    *clock
	client   *http.Client
}

func newHarness(t *testing.T, mutate ...func(*humanauth.Config)) *harness {
	t.Helper()
	h := &harness{
		t:        t,
		sessions: memory.New(),
		passkeys: &recordingPasskeys{Store: pkmemory.New()},
		mailer:   &fakeMailer{},
		policy:   &fakePolicy{},
		clock:    &clock{t: time.Now().UTC()},
	}
	var handler http.Handler = http.NotFoundHandler()
	var mu sync.RWMutex
	h.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		hd := handler
		mu.RUnlock()
		hd.ServeHTTP(w, r)
	}))
	t.Cleanup(h.srv.Close)
	cfg := humanauth.Config{
		PublicURL:     h.srv.URL,
		RPDisplayName: "Example App",
		Now:           h.clock.Now,
	}
	for _, m := range mutate {
		m(&cfg)
	}
	svc, err := humanauth.New(cfg, humanauth.Deps{
		Sessions:   h.sessions,
		MagicLinks: mlmemory.New(),
		Mailer:     h.mailer,
		Passkeys:   h.passkeys,
		Policy:     h.policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.svc = svc
	mu.Lock()
	handler = svc.Handler()
	mu.Unlock()
	h.client = h.newClient()
	return h
}

// newClient returns a client with a fresh cookie jar that does not follow redirects.
func (h *harness) newClient() *http.Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		h.t.Fatal(err)
	}
	c := h.srv.Client()
	return &http.Client{
		Transport: c.Transport,
		Jar:       jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type reqOpt func(*http.Request)

func crossSite(r *http.Request) {
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	r.Header.Set("Origin", "https://evil.example")
}

func withHeader(k, v string) reqOpt { return func(r *http.Request) { r.Header.Set(k, v) } }

// newRequest builds a same-origin browser request against the test server.
func (h *harness) newRequest(method, path, contentType, body string, opts ...reqOpt) *http.Request {
	h.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r, err := http.NewRequest(method, h.srv.URL+path, rd)
	if err != nil {
		h.t.Fatal(err)
	}
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	if method != http.MethodGet && method != http.MethodHead {
		r.Header.Set("Origin", h.srv.URL)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

func (h *harness) do(c *http.Client, r *http.Request) (*http.Response, string) {
	h.t.Helper()
	resp, err := c.Do(r)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp, string(b)
}

func (h *harness) postForm(c *http.Client, path string, form url.Values, opts ...reqOpt) (*http.Response, string) {
	h.t.Helper()
	return h.do(c, h.newRequest(http.MethodPost, path, "application/x-www-form-urlencoded", form.Encode(), opts...))
}

// requestLink asks for a magic link and returns the token from the mailed URL.
func (h *harness) requestLink(c *http.Client, email, next string) string {
	h.t.Helper()
	form := url.Values{"email": {email}}
	if next != "" {
		form.Set("next", next)
	}
	resp, _ := h.postForm(c, "/auth/magic/request", form)
	if resp.StatusCode != http.StatusSeeOther {
		h.t.Fatalf("request status %d", resp.StatusCode)
	}
	link := h.mailer.Last(h.t)
	_, token, ok := strings.Cut(link, "#")
	if !ok || token == "" {
		h.t.Fatalf("link without fragment token: %q", link)
	}
	return token
}

func (h *harness) redeem(c *http.Client, token string) (*http.Response, string) {
	h.t.Helper()
	return h.postForm(c, "/auth/magic", url.Values{"token": {token}})
}

// signIn performs a full magic-link sign-in with client c.
func (h *harness) signIn(c *http.Client) {
	h.t.Helper()
	resp, body := h.redeem(c, h.requestLink(c, testEmail, ""))
	if resp.StatusCode != http.StatusSeeOther {
		h.t.Fatalf("redeem status %d: %s", resp.StatusCode, body)
	}
}

// sessionCookie returns the session cookie value held by c's jar.
func (h *harness) sessionCookie(c *http.Client) string {
	h.t.Helper()
	u, _ := url.Parse(h.srv.URL + "/")
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == "__Host-session" {
			return ck.Value
		}
	}
	return ""
}

// browserRequest returns a request carrying c's cookies, for calling Service
// methods directly.
func (h *harness) browserRequest(c *http.Client, method, path, contentType, body string, opts ...reqOpt) *http.Request {
	h.t.Helper()
	r := h.newRequest(method, path, contentType, body, opts...)
	for _, ck := range c.Jar.Cookies(r.URL) {
		r.AddCookie(ck)
	}
	return r
}

func digestOf(v string) [32]byte { return sha256.Sum256([]byte(v)) }

func findCookie(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
