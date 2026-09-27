// Package humanauth composes magiclink and passkey into browser sign-in: a
// hashed-token session cookie, a per-session CSRF token checked alongside the
// standard library's cross-origin protection, and the HTTP routes the email
// magic-link and passkey ceremonies need.
//
// The session cookie value is 32 random bytes; only its SHA-256 digest is
// stored, the same digest-at-rest pattern as magiclink.Challenge.TokenDigest
// and passkey.Ceremony.HandleDigest. Origins, relying-party ID and redirect
// targets come from Config only. Host is never trusted.
//
// It is not a user directory, account policy, rate limiter or login page. The
// application decides who may sign in and whether an account is active
// (Policy), rate-limits the magic-link request route, renders its own login
// page, and calls Sweep periodically.
//
// Status: CANDIDATE. Capability: identity.human-session.
package humanauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/ajent-social/go/magiclink"
	"github.com/ajent-social/go/passkey"
)

var (
	ErrInvalid   = errors.New("humanauth: invalid input")
	ErrNotFound  = errors.New("humanauth: not found")
	ErrNoSession = errors.New("humanauth: no session")
	ErrCSRF      = errors.New("humanauth: csrf check failed")
	ErrDenied    = errors.New("humanauth: denied")
)

const (
	defaultPrefix       = "/auth"
	defaultCookieName   = "__Host-session"
	defaultSessionTTL   = 30 * 24 * time.Hour
	maxSessionTTL       = 90 * 24 * time.Hour
	defaultMagicLinkTTL = 15 * time.Minute
	// defaultCeremonyTTL mirrors passkey's own default so the ceremony cookie
	// Max-Age matches the stored ceremony lifetime.
	defaultCeremonyTTL = 5 * time.Minute
	tokenBytes         = 32
	csrfHeader         = "X-CSRF-Token"
	csrfField          = "csrf_token"
	hostCookiePrefix   = "__Host-"
	secureCookiePrefix = "__Secure-"
)

// Subject is the signed-in person as the application's Policy describes them.
// ID is opaque and stable (it becomes the WebAuthn user handle); Name is what
// the person types, e.g. an email address.
type Subject struct{ ID, Name, DisplayName string }

// Method records how a session was established.
type Method string

const (
	MethodMagicLink Method = "magiclink"
	MethodPasskey   Method = "passkey"
)

// Policy belongs to the application. humanauth never decides who may sign in.
type Policy interface {
	// SubjectForEmail maps an email that a magic link has just proven to a subject.
	// Any error refuses: no mail is sent at request time, and no session is minted at redeem time.
	SubjectForEmail(ctx context.Context, email string) (Subject, error)
	// Admit runs before every session is minted, by either method, and returns the current subject.
	// Any error refuses the session.
	Admit(ctx context.Context, subjectID string) (Subject, error)
}

// Record is storage-only. The cookie value is never stored.
type Record struct {
	TokenDigest [32]byte // sha256 of the cookie value; the cookie value is never stored
	Subject     Subject
	Method      Method
	CSRF        string // base64url (no padding) of 32 random bytes
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// Store persists session records.
type Store interface {
	Create(ctx context.Context, rec Record) error
	Get(ctx context.Context, digest [32]byte) (Record, error)            // ErrNotFound
	Delete(ctx context.Context, digest [32]byte) error                   // idempotent
	ListSubject(ctx context.Context, subjectID string) ([]Record, error) // newest CreatedAt first
	DeleteSubject(ctx context.Context, subjectID string) (int, error)
	DeleteExpired(ctx context.Context, now time.Time) (int, error)
}

// Config binds the service to one public origin and route prefix.
type Config struct {
	PublicURL     string           // exact origin, e.g. https://app.example; no path, no trailing slash
	Prefix        string           // route prefix; "" → "/auth"; must start with "/" and not end with "/"
	RPDisplayName string           // required
	CookieName    string           // "" → "__Host-session"
	SessionTTL    time.Duration    // 0 → 30 days; must be ≤ 90 days
	MagicLinkTTL  time.Duration    // 0 → 15 minutes
	CeremonyTTL   time.Duration    // passed to passkey.Config; 0 → its default
	AfterLogin    string           // local path; "" → "/"
	AfterLogout   string           // local path; "" → "/"
	Stylesheet    string           // optional local path linked by the built-in pages
	Now           func() time.Time // nil → time.Now
}

// Deps are the stores and seams the service composes. Only Log may be nil.
type Deps struct {
	Sessions   Store
	MagicLinks magiclink.Store
	Mailer     magiclink.Mailer
	Passkeys   passkey.Store
	Policy     Policy
	Log        *slog.Logger // nil → discard
}

// Session is the caller-facing view of a Record.
type Session struct {
	ID        string // hex of TokenDigest; safe to display and to revoke by; never the cookie value
	Subject   Subject
	Method    Method
	CSRF      string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Service mints and checks browser sessions and serves the sign-in routes.
type Service struct {
	cfg        Config
	secure     bool
	cookieBase string // CookieName without a leading "__Host-"
	sessions   Store
	passkeys   passkey.Store
	policy     Policy
	log        *slog.Logger
	magic      *magiclink.Service
	pk         *passkey.Service
	cop        *http.CrossOriginProtection
	now        func() time.Time
	pages      map[string]*template.Template
	handler    http.Handler
}

// New validates cfg, builds the magiclink and passkey services from it so
// URLs and origins cannot drift apart, and returns a Service.
func New(cfg Config, d Deps) (*Service, error) {
	u, err := url.Parse(cfg.PublicURL)
	if err != nil || u.Host == "" || u.User != nil || u.Opaque != "" {
		return nil, fmt.Errorf("%w: PublicURL must be an absolute origin", ErrInvalid)
	}
	switch u.Scheme {
	case "https":
	case "http":
		switch u.Hostname() {
		case "localhost", "127.0.0.1", "::1":
		default:
			return nil, fmt.Errorf("%w: PublicURL must be https (http only for localhost)", ErrInvalid)
		}
	default:
		return nil, fmt.Errorf("%w: PublicURL must be https (http only for localhost)", ErrInvalid)
	}
	if u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(cfg.PublicURL, "?#") {
		return nil, fmt.Errorf("%w: PublicURL must not have a path, query or fragment", ErrInvalid)
	}
	if cfg.PublicURL != u.Scheme+"://"+strings.ToLower(u.Host) {
		return nil, fmt.Errorf("%w: PublicURL must be a lowercase scheme://host[:port] origin", ErrInvalid)
	}
	secure := u.Scheme == "https"

	if cfg.Prefix == "" {
		cfg.Prefix = defaultPrefix
	}
	if !validPrefix(cfg.Prefix) {
		return nil, fmt.Errorf("%w: Prefix must be a clean path starting with / and not ending with /", ErrInvalid)
	}
	if strings.TrimSpace(cfg.RPDisplayName) == "" {
		return nil, fmt.Errorf("%w: RPDisplayName required", ErrInvalid)
	}
	switch {
	case d.Sessions == nil:
		return nil, fmt.Errorf("%w: Deps.Sessions required", ErrInvalid)
	case d.MagicLinks == nil:
		return nil, fmt.Errorf("%w: Deps.MagicLinks required", ErrInvalid)
	case d.Mailer == nil:
		return nil, fmt.Errorf("%w: Deps.Mailer required", ErrInvalid)
	case d.Passkeys == nil:
		return nil, fmt.Errorf("%w: Deps.Passkeys required", ErrInvalid)
	case d.Policy == nil:
		return nil, fmt.Errorf("%w: Deps.Policy required", ErrInvalid)
	}

	if cfg.CookieName == "" {
		cfg.CookieName = defaultCookieName
	}
	if (&http.Cookie{Name: cfg.CookieName, Value: "x"}).Valid() != nil {
		return nil, fmt.Errorf("%w: CookieName is not a valid cookie name", ErrInvalid)
	}
	if !secure && (strings.HasPrefix(cfg.CookieName, hostCookiePrefix) || strings.HasPrefix(cfg.CookieName, secureCookiePrefix)) {
		return nil, fmt.Errorf("%w: CookieName with a __Host- or __Secure- prefix needs an https PublicURL", ErrInvalid)
	}
	base := strings.TrimPrefix(cfg.CookieName, hostCookiePrefix)
	if base == "" {
		return nil, fmt.Errorf("%w: CookieName needs a name after the prefix", ErrInvalid)
	}

	if cfg.SessionTTL < 0 {
		return nil, fmt.Errorf("%w: SessionTTL must not be negative", ErrInvalid)
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = defaultSessionTTL
	}
	if cfg.SessionTTL > maxSessionTTL {
		return nil, fmt.Errorf("%w: SessionTTL must be at most 90 days", ErrInvalid)
	}
	if cfg.MagicLinkTTL < 0 {
		return nil, fmt.Errorf("%w: MagicLinkTTL must not be negative", ErrInvalid)
	}
	if cfg.MagicLinkTTL == 0 {
		cfg.MagicLinkTTL = defaultMagicLinkTTL
	}
	if cfg.CeremonyTTL < 0 {
		return nil, fmt.Errorf("%w: CeremonyTTL must not be negative", ErrInvalid)
	}
	if cfg.CeremonyTTL == 0 {
		cfg.CeremonyTTL = defaultCeremonyTTL
	}

	if cfg.AfterLogin == "" {
		cfg.AfterLogin = "/"
	}
	if !localPath(cfg.AfterLogin) {
		return nil, fmt.Errorf("%w: AfterLogin must be a local path", ErrInvalid)
	}
	if cfg.AfterLogout == "" {
		cfg.AfterLogout = "/"
	}
	if !localPath(cfg.AfterLogout) {
		return nil, fmt.Errorf("%w: AfterLogout must be a local path", ErrInvalid)
	}
	if cfg.Stylesheet != "" && !localPath(cfg.Stylesheet) {
		return nil, fmt.Errorf("%w: Stylesheet must be a local path", ErrInvalid)
	}

	magic, err := magiclink.New(magiclink.Config{
		TTL:     cfg.MagicLinkTTL,
		BaseURL: cfg.PublicURL + cfg.Prefix + "/magic",
	}, d.MagicLinks, d.Mailer)
	if err != nil {
		return nil, fmt.Errorf("%w: MagicLinkTTL: %v", ErrInvalid, err)
	}
	pk, err := passkey.New(passkey.Config{
		RPDisplayName: cfg.RPDisplayName,
		Origin:        cfg.PublicURL,
		CeremonyTTL:   cfg.CeremonyTTL,
	}, d.Passkeys)
	if err != nil {
		return nil, fmt.Errorf("%w: passkey config (CeremonyTTL, PublicURL): %v", ErrInvalid, err)
	}
	cop := http.NewCrossOriginProtection()
	if err := cop.AddTrustedOrigin(cfg.PublicURL); err != nil {
		return nil, fmt.Errorf("%w: PublicURL: %v", ErrInvalid, err)
	}

	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	log := d.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	pages, err := parsePages()
	if err != nil {
		return nil, err
	}
	s := &Service{
		cfg:        cfg,
		secure:     secure,
		cookieBase: base,
		sessions:   d.Sessions,
		passkeys:   d.Passkeys,
		policy:     d.Policy,
		log:        log,
		magic:      magic,
		pk:         pk,
		cop:        cop,
		now:        now,
		pages:      pages,
	}
	s.handler = s.buildHandler()
	return s, nil
}

// Session returns the session named by the request's session cookie. It
// returns ErrNoSession when there is no cookie, an unknown digest, or an
// expired record (which is deleted best-effort). Store failures are returned
// as-is; callers must treat any error as "not signed in".
func (s *Service) Session(r *http.Request) (Session, error) {
	rec, err := s.record(r)
	if err != nil {
		return Session{}, err
	}
	return toSession(rec, true), nil
}

// CSRFToken returns the current session's CSRF token, or "" without a session.
func (s *Service) CSRFToken(r *http.Request) string {
	rec, err := s.record(r)
	if err != nil {
		return ""
	}
	return rec.CSRF
}

// CheckCSRF returns nil for GET, HEAD and OPTIONS. For any other method it
// requires that http.CrossOriginProtection passes and that a session exists
// whose CSRF token matches the X-CSRF-Token header. The csrf_token form field
// is accepted only when that header is absent and the body is
// application/x-www-form-urlencoded; multipart bodies are never parsed.
func (s *Service) CheckCSRF(r *http.Request) error {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return nil
	}
	if err := s.cop.Check(r); err != nil {
		return fmt.Errorf("%w: %v", ErrCSRF, err)
	}
	rec, err := s.record(r)
	if err != nil {
		return ErrCSRF
	}
	var got string
	if vals := r.Header.Values(csrfHeader); len(vals) > 0 {
		if len(vals) != 1 {
			return ErrCSRF
		}
		got = vals[0]
	} else if isURLEncodedForm(r) {
		got = r.PostFormValue(csrfField)
	}
	if got == "" || rec.CSRF == "" || subtle.ConstantTimeCompare([]byte(got), []byte(rec.CSRF)) != 1 {
		return ErrCSRF
	}
	return nil
}

// Handler serves every route in Paths. Mount it at each path, or at
// Prefix+"/"; it matches full request paths.
func (s *Service) Handler() http.Handler { return s.handler }

// Sessions lists a subject's sessions, newest first, with CSRF left blank.
func (s *Service) Sessions(ctx context.Context, subjectID string) ([]Session, error) {
	if subjectID == "" {
		return nil, ErrInvalid
	}
	recs, err := s.sessions.ListSubject(ctx, subjectID)
	if err != nil {
		return nil, err
	}
	out := make([]Session, 0, len(recs))
	for _, rec := range recs {
		out = append(out, toSession(rec, false))
	}
	return out, nil
}

// Revoke deletes one session by its Session.ID. It returns ErrNotFound unless
// the session exists and belongs to subjectID.
func (s *Service) Revoke(ctx context.Context, subjectID, sessionID string) error {
	if subjectID == "" {
		return ErrInvalid
	}
	digest, err := hexDigest(sessionID)
	if err != nil {
		return err
	}
	rec, err := s.sessions.Get(ctx, digest)
	if err != nil {
		return err
	}
	if rec.Subject.ID != subjectID {
		return ErrNotFound
	}
	return s.sessions.Delete(ctx, digest)
}

// RevokeSubject deletes every session of subjectID and returns how many.
func (s *Service) RevokeSubject(ctx context.Context, subjectID string) (int, error) {
	if subjectID == "" {
		return 0, ErrInvalid
	}
	return s.sessions.DeleteSubject(ctx, subjectID)
}

// Sweep deletes expired session records. Call it periodically.
func (s *Service) Sweep(ctx context.Context) (int, error) {
	return s.sessions.DeleteExpired(ctx, s.now().UTC())
}

// record loads the live record for the request's session cookie.
func (s *Service) record(r *http.Request) (Record, error) {
	c, err := r.Cookie(s.cfg.CookieName)
	if err != nil || len(c.Value) != base64.RawURLEncoding.EncodedLen(tokenBytes) {
		return Record{}, ErrNoSession
	}
	digest := sha256.Sum256([]byte(c.Value))
	rec, err := s.sessions.Get(r.Context(), digest)
	if errors.Is(err, ErrNotFound) {
		return Record{}, ErrNoSession
	}
	if err != nil {
		return Record{}, err
	}
	if !rec.ExpiresAt.After(s.now()) {
		_ = s.sessions.Delete(r.Context(), digest)
		return Record{}, ErrNoSession
	}
	return rec, nil
}

// mint is the only place a session is created: it generates the token,
// stores the Record and sets the session cookie.
func (s *Service) mint(w http.ResponseWriter, r *http.Request, sub Subject, m Method) error {
	token, err := randomToken()
	if err != nil {
		return err
	}
	csrf, err := randomToken()
	if err != nil {
		return err
	}
	now := s.now().UTC()
	rec := Record{
		TokenDigest: sha256.Sum256([]byte(token)),
		Subject:     sub,
		Method:      m,
		CSRF:        csrf,
		CreatedAt:   now,
		ExpiresAt:   now.Add(s.cfg.SessionTTL),
	}
	if err := s.sessions.Create(r.Context(), rec); err != nil {
		return err
	}
	// A fresh sign-in replaces whatever session this browser carried.
	if old, err := r.Cookie(s.cfg.CookieName); err == nil && old.Value != "" {
		_ = s.sessions.Delete(r.Context(), sha256.Sum256([]byte(old.Value)))
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.CookieName,
		Value:    token,
		Path:     "/",
		Expires:  rec.ExpiresAt,
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func (s *Service) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func toSession(rec Record, withCSRF bool) Session {
	out := Session{
		ID:        hex.EncodeToString(rec.TokenDigest[:]),
		Subject:   rec.Subject,
		Method:    rec.Method,
		CreatedAt: rec.CreatedAt,
		ExpiresAt: rec.ExpiresAt,
	}
	if withCSRF {
		out.CSRF = rec.CSRF
	}
	return out
}

// hexDigest parses a Session.ID.
func hexDigest(id string) ([32]byte, error) {
	var digest [32]byte
	raw, err := hex.DecodeString(id)
	if err != nil || len(raw) != len(digest) {
		return digest, ErrNotFound
	}
	copy(digest[:], raw)
	return digest, nil
}

func isURLEncodedForm(r *http.Request) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mt == "application/x-www-form-urlencoded"
}

// localPath reports whether s is a same-origin path that is safe to redirect to.
func localPath(s string) bool {
	if !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.HasPrefix(s, `/\`) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f {
			return false // includes \r and \n; browsers also strip tabs, which could form "//"
		}
	}
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "" && u.Host == "" && u.Opaque == ""
}

func validPrefix(p string) bool {
	if len(p) < 2 || p[0] != '/' || strings.HasSuffix(p, "/") || path.Clean(p) != p {
		return false
	}
	for _, c := range p {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.ContainsRune("/-._~", c):
		default:
			return false
		}
	}
	return true
}

func randomToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
