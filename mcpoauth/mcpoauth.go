// Package mcpoauth implements a bounded OAuth 2.1 authorization server for a
// single protected resource with public PKCE clients, as used by an MCP
// server. It provides metadata, dynamic client registration, authorization
// request validation, consent-bound code issuance, token exchange, revocation
// and bearer verification. It is not a login system, session store or
// authorization policy engine: the application authenticates the browser,
// protects its consent form against CSRF, decides which subject and binding
// to approve, and re-checks ownership policy on every verified request.
//
// Adapted with owner authorization from a restricted-source product
// implementation; this adaptation is Apache-2.0. See docs/provenance-mcpoauth.md.
package mcpoauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"time"
)

var (
	ErrInvalid  = errors.New("invalid oauth configuration or input")
	ErrDenied   = errors.New("oauth request denied")
	ErrNotFound = errors.New("oauth record not found")
	ErrExists   = errors.New("oauth record already exists")
	ErrExpired  = errors.New("oauth record expired")
	// ErrReused reports a refresh token presented after it was already
	// rotated. The store revokes the whole grant as a side effect.
	ErrReused = errors.New("oauth refresh token reused")
)

const (
	defaultAccessTokenTTL = time.Hour
	maxAccessTokenTTL     = 24 * time.Hour
	defaultCodeTTL        = 10 * time.Minute
	maxCodeTTL            = 10 * time.Minute
	defaultConsentTTL     = 10 * time.Minute
	maxConsentTTL         = 30 * time.Minute
	defaultRefreshTTL     = 30 * 24 * time.Hour
	maxRefreshTTL         = 90 * 24 * time.Hour

	maxScopes      = 64
	maxScopeLen    = 128
	maxClientName  = 255
	maxRedirectURI = 2048
	maxState       = 1024
	maxRedirects   = 10
	maxNameLen     = 256

	metadataPath          = "/.well-known/oauth-authorization-server"
	protectedResourcePath = "/.well-known/oauth-protected-resource"
)

// Config binds the server to one issuer and one resource. Nothing is ever
// derived from request Host headers.
type Config struct {
	Issuer                 string
	Resource               string
	Scopes                 []string
	AllowLoopbackRedirects bool
	// AllowLocalhostRedirects permits exact localhost HTTP callbacks with an
	// explicit port for clients that cannot use numeric loopback. Disabled by
	// default: localhost resolution is controlled by the client environment.
	AllowLocalhostRedirects bool
	AccessTokenTTL          time.Duration
	CodeTTL                 time.Duration
	ConsentTTL              time.Duration
	// RefreshTTL is the absolute lifetime of a grant (token family) measured
	// from the code exchange. Default 30 days, max 90 days. No refresh token
	// is valid past it regardless of rotation count.
	RefreshTTL time.Duration
	// DisableRefresh removes the refresh_token grant from issuance, metadata
	// and registration. Grants then expire with their single access token.
	DisableRefresh bool
	AuthorizePath  string
	TokenPath      string
	RegisterPath   string
	RevokePath     string
	Logger         *slog.Logger
}

// Client is a registered public client. Redirect URIs are matched exactly.
type Client struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	RedirectURIs []string  `json:"redirect_uris"`
	CreatedAt    time.Time `json:"created_at"`
}

// ConsentRequest is the immutable, validated authorization request the
// application renders for approval.
type ConsentRequest struct {
	ClientID   string
	ClientName string
	Scopes     []string
	Resource   string
	ExpiresAt  time.Time
}

// Approval is the application's decision after it authenticated the browser,
// validated its own CSRF token and checked ownership of Binding.
type Approval struct {
	Subject string
	Binding string
	Scopes  []string
}

// Identity is the result of Verify. Applications apply live policy on top.
// GrantID is stable across refresh rotations within one authorization and
// is not a secret.
type Identity struct {
	Subject   string
	Binding   string
	Scopes    []string
	ClientID  string
	GrantID   string
	ExpiresAt time.Time
}

// ConsentRecord is storage-only. ID is the hex SHA-256 of the handle.
type ConsentRecord struct {
	ID            string    `json:"id"`
	ClientID      string    `json:"client_id"`
	RedirectURI   string    `json:"redirect_uri"`
	CodeChallenge string    `json:"code_challenge"`
	State         string    `json:"state"`
	Resource      string    `json:"resource"`
	Scopes        []string  `json:"scopes"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// CodeRecord is storage-only. ID is the hex SHA-256 of the code.
type CodeRecord struct {
	ID            string    `json:"id"`
	ClientID      string    `json:"client_id"`
	RedirectURI   string    `json:"redirect_uri"`
	CodeChallenge string    `json:"code_challenge"`
	Subject       string    `json:"subject"`
	Binding       string    `json:"binding"`
	Resource      string    `json:"resource"`
	Scopes        []string  `json:"scopes"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// GrantRecord is storage-only. It is the immutable binding of one
// authorization (token family). ID is random hex, not a digest. RevokedAt is
// the single revocation switch for every token in the family.
type GrantRecord struct {
	ID        string    `json:"id"`
	ClientID  string    `json:"client_id"`
	Subject   string    `json:"subject"`
	Binding   string    `json:"binding"`
	Resource  string    `json:"resource"`
	Scopes    []string  `json:"scopes"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	RevokedAt time.Time `json:"revoked_at,omitzero"`
}

// TokenRecord is storage-only. ID is the hex SHA-256 of the access token.
// Bindings are a denormalised copy of the grant and are cross-checked.
type TokenRecord struct {
	ID        string    `json:"id"`
	GrantID   string    `json:"grant_id"`
	ClientID  string    `json:"client_id"`
	Subject   string    `json:"subject"`
	Binding   string    `json:"binding"`
	Resource  string    `json:"resource"`
	Scopes    []string  `json:"scopes"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// RefreshRecord is storage-only. ID is the hex SHA-256 of the refresh token.
// UsedAt is set exactly once by RotateRefresh; a second presentation is reuse.
type RefreshRecord struct {
	ID         string    `json:"id"`
	GrantID    string    `json:"grant_id"`
	ClientID   string    `json:"client_id"`
	Generation int       `json:"generation"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	UsedAt     time.Time `json:"used_at,omitzero"`
	ReplacedBy string    `json:"replaced_by,omitempty"`
}

// GrantIssue is the atomic request that creates a token family: the grant,
// its first access token and, unless refresh is disabled, its first refresh
// token. Refresh is nil when refresh is disabled.
type GrantIssue struct {
	Grant   GrantRecord
	Token   TokenRecord
	Refresh *RefreshRecord
}

// RefreshRotation is the atomic request that consumes one refresh token and
// issues its successors. Token and Refresh carry the old token's GrantID.
type RefreshRotation struct {
	RefreshID string
	At        time.Time
	Token     TokenRecord
	Refresh   RefreshRecord
}

// Store persists clients, consent records, codes, grants and tokens. Every
// method is independently atomic and durable; no method needs a transaction
// spanning another. Create* return ErrExists on an existing ID. Consume*
// atomically delete and return the record so exactly one concurrent caller
// succeeds and the others receive ErrNotFound. Reads never filter by expiry
// or revocation; the server evaluates those. Any other error fails closed.
//
// CreateGrant writes the grant, token and optional refresh record in one
// transaction; any collision fails the whole call with ErrExists. An
// application may run its own live issuance policy inside that transaction
// and return ErrDenied.
//
// RotateRefresh, in one transaction: loads the refresh record RefreshID
// (absent: ErrNotFound); if it is already used, sets RevokedAt on its grant,
// COMMITS that write, and returns ErrReused; otherwise loads the grant
// (absent: ErrNotFound; revoked: ErrDenied), optionally applies application
// policy (ErrDenied), inserts Token and Refresh (collision: ErrExists), and
// marks the old record used with ReplacedBy set. Exactly one of two
// concurrent rotations of the same token may succeed.
//
// RevokeGrant sets RevokedAt if unset (idempotent) and returns ErrNotFound
// for unknown IDs.
type Store interface {
	CreateClient(ctx context.Context, c Client) error
	Client(ctx context.Context, id string) (Client, error)
	CreateConsent(ctx context.Context, c ConsentRecord) error
	Consent(ctx context.Context, id string) (ConsentRecord, error)
	ConsumeConsent(ctx context.Context, id string) (ConsentRecord, error)
	CreateCode(ctx context.Context, c CodeRecord) error
	ConsumeCode(ctx context.Context, id string) (CodeRecord, error)
	CreateGrant(ctx context.Context, g GrantIssue) error
	Grant(ctx context.Context, id string) (GrantRecord, error)
	Token(ctx context.Context, id string) (TokenRecord, error)
	Refresh(ctx context.Context, id string) (RefreshRecord, error)
	RotateRefresh(ctx context.Context, r RefreshRotation) error
	RevokeGrant(ctx context.Context, id string, at time.Time) error
}

// Server is safe for concurrent use.
type Server struct {
	cfg      Config
	store    Store
	log      *slog.Logger
	now      func() time.Time
	metadata []byte
	resource []byte
}

// New validates cfg and returns a server. The issuer and resource must be
// absolute https URLs (http is accepted only for numeric loopback hosts).
func New(cfg Config, store Store) (*Server, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: nil store", ErrInvalid)
	}
	if err := validateIssuer(cfg.Issuer); err != nil {
		return nil, err
	}
	if err := validateResource(cfg.Resource); err != nil {
		return nil, err
	}
	if len(cfg.Scopes) == 0 || len(cfg.Scopes) > maxScopes {
		return nil, fmt.Errorf("%w: between 1 and %d scopes required", ErrInvalid, maxScopes)
	}
	seen := map[string]bool{}
	for _, s := range cfg.Scopes {
		if !validScope(s) || seen[s] {
			return nil, fmt.Errorf("%w: invalid or duplicate scope %q", ErrInvalid, s)
		}
		seen[s] = true
	}
	cfg.Scopes = slices.Clone(cfg.Scopes)
	var err error
	if cfg.AccessTokenTTL, err = ttl(cfg.AccessTokenTTL, defaultAccessTokenTTL, maxAccessTokenTTL); err != nil {
		return nil, fmt.Errorf("access token ttl: %w", err)
	}
	if cfg.CodeTTL, err = ttl(cfg.CodeTTL, defaultCodeTTL, maxCodeTTL); err != nil {
		return nil, fmt.Errorf("code ttl: %w", err)
	}
	if cfg.ConsentTTL, err = ttl(cfg.ConsentTTL, defaultConsentTTL, maxConsentTTL); err != nil {
		return nil, fmt.Errorf("consent ttl: %w", err)
	}
	if cfg.RefreshTTL, err = ttl(cfg.RefreshTTL, defaultRefreshTTL, maxRefreshTTL); err != nil {
		return nil, fmt.Errorf("refresh ttl: %w", err)
	}
	if cfg.RefreshTTL < cfg.AccessTokenTTL {
		return nil, fmt.Errorf("%w: refresh ttl must not be shorter than access token ttl", ErrInvalid)
	}
	for name, p := range map[string]*string{
		"/oauth/authorize": &cfg.AuthorizePath, "/oauth/token": &cfg.TokenPath,
		"/oauth/register": &cfg.RegisterPath, "/oauth/revoke": &cfg.RevokePath,
	} {
		if *p == "" {
			*p = name
		}
		if !validPath(*p) {
			return nil, fmt.Errorf("%w: endpoint path %q must be absolute without query or fragment", ErrInvalid, *p)
		}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	s := &Server{cfg: cfg, store: store, log: cfg.Logger, now: time.Now}
	if s.metadata, s.resource, err = buildMetadata(cfg); err != nil {
		return nil, err
	}
	return s, nil
}

func ttl(v, def, max time.Duration) (time.Duration, error) {
	if v == 0 {
		return def, nil
	}
	if v < 0 || v > max {
		return 0, fmt.Errorf("%w: must be within (0, %s]", ErrInvalid, max)
	}
	return v, nil
}

func validPath(p string) bool {
	return strings.HasPrefix(p, "/") && len(p) < 512 && !strings.ContainsAny(p, "?# \r\n\t") && !strings.Contains(p, "//")
}

func validateIssuer(raw string) error {
	u, err := parseAbsoluteURL(raw)
	if err != nil {
		return fmt.Errorf("issuer: %w", err)
	}
	if u.Path != "" || u.RawQuery != "" || u.ForceQuery {
		return fmt.Errorf("%w: issuer must have no path or query", ErrInvalid)
	}
	return nil
}

func validateResource(raw string) error {
	u, err := parseAbsoluteURL(raw)
	if err != nil {
		return fmt.Errorf("resource: %w", err)
	}
	if u.RawQuery != "" || u.ForceQuery {
		return fmt.Errorf("%w: resource must have no query", ErrInvalid)
	}
	return nil
}

// parseAbsoluteURL accepts https URLs, or http URLs whose host is a numeric
// loopback literal, with no userinfo, fragment or control characters.
func parseAbsoluteURL(raw string) (*url.URL, error) {
	return parseURL(raw, false)
}

func parseURL(raw string, allowLocalhost bool) (*url.URL, error) {
	if raw == "" || len(raw) > maxRedirectURI || !cleanString(raw) || strings.ContainsAny(raw, " \t") {
		return nil, fmt.Errorf("%w: empty, oversized or unclean url", ErrInvalid)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if u.Fragment != "" || strings.Contains(raw, "#") || u.User != nil || u.Opaque != "" || u.Host == "" || u.Hostname() == "" {
		return nil, fmt.Errorf("%w: url must be absolute without userinfo or fragment", ErrInvalid)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(u.Hostname()) && !(allowLocalhost && u.Hostname() == "localhost" && u.Port() != "") {
			return nil, fmt.Errorf("%w: http is only allowed for numeric loopback hosts", ErrInvalid)
		}
	default:
		return nil, fmt.Errorf("%w: scheme must be https", ErrInvalid)
	}
	if _, err := url.ParseQuery(u.RawQuery); err != nil {
		return nil, fmt.Errorf("%w: malformed URL query", ErrInvalid)
	}
	if u.String() != raw {
		return nil, fmt.Errorf("%w: url is not in canonical form", ErrInvalid)
	}
	return u, nil
}

func (s *Server) endpoint(path string) string { return s.cfg.Issuer + path }

// cleanString rejects control characters, which covers CRLF injection.
func cleanString(v string) bool {
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] == 0x7f {
			return false
		}
	}
	return true
}

func validScope(s string) bool {
	if s == "" || len(s) > maxScopeLen {
		return false
	}
	// RFC 6749 §3.3: %x21 / %x23-5B / %x5D-7E.
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

func validOpaque(v string) bool {
	return v != "" && len(v) <= maxNameLen && cleanString(v) && strings.TrimSpace(v) == v
}

// parseScopes parses a space-separated scope string and checks it against a
// ceiling. An empty string yields the whole ceiling.
func parseScopes(raw string, ceiling []string) ([]string, error) {
	if raw == "" {
		return slices.Clone(ceiling), nil
	}
	if len(raw) > maxScopes*(maxScopeLen+1) {
		return nil, fmt.Errorf("%w: scope too long", ErrInvalid)
	}
	return narrowScopes(strings.Split(raw, " "), ceiling)
}

func narrowScopes(requested, ceiling []string) ([]string, error) {
	if len(requested) == 0 || len(ceiling) == 0 {
		return nil, fmt.Errorf("%w: explicit non-empty scopes required", ErrInvalid)
	}
	if len(requested) > maxScopes {
		return nil, fmt.Errorf("%w: too many scopes", ErrInvalid)
	}
	out := make([]string, 0, len(requested))
	for _, sc := range requested {
		if !validScope(sc) || !slices.Contains(ceiling, sc) || slices.Contains(out, sc) {
			return nil, fmt.Errorf("%w: scope %q is not permitted", ErrInvalid, sc)
		}
		out = append(out, sc)
	}
	return out, nil
}

func randomSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// digest keys storage by the SHA-256 of a uniformly random secret; the raw
// value is never persisted.
func digest(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// validCodeChallenge checks the S256 challenge syntax: exactly 43 base64url
// characters without padding.
func validCodeChallenge(c string) bool {
	if len(c) != 43 {
		return false
	}
	for i := 0; i < len(c); i++ {
		if !isBase64URL(c[i]) {
			return false
		}
	}
	return true
}

func isBase64URL(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

// validCodeVerifier enforces RFC 7636 §4.1: 43..128 unreserved characters.
func validCodeVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !(isBase64URL(c) || c == '.' || c == '~') {
			return false
		}
	}
	return true
}

func verifyPKCES256(verifier, challenge string) bool {
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

// Consent reads a pending request without consuming it.
func (s *Server) Consent(ctx context.Context, handle string) (ConsentRequest, error) {
	if handle == "" {
		return ConsentRequest{}, ErrNotFound
	}
	rec, err := s.store.Consent(ctx, digest(handle))
	if err != nil {
		return ConsentRequest{}, err
	}
	if !s.now().Before(rec.ExpiresAt) {
		return ConsentRequest{}, ErrExpired
	}
	return s.consentRequest(ctx, rec)
}

func (s *Server) consentRequest(ctx context.Context, rec ConsentRecord) (ConsentRequest, error) {
	client, err := s.store.Client(ctx, rec.ClientID)
	if err != nil {
		return ConsentRequest{}, fmt.Errorf("resolve consent client: %w", err)
	}
	if client.ID != rec.ClientID || !s.redirectOK(client, rec.RedirectURI) || rec.Resource != s.cfg.Resource || !validCodeChallenge(rec.CodeChallenge) || !cleanString(rec.State) {
		return ConsentRequest{}, ErrDenied
	}
	if _, err := narrowScopes(rec.Scopes, s.cfg.Scopes); err != nil {
		return ConsentRequest{}, ErrDenied
	}
	return ConsentRequest{ClientID: rec.ClientID, ClientName: client.Name, Scopes: slices.Clone(rec.Scopes), Resource: rec.Resource, ExpiresAt: rec.ExpiresAt}, nil
}

// Approve consumes the consent record atomically, issues a code bound to the
// original request, and returns the redirect URL for the browser.
func (s *Server) Approve(ctx context.Context, handle string, a Approval) (string, error) {
	if !validOpaque(a.Subject) || (a.Binding != "" && !validOpaque(a.Binding)) {
		return "", fmt.Errorf("%w: subject and binding must be non-empty clean strings", ErrInvalid)
	}
	if handle == "" {
		return "", ErrNotFound
	}
	// Validate the narrowing before consuming so a bad approval leaves the
	// consent record intact for a corrected retry.
	peek, err := s.store.Consent(ctx, digest(handle))
	if err != nil {
		return "", err
	}
	if _, err = s.consentRequest(ctx, peek); err != nil {
		return "", err
	}
	scopes, err := narrowScopes(a.Scopes, peek.Scopes)
	if err != nil {
		return "", err
	}
	rec, err := s.store.ConsumeConsent(ctx, digest(handle))
	if err != nil {
		return "", err
	}
	if _, err = s.consentRequest(ctx, rec); err != nil {
		return "", err
	}
	// Re-narrow against the consumed record: the peek is not authoritative.
	if scopes, err = narrowScopes(scopes, rec.Scopes); err != nil {
		return "", err
	}
	now := s.now()
	if !now.Before(rec.ExpiresAt) {
		return "", ErrExpired
	}
	code, err := randomSecret()
	if err != nil {
		return "", err
	}
	err = s.store.CreateCode(ctx, CodeRecord{
		ID: digest(code), ClientID: rec.ClientID, RedirectURI: rec.RedirectURI,
		CodeChallenge: rec.CodeChallenge, Subject: a.Subject, Binding: a.Binding,
		Resource: rec.Resource, Scopes: scopes, CreatedAt: now, ExpiresAt: now.Add(s.cfg.CodeTTL),
	})
	if err != nil {
		return "", fmt.Errorf("persist authorization code: %w", err)
	}
	return appendQuery(rec.RedirectURI, url.Values{"code": {code}, "state": {rec.State}}), nil
}

// Deny consumes the consent record and returns the access_denied redirect.
func (s *Server) Deny(ctx context.Context, handle string) (string, error) {
	if handle == "" {
		return "", ErrNotFound
	}
	rec, err := s.store.ConsumeConsent(ctx, digest(handle))
	if err != nil {
		return "", err
	}
	if _, err = s.consentRequest(ctx, rec); err != nil {
		return "", err
	}
	return errorRedirect(rec.RedirectURI, "access_denied", "the resource owner denied the request", rec.State), nil
}

// Verify resolves a raw bearer token, failing closed on any store error,
// unknown, expired or resource-mismatched token, and on a missing, revoked,
// expired or mismatched grant. The grant is read on every call so family
// revocation takes effect immediately; nothing is cached.
func (s *Server) Verify(ctx context.Context, raw string) (Identity, error) {
	if raw == "" || len(raw) > 256 {
		return Identity{}, ErrDenied
	}
	rec, err := s.store.Token(ctx, digest(raw))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Identity{}, ErrDenied
		}
		return Identity{}, fmt.Errorf("lookup token: %w", err)
	}
	now := s.now()
	if rec.GrantID == "" || !now.Before(rec.ExpiresAt) || rec.Resource != s.cfg.Resource || rec.Subject == "" {
		return Identity{}, ErrDenied
	}
	grant, err := s.store.Grant(ctx, rec.GrantID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Identity{}, ErrDenied
		}
		return Identity{}, fmt.Errorf("lookup grant: %w", err)
	}
	if !grantActive(grant, now) || !tokenMatchesGrant(rec, grant) {
		return Identity{}, ErrDenied
	}
	// Token scopes must sit inside the grant, which must sit inside the ceiling.
	ceiling, err := narrowScopes(grant.Scopes, s.cfg.Scopes)
	if err != nil {
		return Identity{}, ErrDenied
	}
	scopes, err := narrowScopes(rec.Scopes, ceiling)
	if err != nil {
		return Identity{}, ErrDenied
	}
	return Identity{Subject: rec.Subject, Binding: rec.Binding, Scopes: scopes, ClientID: rec.ClientID, GrantID: grant.ID, ExpiresAt: rec.ExpiresAt}, nil
}

func grantActive(g GrantRecord, now time.Time) bool {
	return g.ID != "" && g.RevokedAt.IsZero() && now.Before(g.ExpiresAt) && g.Subject != "" && g.ClientID != ""
}

func tokenMatchesGrant(t TokenRecord, g GrantRecord) bool {
	return t.GrantID == g.ID && t.ClientID == g.ClientID && t.Subject == g.Subject &&
		t.Binding == g.Binding && t.Resource == g.Resource && !t.ExpiresAt.After(g.ExpiresAt)
}

// Revoke revokes the whole grant behind a raw access or refresh token.
// Unknown tokens are a successful no-op; store failures surface.
func (s *Server) Revoke(ctx context.Context, raw string) error {
	if raw == "" || len(raw) > 256 {
		return nil
	}
	id := digest(raw)
	grantID := ""
	tok, err := s.store.Token(ctx, id)
	switch {
	case err == nil:
		grantID = tok.GrantID
	case !errors.Is(err, ErrNotFound):
		return fmt.Errorf("lookup token: %w", err)
	default:
		ref, err := s.store.Refresh(ctx, id)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return nil
			}
			return fmt.Errorf("lookup refresh token: %w", err)
		}
		grantID = ref.GrantID
	}
	if grantID == "" {
		return nil
	}
	if err := s.store.RevokeGrant(ctx, grantID, s.now()); err != nil && !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("revoke grant: %w", err)
	}
	return nil
}

// issued is the result of grant creation or rotation, ready for the token
// response. Raw secrets live only here and in the HTTP response body.
type issued struct {
	access, refresh string
	scopes          []string
	expiresAt       time.Time
	now             time.Time
}

func (s *Server) newTokenRecord(grant GrantRecord, scopes []string, now time.Time) (string, TokenRecord, error) {
	raw, err := randomSecret()
	if err != nil {
		return "", TokenRecord{}, err
	}
	exp := now.Add(s.cfg.AccessTokenTTL)
	if exp.After(grant.ExpiresAt) {
		exp = grant.ExpiresAt
	}
	return raw, TokenRecord{
		ID: digest(raw), GrantID: grant.ID, ClientID: grant.ClientID, Subject: grant.Subject,
		Binding: grant.Binding, Resource: grant.Resource, Scopes: slices.Clone(scopes), CreatedAt: now, ExpiresAt: exp,
	}, nil
}

func (s *Server) newRefreshRecord(grant GrantRecord, generation int, now time.Time) (string, RefreshRecord, error) {
	raw, err := randomSecret()
	if err != nil {
		return "", RefreshRecord{}, err
	}
	return raw, RefreshRecord{
		ID: digest(raw), GrantID: grant.ID, ClientID: grant.ClientID, Generation: generation,
		CreatedAt: now, ExpiresAt: grant.ExpiresAt,
	}, nil
}

// issueGrant creates a new token family from a redeemed code.
func (s *Server) issueGrant(ctx context.Context, code CodeRecord, scopes []string, now time.Time) (issued, error) {
	grantID, err := randomSecret()
	if err != nil {
		return issued{}, err
	}
	grant := GrantRecord{
		ID: digest(grantID)[:32], ClientID: code.ClientID, Subject: code.Subject, Binding: code.Binding,
		Resource: code.Resource, Scopes: slices.Clone(scopes), CreatedAt: now,
	}
	if s.cfg.DisableRefresh {
		grant.ExpiresAt = now.Add(s.cfg.AccessTokenTTL)
	} else {
		grant.ExpiresAt = now.Add(s.cfg.RefreshTTL)
	}
	access, tok, err := s.newTokenRecord(grant, scopes, now)
	if err != nil {
		return issued{}, err
	}
	req := GrantIssue{Grant: grant, Token: tok}
	out := issued{access: access, scopes: scopes, expiresAt: tok.ExpiresAt, now: now}
	if !s.cfg.DisableRefresh {
		raw, ref, err := s.newRefreshRecord(grant, 1, now)
		if err != nil {
			return issued{}, err
		}
		req.Refresh, out.refresh = &ref, raw
	}
	if err := s.store.CreateGrant(ctx, req); err != nil {
		return issued{}, err
	}
	return out, nil
}

// refresh rotates a raw refresh token for clientID, narrowing to requested
// scopes when given. It returns ErrDenied (wrapped) for every client-facing
// rejection without distinguishing them, and ErrReused after the family has
// been revoked. Immutable bindings are checked before the atomic rotation so
// a wrong client_id never reaches the store and never revokes the family.
func (s *Server) refresh(ctx context.Context, raw, clientID, requestedScope string) (issued, error) {
	if s.cfg.DisableRefresh || raw == "" || len(raw) > 256 || clientID == "" {
		return issued{}, ErrDenied
	}
	old, err := s.store.Refresh(ctx, digest(raw))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return issued{}, ErrDenied
		}
		return issued{}, fmt.Errorf("lookup refresh token: %w", err)
	}
	if old.ClientID != clientID || old.GrantID == "" {
		return issued{}, ErrDenied
	}
	grant, err := s.store.Grant(ctx, old.GrantID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return issued{}, ErrDenied
		}
		return issued{}, fmt.Errorf("lookup grant: %w", err)
	}
	now := s.now()
	if grant.ClientID != clientID || grant.Resource != s.cfg.Resource || !grantActive(grant, now) || !now.Before(old.ExpiresAt) {
		return issued{}, ErrDenied
	}
	ceiling, err := narrowScopes(grant.Scopes, s.cfg.Scopes)
	if err != nil {
		return issued{}, ErrDenied
	}
	scopes, err := parseScopes(requestedScope, ceiling)
	if err != nil {
		return issued{}, fmt.Errorf("%w: %v", ErrDenied, err)
	}
	access, tok, err := s.newTokenRecord(grant, scopes, now)
	if err != nil {
		return issued{}, err
	}
	rawRefresh, ref, err := s.newRefreshRecord(grant, old.Generation+1, now)
	if err != nil {
		return issued{}, err
	}
	if err := s.store.RotateRefresh(ctx, RefreshRotation{RefreshID: old.ID, At: now, Token: tok, Refresh: ref}); err != nil {
		return issued{}, err
	}
	return issued{access: access, refresh: rawRefresh, scopes: scopes, expiresAt: tok.ExpiresAt, now: now}, nil
}

// appendQuery adds params to an already-validated redirect URI.
func appendQuery(rawURI string, params url.Values) string {
	u, err := url.Parse(rawURI)
	if err != nil {
		return rawURI
	}
	q := u.Query()
	for k, vs := range params {
		for _, v := range vs {
			if v != "" {
				q.Set(k, v)
			}
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func errorRedirect(redirectURI, code, desc, state string) string {
	return appendQuery(redirectURI, url.Values{"error": {code}, "error_description": {desc}, "state": {state}})
}
