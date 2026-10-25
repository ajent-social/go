// Package mcpclientoauth coordinates OAuth 2.1 authorization-code + PKCE when
// the product is the client connecting to remote authorization servers (for
// example remote MCP servers). Tokens are stored as caller-sealed ciphertext;
// the package never logs bearer secrets.
//
// Distinct from mcpoauth, where the product is the authorization server.
//
// Status: CANDIDATE. Capability: identity.mcp-client-oauth.
package mcpclientoauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	ErrInvalid          = errors.New("mcpclientoauth: invalid input")
	ErrNotFound         = errors.New("mcpclientoauth: not found")
	ErrExists           = errors.New("mcpclientoauth: already exists")
	ErrExpired          = errors.New("mcpclientoauth: expired")
	ErrDenied           = errors.New("mcpclientoauth: denied")
	ErrUnsupportedStore = errors.New("mcpclientoauth: lifecycle store required")
	ErrConflict         = errors.New("mcpclientoauth: stale connection or token")
	ErrRefreshUncertain = errors.New("mcpclientoauth: refresh claimed; reconnect required if outcome unavailable")
)

const (
	defaultStateTTL      = 10 * time.Minute
	maxStateTTL          = 30 * time.Minute
	defaultRefreshMargin = 5 * time.Minute
	maxRefreshMargin     = 30 * time.Minute
	stateBytes           = 32
	verifierBytes        = 32
)

// ServerConfig is one remote authorization server. All URLs are configured
// absolutes — never derived from request Host.
type ServerConfig struct {
	ID           string // stable server id (slug)
	AuthURL      string
	TokenURL     string
	RevokeURL    string // optional RFC 7009
	ClientID     string
	ClientSecret string // optional for public clients
	RedirectURL  string
	Scopes       []string
	// Resource is an explicit canonical audience URL. Empty preserves generic
	// OAuth compatibility; MCP callers must set it.
	Resource string
	// ExpectedIssuer enables mandatory exact RFC 9207 callback issuer checking.
	// Empty retains legacy callbacks without iss; discovery belongs to the SDK.
	ExpectedIssuer string
}

// Config binds servers and TTLs.
type Config struct {
	Servers       []ServerConfig
	StateTTL      time.Duration
	RefreshMargin time.Duration
	HTTPClient    *http.Client
}

// Pending is storage-only. StateDigest is SHA-256 of the browser state.
// Verifier is a secret stored until consume-once Exchange. The SQL adapter
// stores it as plaintext: callers own database access, encryption at rest and
// expired-pending retention. ExpiresAt enforces use expiry, not physical deletion.
type Pending struct {
	StateDigest [32]byte
	ServerID    string
	OwnerID     string
	Verifier    string
	ExpiresAt   time.Time
	CreatedAt   time.Time
	Generation  string
}

// TokenRecord is storage-only. Ciphertext is an application-sealed blob
// (AMSL does not invent KMS). Metadata is safe for authorized listing.
type TokenRecord struct {
	OwnerID    string
	ServerID   string
	Ciphertext []byte
	ExpiresAt  time.Time // access-token expiry hint for refresh margin
	UpdatedAt  time.Time
	Generation string // opaque connection epoch; never reuse
	Version    int64  // store-managed CAS revision
}

// TokenSecrets is the plaintext payload applications seal into Ciphertext.
type TokenSecrets struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token,omitempty"`
	TokenType    string   `json:"token_type,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
}

// SealFunc encrypts TokenSecrets for durable storage.
type SealFunc func(TokenSecrets) ([]byte, error)

// OpenFunc decrypts a sealed blob.
type OpenFunc func([]byte) (TokenSecrets, error)

// Store persists pending auth and sealed tokens.
type Store interface {
	PutPending(context.Context, Pending) error
	TakePending(context.Context, [32]byte) (Pending, error)
	PutToken(context.Context, TokenRecord) error
	LookupToken(ctx context.Context, ownerID, serverID string) (TokenRecord, error)
	DeleteToken(ctx context.Context, ownerID, serverID string) error
}

// LifecycleStore is the v2 atomic coordination contract. All operations for a
// binding must linearize across every replica using that store. Claims never
// expire: a provider may have rotated a token even when its response was lost.
// Legacy PutToken must fail closed; DeleteToken must durably invalidate.
// See docs/mcp-client-oauth.md for migration and state transition requirements.
type LifecycleStore interface {
	Store
	// BeginConnection replaces any prior generation with an empty connection.
	BeginConnection(ctx context.Context, ownerID, serverID, generation string) error
	// ClaimRefresh CASes a ready record to claimed and advances its version.
	// Return ErrConflict for a stale snapshot or an already-claimed record.
	ClaimRefresh(context.Context, TokenRecord) (TokenRecord, error)
	// CompleteToken CASes empty or claimed to ready and advances its version.
	// It must never insert or overwrite a different generation/revision.
	CompleteToken(context.Context, TokenRecord) error
	// Disconnect atomically returns the old record and leaves an invalidated
	// binding, including when no token exists. Outstanding completions fail.
	Disconnect(ctx context.Context, ownerID, serverID string) (TokenRecord, error)
}

// Service runs client OAuth flows.
type Service struct {
	cfg     Config
	store   LifecycleStore
	seal    SealFunc
	open    OpenFunc
	servers map[string]ServerConfig
	http    *http.Client
	now     func() time.Time
}

// New validates config. seal/open are required so tokens are never stored as
// plaintext in the Store.
func New(cfg Config, store Store, seal SealFunc, open OpenFunc) (*Service, error) {
	if store == nil || seal == nil || open == nil {
		return nil, ErrInvalid
	}
	lifecycle, ok := store.(LifecycleStore)
	if !ok {
		return nil, ErrUnsupportedStore
	}
	ttl := cfg.StateTTL
	if ttl == 0 {
		ttl = defaultStateTTL
	}
	if ttl < time.Minute || ttl > maxStateTTL {
		return nil, fmt.Errorf("%w: StateTTL out of range", ErrInvalid)
	}
	cfg.StateTTL = ttl
	margin := cfg.RefreshMargin
	if margin == 0 {
		margin = defaultRefreshMargin
	}
	if margin < time.Second || margin > maxRefreshMargin {
		return nil, fmt.Errorf("%w: RefreshMargin out of range", ErrInvalid)
	}
	cfg.RefreshMargin = margin
	if len(cfg.Servers) == 0 {
		return nil, fmt.Errorf("%w: at least one server required", ErrInvalid)
	}
	s := &Service{
		cfg:     cfg,
		store:   lifecycle,
		seal:    seal,
		open:    open,
		servers: map[string]ServerConfig{},
		http:    cfg.HTTPClient,
		now:     time.Now,
	}
	// Clone the client; preserve its Transport/TLS and never mutate the caller.
	client := http.Client{}
	if s.http != nil {
		client = *s.http
	}
	if client.Timeout <= 0 || client.Timeout > 15*time.Second {
		client.Timeout = 15 * time.Second
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	s.http = &client
	for _, sc := range cfg.Servers {
		if err := validateServer(sc); err != nil {
			return nil, fmt.Errorf("server %s: %w", sc.ID, err)
		}
		if _, ok := s.servers[sc.ID]; ok {
			return nil, fmt.Errorf("%w: duplicate server %s", ErrInvalid, sc.ID)
		}
		s.servers[sc.ID] = sc
	}
	return s, nil
}

func validateServer(sc ServerConfig) error {
	if strings.TrimSpace(sc.ID) == "" || sc.ClientID == "" {
		return ErrInvalid
	}
	for _, u := range []string{sc.AuthURL, sc.TokenURL, sc.RedirectURL} {
		if err := validateAbsoluteURL(u, true); err != nil {
			return err
		}
	}
	if sc.RevokeURL != "" {
		if err := validateAbsoluteURL(sc.RevokeURL, true); err != nil {
			return err
		}
	}
	if sc.Resource != "" {
		if err := validateCanonicalURL(sc.Resource); err != nil {
			return err
		}
	}
	if sc.ExpectedIssuer != "" {
		if err := validateCanonicalURL(sc.ExpectedIssuer); err != nil {
			return err
		}
	}
	return nil
}

// Canonical URLs are supplied by the caller rather than silently rewritten:
// audience and issuer comparisons are exact. Queries are permitted for resources.
func validateCanonicalURL(raw string) error {
	if err := validateAbsoluteURL(raw, true); err != nil {
		return err
	}
	u, _ := url.Parse(raw)
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			return fmt.Errorf("%w: URL has dot segments", ErrInvalid)
		}
	}
	if u.User != nil || u.Opaque != "" || u.String() != raw ||
		u.Host != strings.ToLower(u.Host) || u.Hostname() == "" ||
		strings.HasSuffix(u.Hostname(), ".") || u.Port() == "443" && u.Scheme == "https" ||
		u.Port() == "80" && u.Scheme == "http" {
		return fmt.Errorf("%w: URL must be canonical without userinfo or default port", ErrInvalid)
	}
	return nil
}

func validateAbsoluteURL(raw string, httpsOrLoopback bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("%w: URL must be absolute without fragment", ErrInvalid)
	}
	if !httpsOrLoopback {
		return nil
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
		return fmt.Errorf("%w: http only allowed on loopback", ErrInvalid)
	default:
		return fmt.Errorf("%w: unsupported URL scheme", ErrInvalid)
	}
}

// StartResult is returned to the browser.
type StartResult struct {
	AuthURL string
	State   string
}

// Start begins PKCE authorization for owner against serverID.
func (s *Service) Start(ctx context.Context, ownerID, serverID string) (StartResult, error) {
	if err := ctx.Err(); err != nil {
		return StartResult{}, err
	}
	if ownerID == "" {
		return StartResult{}, ErrInvalid
	}
	sc, ok := s.servers[serverID]
	if !ok {
		return StartResult{}, ErrNotFound
	}
	state, err := randomToken(stateBytes)
	if err != nil {
		return StartResult{}, err
	}
	verifier, err := randomToken(verifierBytes)
	if err != nil {
		return StartResult{}, err
	}
	generation, err := randomToken(stateBytes)
	if err != nil {
		return StartResult{}, err
	}
	if err := s.store.BeginConnection(ctx, ownerID, serverID, generation); err != nil {
		return StartResult{}, err
	}
	now := s.now().UTC()
	pending := Pending{
		Generation:  generation,
		StateDigest: sha256.Sum256([]byte(state)),
		ServerID:    serverID,
		OwnerID:     ownerID,
		Verifier:    verifier,
		ExpiresAt:   now.Add(s.cfg.StateTTL),
		CreatedAt:   now,
	}
	if err := s.store.PutPending(ctx, pending); err != nil {
		return StartResult{}, err
	}
	challenge := pkceChallenge(verifier)
	authURL, _ := url.Parse(sc.AuthURL) // validated at construction
	q := authURL.Query()
	q.Del("resource")
	q.Del("scope")
	q.Set("response_type", "code")
	if sc.Resource != "" {
		q.Set("resource", sc.Resource)
	}
	q.Set("client_id", sc.ClientID)
	q.Set("redirect_uri", sc.RedirectURL)
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	if len(sc.Scopes) > 0 {
		q.Set("scope", strings.Join(sc.Scopes, " "))
	}
	authURL.RawQuery = q.Encode()
	return StartResult{AuthURL: authURL.String(), State: state}, nil
}

// ExchangeInput is the callback after IdP redirect.
type ExchangeInput struct {
	OwnerID string
	State   string
	Code    string
	Issuer  string // callback iss; required when ExpectedIssuer is configured
}

// Exchange consumes pending state, exchanges the code, and stores sealed tokens.
func (s *Service) Exchange(ctx context.Context, in ExchangeInput) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if in.OwnerID == "" || in.State == "" || in.Code == "" {
		return ErrInvalid
	}
	pending, err := s.store.TakePending(ctx, sha256.Sum256([]byte(in.State)))
	if err != nil {
		return err
	}
	if pending.OwnerID != in.OwnerID {
		return ErrDenied
	}
	if !pending.ExpiresAt.After(s.now().UTC()) {
		return ErrExpired
	}
	sc, ok := s.servers[pending.ServerID]
	if !ok {
		return ErrNotFound
	}
	if sc.ExpectedIssuer != "" {
		if in.Issuer != sc.ExpectedIssuer {
			return ErrDenied
		}
	} else if in.Issuer != "" {
		return ErrDenied
	}
	if pending.Generation == "" {
		return ErrConflict
	}
	secrets, expires, err := s.tokenRequest(ctx, sc, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {in.Code},
		"redirect_uri":  {sc.RedirectURL},
		"client_id":     {sc.ClientID},
		"code_verifier": {pending.Verifier},
	})
	if err != nil {
		return err
	}
	ct, err := s.seal(secrets)
	if err != nil {
		return fmt.Errorf("seal token: %w", err)
	}
	now := s.now().UTC()
	return s.store.CompleteToken(ctx, TokenRecord{
		Generation: pending.Generation, Version: 0,
		OwnerID: in.OwnerID, ServerID: pending.ServerID,
		Ciphertext: ct, ExpiresAt: expires, UpdatedAt: now,
	})
}

// ValidToken returns plaintext secrets, refreshing when within margin.
func (s *Service) ValidToken(ctx context.Context, ownerID, serverID string) (TokenSecrets, error) {
	if err := ctx.Err(); err != nil {
		return TokenSecrets{}, err
	}
	rec, err := s.store.LookupToken(ctx, ownerID, serverID)
	if err != nil {
		return TokenSecrets{}, err
	}
	secrets, err := s.open(rec.Ciphertext)
	if err != nil {
		return TokenSecrets{}, fmt.Errorf("%w: open token", ErrDenied)
	}
	if rec.ExpiresAt.After(s.now().UTC().Add(s.cfg.RefreshMargin)) {
		return secrets, nil
	}
	if secrets.RefreshToken == "" {
		return TokenSecrets{}, ErrExpired
	}
	sc, ok := s.servers[serverID]
	if !ok {
		return TokenSecrets{}, ErrNotFound
	}
	rec, err = s.store.ClaimRefresh(ctx, rec)
	if err != nil {
		return TokenSecrets{}, err
	}
	// Never release this claim on error: even a network error can hide rotation.
	refreshed, expires, err := s.tokenRequest(ctx, sc, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {secrets.RefreshToken},
		"client_id":     {sc.ClientID},
	})
	if err != nil {
		return TokenSecrets{}, err
	}
	if refreshed.RefreshToken == "" {
		refreshed.RefreshToken = secrets.RefreshToken
	}
	ct, err := s.seal(refreshed)
	if err != nil {
		return TokenSecrets{}, err
	}
	now := s.now().UTC()
	if err := s.store.CompleteToken(ctx, TokenRecord{
		Generation: rec.Generation, Version: rec.Version,
		OwnerID: ownerID, ServerID: serverID,
		Ciphertext: ct, ExpiresAt: expires, UpdatedAt: now,
	}); err != nil {
		return TokenSecrets{}, err
	}
	return refreshed, nil
}

// Revoke invalidates locally before best-effort provider revocation. A successful
// return establishes local disconnection only, not provider revocation.
func (s *Service) Revoke(ctx context.Context, ownerID, serverID string) error {
	if ownerID == "" || serverID == "" {
		return ErrInvalid
	}
	rec, err := s.store.Disconnect(ctx, ownerID, serverID)
	if err != nil {
		return err
	}
	sc, ok := s.servers[serverID]
	if ok && sc.RevokeURL != "" && len(rec.Ciphertext) != 0 {
		secrets, openErr := s.open(rec.Ciphertext)
		if openErr == nil {
			_ = s.revokeAtProvider(ctx, sc, secrets)
		}
	}
	return nil
}

func (s *Service) revokeAtProvider(ctx context.Context, sc ServerConfig, secrets TokenSecrets) error {
	token := secrets.RefreshToken
	if token == "" {
		token = secrets.AccessToken
	}
	if token == "" {
		return nil
	}
	form := url.Values{"token": {token}, "client_id": {sc.ClientID}}
	if sc.ClientSecret != "" {
		form.Set("client_secret", sc.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sc.RevokeURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ErrDenied
	}
	return nil
}

func (s *Service) tokenRequest(ctx context.Context, sc ServerConfig, form url.Values) (TokenSecrets, time.Time, error) {
	if sc.ClientSecret != "" {
		form.Set("client_secret", sc.ClientSecret)
	}
	if sc.Resource != "" {
		form.Set("resource", sc.Resource)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sc.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return TokenSecrets{}, time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		return TokenSecrets{}, time.Time{}, fmt.Errorf("token request: %w", ErrDenied)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return TokenSecrets{}, time.Time{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return TokenSecrets{}, time.Time{}, fmt.Errorf("%w: token endpoint status %d", ErrDenied, resp.StatusCode)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return TokenSecrets{}, time.Time{}, fmt.Errorf("%w: invalid token JSON", ErrDenied)
	}
	access := jsonString(raw, "access_token")
	if access == "" {
		return TokenSecrets{}, time.Time{}, fmt.Errorf("%w: missing access_token", ErrDenied)
	}
	secrets := TokenSecrets{
		AccessToken:  access,
		RefreshToken: jsonString(raw, "refresh_token"),
		TokenType:    jsonString(raw, "token_type"),
	}
	if scope := jsonString(raw, "scope"); scope != "" {
		secrets.Scopes = strings.Fields(scope)
	}
	expires := s.now().UTC().Add(time.Hour)
	if v, ok := raw["expires_in"]; ok {
		var n float64
		if json.Unmarshal(v, &n) == nil && n > 0 {
			expires = s.now().UTC().Add(time.Duration(n) * time.Second)
		}
	}
	return secrets, expires, nil
}

func jsonString(m map[string]json.RawMessage, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	var s string
	if json.Unmarshal(v, &s) != nil {
		return ""
	}
	return s
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// PlainSeal is a test/dev seal that stores JSON without encryption.
// Production callers must supply real Seal/Open (KMS, libsodium, etc.).
func PlainSeal(s TokenSecrets) ([]byte, error) { return json.Marshal(s) }

// PlainOpen reverses PlainSeal.
func PlainOpen(b []byte) (TokenSecrets, error) {
	var s TokenSecrets
	err := json.Unmarshal(b, &s)
	return s, err
}
