// Package oidc coordinates OAuth 2.0 + OpenID Connect authorization-code
// login for social identity providers around the maintained go-oidc and
// golang.org/x/oauth2 libraries.
//
// It is not a session store, user directory, or entitlement engine. Callers
// verify the browser CSRF state, mint sessions after Accept, and map the
// returned Subject onto accounts.Account (or equivalent). Never derive
// redirect URIs or issuer trust from untrusted request Host headers.
//
// Status: CANDIDATE. Capability: identity.oidc-social.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var (
	ErrInvalid  = errors.New("oidc: invalid input")
	ErrNotFound = errors.New("oidc: not found")
	ErrExists   = errors.New("oidc: already exists")
	ErrDenied   = errors.New("oidc: denied")
	ErrExpired  = errors.New("oidc: expired")
)

const (
	defaultStateTTL = 10 * time.Minute
	maxStateTTL     = 30 * time.Minute
	stateBytes      = 32
)

// ProviderID names a configured IdP (google, github, apple, …).
type ProviderID string

// ProviderConfig is one OIDC/OAuth authorization server.
// GitHub is OAuth 2.0 without a standard OIDC userinfo ID token; set
// UserInfoURL and leave Issuer empty only when using a non-OIDC adapter
// registered via CustomUserInfo. Prefer full OIDC issuers when available.
type ProviderConfig struct {
	ID           ProviderID
	Issuer       string // required for OIDC (Google, Apple, …)
	ClientID     string
	ClientSecret string
	// RedirectURI must be an absolute https (or http loopback) URL owned by the app.
	RedirectURI string
	Scopes      []string // default openid email profile
}

// Config binds providers. StateTTL defaults to 10 minutes.
type Config struct {
	Providers []ProviderConfig
	StateTTL  time.Duration
}

// Identity is the verified subject after code exchange.
type Identity struct {
	Provider  ProviderID
	Subject   string // IdP subject (stable)
	Email     string
	EmailVerified bool
	Name      string
	RawClaims map[string]any // optional; may be nil
}

// Pending is storage-only. StateDigest is SHA-256 of the browser state value.
type Pending struct {
	StateDigest [32]byte
	Provider    ProviderID
	Nonce       string
	ExpiresAt   time.Time
	CreatedAt   time.Time
}

// Binding links an IdP subject to a local account id.
type Binding struct {
	Provider  ProviderID
	Subject   string
	AccountID string
	CreatedAt time.Time
}

// Store persists pending auth states and provider→account bindings.
type Store interface {
	PutPending(context.Context, Pending) error
	TakePending(context.Context, [32]byte) (Pending, error)
	PutBinding(context.Context, Binding) error
	LookupBinding(ctx context.Context, provider ProviderID, subject string) (Binding, error)
	LookupBindingsByAccount(ctx context.Context, accountID string) ([]Binding, error)
}

// Service starts and finishes OIDC authorization-code flows.
type Service struct {
	cfg       Config
	store     Store
	providers map[ProviderID]*providerRuntime
	now       func() time.Time
}

type providerRuntime struct {
	cfg      ProviderConfig
	verifier *gooidc.IDTokenVerifier
	oauth    oauth2.Config
}

// New discovers OIDC providers and validates config.
func New(ctx context.Context, cfg Config, store Store) (*Service, error) {
	if store == nil {
		return nil, ErrInvalid
	}
	ttl := cfg.StateTTL
	if ttl == 0 {
		ttl = defaultStateTTL
	}
	if ttl < time.Minute || ttl > maxStateTTL {
		return nil, fmt.Errorf("%w: StateTTL out of range", ErrInvalid)
	}
	cfg.StateTTL = ttl
	if len(cfg.Providers) == 0 {
		return nil, fmt.Errorf("%w: at least one provider required", ErrInvalid)
	}
	s := &Service{
		cfg:       cfg,
		store:     store,
		providers: map[ProviderID]*providerRuntime{},
		now:       time.Now,
	}
	for _, p := range cfg.Providers {
		rt, err := buildProvider(ctx, p)
		if err != nil {
			return nil, fmt.Errorf("provider %s: %w", p.ID, err)
		}
		if _, ok := s.providers[p.ID]; ok {
			return nil, fmt.Errorf("%w: duplicate provider %s", ErrInvalid, p.ID)
		}
		s.providers[p.ID] = rt
	}
	return s, nil
}

func buildProvider(ctx context.Context, p ProviderConfig) (*providerRuntime, error) {
	if strings.TrimSpace(string(p.ID)) == "" || p.ClientID == "" || p.ClientSecret == "" {
		return nil, ErrInvalid
	}
	if err := validateRedirectURI(p.RedirectURI); err != nil {
		return nil, err
	}
	scopes := p.Scopes
	if len(scopes) == 0 {
		scopes = []string{gooidc.ScopeOpenID, "email", "profile"}
	}
	if p.Issuer == "" {
		return nil, fmt.Errorf("%w: Issuer required (use a full OIDC issuer; non-OIDC providers need a separate adapter)", ErrInvalid)
	}
	provider, err := gooidc.NewProvider(ctx, p.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discover issuer: %w", err)
	}
	verifier := provider.Verifier(&gooidc.Config{ClientID: p.ClientID})
	oauth := oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  p.RedirectURI,
		Scopes:       scopes,
	}
	return &providerRuntime{cfg: p, verifier: verifier, oauth: oauth}, nil
}

func validateRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Fragment != "" {
		return fmt.Errorf("%w: RedirectURI must be an absolute URL without fragment", ErrInvalid)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
		return fmt.Errorf("%w: http RedirectURI only allowed on loopback", ErrInvalid)
	default:
		return fmt.Errorf("%w: unsupported RedirectURI scheme", ErrInvalid)
	}
}

// StartResult is returned to the browser.
type StartResult struct {
	AuthURL string
	State   string // set as cookie; store only digest
}

// Start begins an authorization-code flow for provider.
func (s *Service) Start(ctx context.Context, provider ProviderID) (StartResult, error) {
	if err := ctx.Err(); err != nil {
		return StartResult{}, err
	}
	rt, ok := s.providers[provider]
	if !ok {
		return StartResult{}, ErrNotFound
	}
	state, err := randomToken()
	if err != nil {
		return StartResult{}, err
	}
	nonce, err := randomToken()
	if err != nil {
		return StartResult{}, err
	}
	now := s.now().UTC()
	pending := Pending{
		StateDigest: sha256.Sum256([]byte(state)),
		Provider:    provider,
		Nonce:       nonce,
		ExpiresAt:   now.Add(s.cfg.StateTTL),
		CreatedAt:   now,
	}
	if err := s.store.PutPending(ctx, pending); err != nil {
		return StartResult{}, err
	}
	authURL := rt.oauth.AuthCodeURL(state, oauth2.AccessTypeOffline, gooidc.Nonce(nonce))
	return StartResult{AuthURL: authURL, State: state}, nil
}

// AcceptInput is the callback query after IdP redirect.
type AcceptInput struct {
	Provider ProviderID
	State    string
	Code     string
}

// Accept exchanges the code, verifies the ID token, and returns Identity.
// It does not create accounts or sessions.
func (s *Service) Accept(ctx context.Context, in AcceptInput) (Identity, error) {
	if err := ctx.Err(); err != nil {
		return Identity{}, err
	}
	if in.State == "" || in.Code == "" {
		return Identity{}, ErrInvalid
	}
	rt, ok := s.providers[in.Provider]
	if !ok {
		return Identity{}, ErrNotFound
	}
	pending, err := s.store.TakePending(ctx, sha256.Sum256([]byte(in.State)))
	if err != nil {
		return Identity{}, err
	}
	if pending.Provider != in.Provider {
		return Identity{}, ErrDenied
	}
	if !pending.ExpiresAt.After(s.now().UTC()) {
		return Identity{}, ErrExpired
	}
	token, err := rt.oauth.Exchange(ctx, in.Code)
	if err != nil {
		return Identity{}, fmt.Errorf("token exchange: %w", ErrDenied)
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok || rawID == "" {
		return Identity{}, fmt.Errorf("%w: missing id_token", ErrDenied)
	}
	idToken, err := rt.verifier.Verify(ctx, rawID)
	if err != nil {
		return Identity{}, fmt.Errorf("verify id_token: %w", ErrDenied)
	}
	if pending.Nonce != "" {
		var claims struct {
			Nonce string `json:"nonce"`
		}
		if err := idToken.Claims(&claims); err != nil || claims.Nonce != pending.Nonce {
			return Identity{}, ErrDenied
		}
	}
	var profile struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	_ = idToken.Claims(&profile)
	var raw map[string]any
	_ = idToken.Claims(&raw)
	return Identity{
		Provider:      in.Provider,
		Subject:       idToken.Subject,
		Email:         strings.TrimSpace(strings.ToLower(profile.Email)),
		EmailVerified: profile.EmailVerified,
		Name:          profile.Name,
		RawClaims:     raw,
	}, nil
}

// LinkBinding stores provider subject → account. Duplicate different account is ErrExists.
func (s *Service) LinkBinding(ctx context.Context, provider ProviderID, subject, accountID string) error {
	if provider == "" || subject == "" || accountID == "" {
		return ErrInvalid
	}
	existing, err := s.store.LookupBinding(ctx, provider, subject)
	if err == nil {
		if existing.AccountID == accountID {
			return nil
		}
		return ErrExists
	}
	if !errors.Is(err, ErrNotFound) {
		return err
	}
	return s.store.PutBinding(ctx, Binding{
		Provider: provider, Subject: subject, AccountID: accountID, CreatedAt: s.now().UTC(),
	})
}

// AccountFor returns the linked account id for an identity.
func (s *Service) AccountFor(ctx context.Context, id Identity) (string, error) {
	b, err := s.store.LookupBinding(ctx, id.Provider, id.Subject)
	if err != nil {
		return "", err
	}
	return b.AccountID, nil
}

func randomToken() (string, error) {
	b := make([]byte, stateBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
