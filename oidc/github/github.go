// Package github provides a non-OIDC OAuth 2.0 adapter for GitHub login that
// produces oidc.Identity and shares oidc.Store for pending state and bindings.
//
// Status: CANDIDATE. Capability: identity.oidc-social (GitHub adapter).
package github

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

	"github.com/ajent-social/go/oidc"
)

const (
	defaultAuthURL  = "https://github.com/login/oauth/authorize"
	defaultTokenURL = "https://github.com/login/oauth/access_token"
	defaultUserURL  = "https://api.github.com/user"
	defaultEmailURL = "https://api.github.com/user/emails"
	providerID      = oidc.ProviderID("github")
	stateBytes      = 32
)

// Config for GitHub OAuth.
type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string // absolute https or loopback http
	AuthURL      string // optional override
	TokenURL     string
	UserURL      string
	EmailURL     string
	Scopes       []string // default: read:user user:email
	StateTTL     time.Duration
	HTTPClient   *http.Client
}

// Service runs GitHub OAuth and uses oidc.Store for pending + bindings.
type Service struct {
	cfg   Config
	store oidc.Store
	http  *http.Client
	now   func() time.Time
}

// New validates config.
func New(cfg Config, store oidc.Store) (*Service, error) {
	if store == nil || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, oidc.ErrInvalid
	}
	if err := validateRedirect(cfg.RedirectURI); err != nil {
		return nil, err
	}
	if cfg.AuthURL == "" {
		cfg.AuthURL = defaultAuthURL
	}
	if cfg.TokenURL == "" {
		cfg.TokenURL = defaultTokenURL
	}
	if cfg.UserURL == "" {
		cfg.UserURL = defaultUserURL
	}
	if cfg.EmailURL == "" {
		cfg.EmailURL = defaultEmailURL
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"read:user", "user:email"}
	}
	ttl := cfg.StateTTL
	if ttl == 0 {
		ttl = 10 * time.Minute
	}
	if ttl < time.Minute || ttl > 30*time.Minute {
		return nil, fmt.Errorf("%w: StateTTL out of range", oidc.ErrInvalid)
	}
	cfg.StateTTL = ttl
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	return &Service{cfg: cfg, store: store, http: hc, now: time.Now}, nil
}

func validateRedirect(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Fragment != "" {
		return fmt.Errorf("%w: RedirectURI must be absolute without fragment", oidc.ErrInvalid)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		h := u.Hostname()
		if h == "localhost" || h == "127.0.0.1" || h == "::1" {
			return nil
		}
		return fmt.Errorf("%w: http RedirectURI only on loopback", oidc.ErrInvalid)
	default:
		return fmt.Errorf("%w: unsupported RedirectURI scheme", oidc.ErrInvalid)
	}
}

// StartResult for the browser.
type StartResult struct {
	AuthURL string
	State   string
}

// Start begins GitHub OAuth.
func (s *Service) Start(ctx context.Context) (StartResult, error) {
	if err := ctx.Err(); err != nil {
		return StartResult{}, err
	}
	state, err := randomToken()
	if err != nil {
		return StartResult{}, err
	}
	now := s.now().UTC()
	if err := s.store.PutPending(ctx, oidc.Pending{
		StateDigest: sha256.Sum256([]byte(state)),
		Provider:    providerID,
		ExpiresAt:   now.Add(s.cfg.StateTTL),
		CreatedAt:   now,
	}); err != nil {
		return StartResult{}, err
	}
	q := url.Values{
		"client_id":    {s.cfg.ClientID},
		"redirect_uri": {s.cfg.RedirectURI},
		"scope":        {strings.Join(s.cfg.Scopes, " ")},
		"state":        {state},
	}
	return StartResult{AuthURL: s.cfg.AuthURL + "?" + q.Encode(), State: state}, nil
}

// Accept exchanges the code and returns oidc.Identity.
func (s *Service) Accept(ctx context.Context, state, code string) (oidc.Identity, error) {
	if err := ctx.Err(); err != nil {
		return oidc.Identity{}, err
	}
	if state == "" || code == "" {
		return oidc.Identity{}, oidc.ErrInvalid
	}
	pending, err := s.store.TakePending(ctx, sha256.Sum256([]byte(state)))
	if err != nil {
		return oidc.Identity{}, err
	}
	if pending.Provider != providerID {
		return oidc.Identity{}, oidc.ErrDenied
	}
	if !pending.ExpiresAt.After(s.now().UTC()) {
		return oidc.Identity{}, oidc.ErrExpired
	}
	token, err := s.exchange(ctx, code)
	if err != nil {
		return oidc.Identity{}, err
	}
	user, err := s.fetchUser(ctx, token)
	if err != nil {
		return oidc.Identity{}, err
	}
	email, verified, err := s.fetchEmail(ctx, token, user.Email)
	if err != nil {
		return oidc.Identity{}, err
	}
	return oidc.Identity{
		Provider:      providerID,
		Subject:       fmt.Sprintf("%d", user.ID),
		Email:         email,
		EmailVerified: verified,
		Name:          user.Name,
	}, nil
}

// LinkBinding delegates to oidc.Service semantics via store.
func (s *Service) LinkBinding(ctx context.Context, subject, accountID string) error {
	if subject == "" || accountID == "" {
		return oidc.ErrInvalid
	}
	existing, err := s.store.LookupBinding(ctx, providerID, subject)
	if err == nil {
		if existing.AccountID == accountID {
			return nil
		}
		return oidc.ErrExists
	}
	if !errors.Is(err, oidc.ErrNotFound) {
		return err
	}
	return s.store.PutBinding(ctx, oidc.Binding{
		Provider: providerID, Subject: subject, AccountID: accountID, CreatedAt: s.now().UTC(),
	})
}

type ghUser struct {
	ID    int64  `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
	Login string `json:"login"`
}

func (s *Service) exchange(ctx context.Context, code string) (string, error) {
	form := url.Values{
		"client_id": {s.cfg.ClientID}, "client_secret": {s.cfg.ClientSecret},
		"code": {code}, "redirect_uri": {s.cfg.RedirectURI},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: token exchange", oidc.ErrDenied)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("%w: token status %d", oidc.ErrDenied, resp.StatusCode)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.AccessToken == "" {
		return "", fmt.Errorf("%w: missing access_token", oidc.ErrDenied)
	}
	return out.AccessToken, nil
}

func (s *Service) fetchUser(ctx context.Context, token string) (ghUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.UserURL, nil)
	if err != nil {
		return ghUser{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		return ghUser{}, fmt.Errorf("%w: user", oidc.ErrDenied)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return ghUser{}, fmt.Errorf("%w: user status %d", oidc.ErrDenied, resp.StatusCode)
	}
	var u ghUser
	if err := json.Unmarshal(body, &u); err != nil || u.ID == 0 {
		return ghUser{}, fmt.Errorf("%w: invalid user", oidc.ErrDenied)
	}
	if u.Name == "" {
		u.Name = u.Login
	}
	return u, nil
}

func (s *Service) fetchEmail(ctx context.Context, token, fallback string) (string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.EmailURL, nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(fallback)), fallback != "", nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return strings.ToLower(strings.TrimSpace(fallback)), fallback != "", nil
	}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.Unmarshal(body, &emails); err != nil {
		return strings.ToLower(strings.TrimSpace(fallback)), fallback != "", nil
	}
	for _, e := range emails {
		if e.Primary && e.Verified {
			return strings.ToLower(strings.TrimSpace(e.Email)), true, nil
		}
	}
	for _, e := range emails {
		if e.Verified {
			return strings.ToLower(strings.TrimSpace(e.Email)), true, nil
		}
	}
	fb := strings.ToLower(strings.TrimSpace(fallback))
	return fb, fb != "", nil
}

func randomToken() (string, error) {
	b := make([]byte, stateBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
