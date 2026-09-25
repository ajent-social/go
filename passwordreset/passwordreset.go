// Package passwordreset issues and consumes single-use password-reset tokens.
//
// Status: CANDIDATE. Capability: identity.password-reset.
package passwordreset

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrInvalid  = errors.New("passwordreset: invalid input")
	ErrNotFound = errors.New("passwordreset: not found")
	ErrExists   = errors.New("passwordreset: already exists")
	ErrExpired  = errors.New("passwordreset: expired")
	ErrDenied   = errors.New("passwordreset: denied")
)

const (
	defaultTTL = time.Hour
	maxTTL     = 24 * time.Hour
	tokenBytes = 32
)

// Challenge is storage-only.
type Challenge struct {
	TokenDigest [32]byte
	AccountID   string
	ExpiresAt   time.Time
	CreatedAt   time.Time
}

// Store persists hashed challenges. Consume deletes atomically.
type Store interface {
	Put(context.Context, Challenge) error
	Consume(context.Context, [32]byte) (Challenge, error)
	InvalidateAccount(context.Context, string) error
}

// Notifier sends the reset link. Must not log the token.
type Notifier interface {
	SendResetLink(ctx context.Context, accountID, url string) error
}

// Config bounds lifetime.
type Config struct {
	TTL     time.Duration
	BaseURL string // e.g. https://app.example/auth/reset
}

// Service issues and consumes reset tokens.
type Service struct {
	cfg      Config
	store    Store
	notifier Notifier
	now      func() time.Time
}

// New constructs a Service. notifier may be nil if the caller sends mail using IssueResult.
func New(cfg Config, store Store, notifier Notifier) (*Service, error) {
	if store == nil {
		return nil, ErrInvalid
	}
	ttl := cfg.TTL
	if ttl == 0 {
		ttl = defaultTTL
	}
	if ttl < time.Minute || ttl > maxTTL {
		return nil, fmt.Errorf("%w: TTL out of range", ErrInvalid)
	}
	cfg.TTL = ttl
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, fmt.Errorf("%w: BaseURL required", ErrInvalid)
	}
	return &Service{cfg: cfg, store: store, notifier: notifier, now: time.Now}, nil
}

// IssueInput creates a reset challenge for an account.
type IssueInput struct {
	AccountID string
}

// IssueResult returns the plaintext token once.
type IssueResult struct {
	Token   string
	URL     string
	Expires time.Time
}

// Issue stores a hashed challenge and optionally notifies.
func (s *Service) Issue(ctx context.Context, in IssueInput) (IssueResult, error) {
	if err := ctx.Err(); err != nil {
		return IssueResult{}, err
	}
	if strings.TrimSpace(in.AccountID) == "" {
		return IssueResult{}, ErrInvalid
	}
	token, err := randomToken()
	if err != nil {
		return IssueResult{}, err
	}
	now := s.now().UTC()
	ch := Challenge{
		TokenDigest: sha256.Sum256([]byte(token)),
		AccountID:   in.AccountID,
		ExpiresAt:   now.Add(s.cfg.TTL),
		CreatedAt:   now,
	}
	_ = s.store.InvalidateAccount(ctx, in.AccountID)
	if err := s.store.Put(ctx, ch); err != nil {
		return IssueResult{}, err
	}
	link := strings.TrimRight(s.cfg.BaseURL, "/") + "#" + token
	if s.notifier != nil {
		if err := s.notifier.SendResetLink(ctx, in.AccountID, link); err != nil {
			return IssueResult{}, err
		}
	}
	return IssueResult{Token: token, URL: link, Expires: ch.ExpiresAt}, nil
}

// Consume validates and burns a plaintext token.
func (s *Service) Consume(ctx context.Context, token string) (Challenge, error) {
	if err := ctx.Err(); err != nil {
		return Challenge{}, err
	}
	if token == "" {
		return Challenge{}, ErrInvalid
	}
	ch, err := s.store.Consume(ctx, sha256.Sum256([]byte(token)))
	if err != nil {
		return Challenge{}, err
	}
	if !ch.ExpiresAt.After(s.now().UTC()) {
		return Challenge{}, ErrExpired
	}
	return ch, nil
}

func randomToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
