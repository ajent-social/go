// Package magiclink issues and consumes single-use email sign-in challenges.
//
// Delivery is not included: callers implement Mailer (SMTP, provider SDK, etc.).
// This package owns hashed token storage, expiry and one-time consume. It is not
// a user directory or session mint — after Consume, the application creates a
// browser session (e.g. SCS) for the returned subject.
//
// Status: CANDIDATE. Capability: identity.magic-link.
package magiclink

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"
)

var (
	ErrInvalid  = errors.New("magiclink: invalid input")
	ErrNotFound = errors.New("magiclink: not found")
	ErrExists   = errors.New("magiclink: already exists")
	ErrExpired  = errors.New("magiclink: expired")
	ErrDenied   = errors.New("magiclink: denied")
)

const (
	defaultTTL = 15 * time.Minute
	maxTTL     = time.Hour
	tokenBytes = 32
)

// Purpose distinguishes login vs email-verify flows.
type Purpose string

const (
	PurposeLogin        Purpose = "login"
	PurposeVerifyEmail  Purpose = "verify_email"
)

// Challenge is storage-only. TokenDigest is SHA-256 of the plaintext token.
type Challenge struct {
	TokenDigest [32]byte
	Purpose     Purpose
	Email       string
	SubjectID   string // may be empty until first login creates an account
	ExpiresAt   time.Time
	CreatedAt   time.Time
}

// Store persists hashed challenges. Consume must delete and return atomically.
type Store interface {
	Put(context.Context, Challenge) error
	Consume(context.Context, [32]byte) (Challenge, error)
	// InvalidateEmail removes outstanding challenges for an email (optional hygiene).
	InvalidateEmail(context.Context, string, Purpose) error
}

// Mailer sends the plaintext link. Implementations must not log the token.
type Mailer interface {
	SendMagicLink(ctx context.Context, email, url string) error
}

// Config bounds challenge lifetime.
type Config struct {
	TTL time.Duration
	// BaseURL is the exact redeem origin+path prefix, e.g. https://app.example/auth/magic
	// The issued URL is BaseURL + "#" + token (fragment) unless AbsoluteURL is set by Issue options.
	BaseURL string
}

// Service issues and consumes challenges.
type Service struct {
	cfg    Config
	store  Store
	mailer Mailer
	now    func() time.Time
}

// New constructs a Service. mailer may be nil if the caller sends mail itself
// using the token from Issue.
func New(cfg Config, store Store, mailer Mailer) (*Service, error) {
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
	return &Service{cfg: cfg, store: store, mailer: mailer, now: time.Now}, nil
}

// IssueInput creates a challenge for email.
type IssueInput struct {
	Email     string
	Purpose   Purpose
	SubjectID string
}

// IssueResult returns the plaintext token once. Prefer sending via Mailer.
type IssueResult struct {
	Token   string
	URL     string
	Expires time.Time
}

// Issue stores a hashed challenge and optionally emails the link.
func (s *Service) Issue(ctx context.Context, in IssueInput) (IssueResult, error) {
	if err := ctx.Err(); err != nil {
		return IssueResult{}, err
	}
	email, err := normalizeEmail(in.Email)
	if err != nil {
		return IssueResult{}, err
	}
	if in.Purpose != PurposeLogin && in.Purpose != PurposeVerifyEmail {
		return IssueResult{}, ErrInvalid
	}
	token, err := randomToken()
	if err != nil {
		return IssueResult{}, err
	}
	now := s.now().UTC()
	ch := Challenge{
		TokenDigest: sha256.Sum256([]byte(token)),
		Purpose:     in.Purpose,
		Email:       email,
		SubjectID:   in.SubjectID,
		ExpiresAt:   now.Add(s.cfg.TTL),
		CreatedAt:   now,
	}
	_ = s.store.InvalidateEmail(ctx, email, in.Purpose)
	if err := s.store.Put(ctx, ch); err != nil {
		return IssueResult{}, err
	}
	link := strings.TrimRight(s.cfg.BaseURL, "/") + "#" + token
	if s.mailer != nil {
		if err := s.mailer.SendMagicLink(ctx, email, link); err != nil {
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
	digest := sha256.Sum256([]byte(token))
	ch, err := s.store.Consume(ctx, digest)
	if err != nil {
		return Challenge{}, err
	}
	if !ch.ExpiresAt.After(s.now().UTC()) {
		return Challenge{}, ErrExpired
	}
	return ch, nil
}

func normalizeEmail(raw string) (string, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" || len(raw) > 320 {
		return "", ErrInvalid
	}
	addr, err := mail.ParseAddress(raw)
	if err != nil || addr.Address != raw {
		return "", ErrInvalid
	}
	return raw, nil
}

func randomToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
