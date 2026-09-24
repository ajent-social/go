// Package publishablekey issues browser-embeddable public identifiers with
// hashed storage and optional origin allowlists.
//
// Status: CANDIDATE. Capability: identity.publishable-key.
package publishablekey

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

var (
	ErrInvalid  = errors.New("publishablekey: invalid input")
	ErrNotFound = errors.New("publishablekey: not found")
	ErrExists   = errors.New("publishablekey: already exists")
	ErrDenied   = errors.New("publishablekey: denied")
	ErrExpired  = errors.New("publishablekey: expired")
)

const (
	defaultPrefix = "pk_"
	secretBytes   = 24
	idBytes       = 16
)

// Key is storage metadata (no plaintext secret).
type Key struct {
	ID             string
	OwnerID        string
	Prefix         string
	Digest         [32]byte
	AllowedOrigins []string
	Scopes         []string
	ExpiresAt      time.Time // zero = no expiry
	CreatedAt      time.Time
	RevokedAt      time.Time
}

// Store persists keys.
type Store interface {
	Create(context.Context, Key) error
	Lookup(context.Context, string) (Key, error)
	LookupByDigest(context.Context, [32]byte) (Key, error)
	Revoke(ctx context.Context, id, ownerID string, at time.Time) error
}

// Config for issuance.
type Config struct {
	Prefix string // default pk_
}

// Service issues and verifies publishable keys.
type Service struct {
	cfg  Config
	store Store
	now  func() time.Time
}

// New constructs a Service.
func New(cfg Config, store Store) (*Service, error) {
	if store == nil {
		return nil, ErrInvalid
	}
	if cfg.Prefix == "" {
		cfg.Prefix = defaultPrefix
	}
	if strings.ContainsAny(cfg.Prefix, " \t\n") {
		return nil, fmt.Errorf("%w: invalid Prefix", ErrInvalid)
	}
	return &Service{cfg: cfg, store: store, now: time.Now}, nil
}

// IssueInput creates a key.
type IssueInput struct {
	OwnerID        string
	AllowedOrigins []string
	Scopes         []string
	TTL            time.Duration // 0 = no expiry
}

// IssueResult returns plaintext once.
type IssueResult struct {
	Key       Key
	Plaintext string
}

// Issue creates a hashed key. Plaintext is prefix + hex secret.
func (s *Service) Issue(ctx context.Context, in IssueInput) (IssueResult, error) {
	if err := ctx.Err(); err != nil {
		return IssueResult{}, err
	}
	if in.OwnerID == "" {
		return IssueResult{}, ErrInvalid
	}
	for _, o := range in.AllowedOrigins {
		if err := validateOriginPattern(o); err != nil {
			return IssueResult{}, err
		}
	}
	id, err := randomHex(idBytes)
	if err != nil {
		return IssueResult{}, err
	}
	secret, err := randomHex(secretBytes)
	if err != nil {
		return IssueResult{}, err
	}
	plain := s.cfg.Prefix + secret
	now := s.now().UTC()
	k := Key{
		ID: id, OwnerID: in.OwnerID, Prefix: s.cfg.Prefix,
		Digest: sha256.Sum256([]byte(plain)),
		AllowedOrigins: append([]string(nil), in.AllowedOrigins...),
		Scopes: append([]string(nil), in.Scopes...),
		CreatedAt: now,
	}
	if in.TTL > 0 {
		k.ExpiresAt = now.Add(in.TTL)
	}
	if err := s.store.Create(ctx, k); err != nil {
		return IssueResult{}, err
	}
	return IssueResult{Key: k, Plaintext: plain}, nil
}

// VerifyInput checks a presented key and optional Origin header value.
type VerifyInput struct {
	Plaintext string
	Origin    string // from Origin header; empty skips origin check
}

// Verify returns the key if valid. Origin must match allowlist when set on key.
func (s *Service) Verify(ctx context.Context, in VerifyInput) (Key, error) {
	if err := ctx.Err(); err != nil {
		return Key{}, err
	}
	if in.Plaintext == "" || !strings.HasPrefix(in.Plaintext, s.cfg.Prefix) {
		return Key{}, ErrDenied
	}
	digest := sha256.Sum256([]byte(in.Plaintext))
	k, err := s.store.LookupByDigest(ctx, digest)
	if err != nil {
		return Key{}, ErrDenied
	}
	if subtle.ConstantTimeCompare(k.Digest[:], digest[:]) != 1 {
		return Key{}, ErrDenied
	}
	if !k.RevokedAt.IsZero() {
		return Key{}, ErrDenied
	}
	if !k.ExpiresAt.IsZero() && !k.ExpiresAt.After(s.now().UTC()) {
		return Key{}, ErrExpired
	}
	if len(k.AllowedOrigins) > 0 {
		if in.Origin == "" || !OriginAllowed(in.Origin, k.AllowedOrigins) {
			return Key{}, ErrDenied
		}
	}
	return k, nil
}

// Revoke marks a key revoked.
func (s *Service) Revoke(ctx context.Context, id, ownerID string) error {
	return s.store.Revoke(ctx, id, ownerID, s.now().UTC())
}

// OriginAllowed reports whether requestOrigin matches any pattern.
// Patterns are absolute origins (https://app.example.com) or subdomain
// wildcards (https://*.example.com). Never pass request Host as a pattern.
func OriginAllowed(requestOrigin string, patterns []string) bool {
	req, err := url.Parse(requestOrigin)
	if err != nil || req.Scheme == "" || req.Host == "" {
		return false
	}
	reqOrigin := strings.ToLower(req.Scheme + "://" + req.Host)
	for _, p := range patterns {
		p = strings.TrimSpace(strings.ToLower(p))
		if p == reqOrigin {
			return true
		}
		if strings.Contains(p, "://*.") {
			if originMatchesWildcard(reqOrigin, p) {
				return true
			}
		}
	}
	return false
}

func originMatchesWildcard(reqOrigin, pat string) bool {
	// pat like https://*.example.com or https://*.example.com:8443
	u, err := url.Parse(pat)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if !strings.HasPrefix(host, "*.") {
		return false
	}
	suffix := host[1:] // .example.com
	ru, err := url.Parse(reqOrigin)
	if err != nil || ru.Scheme != u.Scheme {
		return false
	}
	if effectivePort(ru) != effectivePort(u) {
		return false
	}
	h := ru.Hostname()
	if !strings.HasSuffix(h, suffix) {
		return false
	}
	prefix := strings.TrimSuffix(h, suffix)
	return prefix != "" && !strings.Contains(prefix, ".")
}

func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch u.Scheme {
	case "https":
		return "443"
	case "http":
		return "80"
	default:
		return ""
	}
}

func validateOriginPattern(p string) error {
	p = strings.TrimSpace(p)
	if p == "" {
		return ErrInvalid
	}
	if strings.Contains(p, "://*.") {
		u, err := url.Parse(p)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
			return fmt.Errorf("%w: invalid wildcard origin", ErrInvalid)
		}
		if !strings.HasPrefix(u.Host, "*.") || len(u.Host) < 4 {
			return fmt.Errorf("%w: invalid wildcard host", ErrInvalid)
		}
		return nil
	}
	u, err := url.Parse(p)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Path != "" && u.Path != "/" {
		return fmt.Errorf("%w: origin must be scheme://host", ErrInvalid)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("%w: unsupported origin scheme", ErrInvalid)
	}
	return nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
