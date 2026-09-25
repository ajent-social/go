// Package apple helps configure Sign in with Apple for oidc.New.
//
// It generates the ES256 client-secret JWT required by Apple and exposes an
// issuer preset. Use with oidc.ProviderConfig{Issuer: apple.Issuer, ...}.
//
// Status: CANDIDATE. Capability: identity.oidc-social (Apple helper).
package apple

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Issuer is Apple's OIDC issuer.
const Issuer = "https://appleid.apple.com"

// ProviderID for oidc.ProviderConfig.ID.
const ProviderID = "apple"

// ErrInvalid reports bad Apple configuration input.
var ErrInvalid = errors.New("oidc/apple: invalid input")

// ClientSecretInput builds Apple's client secret JWT.
type ClientSecretInput struct {
	TeamID     string
	ClientID   string // Services ID
	KeyID      string
	PrivateKey []byte // PKCS8 PEM ECDSA P-256
	// TTL defaults to 180 days (Apple max). Max 180 days.
	TTL time.Duration
	Now func() time.Time
}

// ClientSecret returns a signed ES256 JWT for use as OAuth client_secret.
func ClientSecret(in ClientSecretInput) (string, error) {
	if in.TeamID == "" || in.ClientID == "" || in.KeyID == "" || len(in.PrivateKey) == 0 {
		return "", ErrInvalid
	}
	ttl := in.TTL
	if ttl == 0 {
		ttl = 180 * 24 * time.Hour
	}
	if ttl > 180*24*time.Hour {
		return "", fmt.Errorf("%w: TTL exceeds Apple maximum", ErrInvalid)
	}
	nowFn := in.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	key, err := parseECPrivateKey(in.PrivateKey)
	if err != nil {
		return "", err
	}
	now := nowFn().UTC()
	header := base64.RawURLEncoding.EncodeToString(mustJSON(map[string]string{
		"alg": "ES256", "kid": in.KeyID, "typ": "JWT",
	}))
	payload := base64.RawURLEncoding.EncodeToString(mustJSON(map[string]any{
		"iss": in.TeamID,
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
		"aud": Issuer,
		"sub": in.ClientID,
	}))
	signingInput := header + "." + payload
	sum := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		return "", err
	}
	sig := append(pad32(r.Bytes()), pad32(s.Bytes())...)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Preset returns a partial oidc provider config (caller sets ClientSecret via ClientSecret).
func Preset(clientID, redirectURI string) (issuer, id string, scopes []string, err error) {
	if clientID == "" || redirectURI == "" {
		return "", "", nil, ErrInvalid
	}
	return Issuer, ProviderID, []string{"openid", "email", "name"}, nil
}

func parseECPrivateKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, ErrInvalid
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: not ECDSA", ErrInvalid)
	}
	return ec, nil
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func pad32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// NormalizePrivateKeyPEM accepts PEM text with optional whitespace cleanup.
func NormalizePrivateKeyPEM(s string) []byte {
	return []byte(strings.TrimSpace(s) + "\n")
}
