// Package servicecred implements scoped, revocable machine credentials.
// It is not a login system or authorization policy engine. Callers must derive
// grants and requirements from trusted policy, never from untrusted requests.
package servicecred

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"time"
)

var (
	ErrDenied   = errors.New("credential denied")
	ErrNotFound = errors.New("credential not found")
	ErrExists   = errors.New("credential already exists")
	ErrInvalid  = errors.New("invalid credential configuration")
)

// Access has exact, case-sensitive bindings. Scopes have no wildcard semantics.
type Access struct {
	Owner    string   `json:"owner"`
	Resource string   `json:"resource"`
	Scopes   []string `json:"scopes"`
}
type Grant struct {
	Access
	ExpiresAt time.Time `json:"expires_at"`
}

// Metadata contains no bearer secret or verifier and is safe for authorized listing.
type Metadata struct {
	ID string `json:"id"`
	Grant
	CreatedAt time.Time `json:"created_at"`
	RevokedAt time.Time `json:"revoked_at,omitzero"`
}

// Record is storage-only. Never return it from management endpoints.
type Record struct {
	Metadata
	Digest [32]byte `json:"digest"`
}

// Store must atomically create without overwrite, read authoritative committed
// state without caching, and revoke only an exact owner/resource match. Revoke
// is idempotent and must not alter grants. Successful writes must be durable.
// Missing records return ErrNotFound; collisions return ErrExists.
type Store interface {
	Create(context.Context, Record) error
	Lookup(context.Context, string) (Record, error)
	Revoke(context.Context, string, string, string, time.Time) error
	List(context.Context, string, string) ([]Metadata, error)
}

// Secret redacts ordinary formatting and serialization. Reveal is explicit;
// callers must protect its result. Go cannot guarantee secret-memory erasure.
type Secret struct{ reveal func() string }

func (Secret) String() string               { return "[REDACTED]" }
func (Secret) GoString() string             { return "[REDACTED]" }
func (Secret) Format(w fmt.State, _ rune)   { _, _ = io.WriteString(w, "[REDACTED]") }
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"[REDACTED]"`), nil }
func (Secret) MarshalText() ([]byte, error) { return []byte("[REDACTED]"), nil }
func (Secret) LogValue() slog.Value         { return slog.StringValue("[REDACTED]") }
func (s Secret) Reveal() string {
	if s.reveal == nil {
		return ""
	}
	return s.reveal()
}

type Service struct {
	store Store
	now   func() time.Time
}

func New(store Store) (*Service, error) {
	if store == nil {
		return nil, ErrInvalid
	}
	return &Service{store: store, now: time.Now}, nil
}
func validAccess(a Access) bool {
	if !validName(a.Owner) || !validName(a.Resource) || len(a.Scopes) == 0 || len(a.Scopes) > 64 {
		return false
	}
	seen := map[string]bool{}
	for _, s := range a.Scopes {
		if !validName(s) || seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}
func validName(s string) bool {
	return len(s) > 0 && len(s) <= 256 && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\x00\r\n")
}
func contains(parent, child Access) bool {
	if parent.Owner != child.Owner || parent.Resource != child.Resource {
		return false
	}
	for _, scope := range child.Scopes {
		if !slices.Contains(parent.Scopes, scope) {
			return false
		}
	}
	return true
}

// Issue narrows a caller-authorized ceiling. The caller must authenticate and
// authorize that ceiling first. This method is not a remote issuance endpoint.
// Lost issuance responses are not recoverable: revoke by metadata ID and reissue.
func (s *Service) Issue(ctx context.Context, ceiling, requested Grant) (Secret, Metadata, error) {
	if err := ctx.Err(); err != nil {
		return Secret{}, Metadata{}, err
	}
	now := s.now().UTC()
	if !validAccess(ceiling.Access) || !validAccess(requested.Access) || !requested.ExpiresAt.After(now) || !ceiling.ExpiresAt.After(now) {
		return Secret{}, Metadata{}, ErrInvalid
	}
	if !contains(ceiling.Access, requested.Access) || requested.ExpiresAt.After(ceiling.ExpiresAt) {
		return Secret{}, Metadata{}, ErrDenied
	}
	var idBytes [16]byte
	var secretBytes [32]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return Secret{}, Metadata{}, fmt.Errorf("generate credential ID: %w", err)
	}
	if _, err := rand.Read(secretBytes[:]); err != nil {
		return Secret{}, Metadata{}, fmt.Errorf("generate credential secret: %w", err)
	}
	id := hex.EncodeToString(idBytes[:])
	raw := "amsl1_" + id + "_" + hex.EncodeToString(secretBytes[:])
	requested.Scopes = slices.Clone(requested.Scopes)
	m := Metadata{ID: id, Grant: requested, CreatedAt: now}
	record := Record{Metadata: m, Digest: sha256.Sum256([]byte(raw))}
	if err := s.store.Create(ctx, record); err != nil {
		return Secret{}, Metadata{}, fmt.Errorf("persist credential: %w", err)
	}
	return Secret{reveal: func() string { return raw }}, m, nil
}

// List returns sanitized metadata for one exact, caller-authorized binding.
// Callers must authorize access before requesting the list.
func (s *Service) List(ctx context.Context, owner, resource string) ([]Metadata, error) {
	if !validName(owner) || !validName(resource) {
		return nil, ErrInvalid
	}
	items, err := s.store.List(ctx, owner, resource)
	if err != nil {
		return nil, fmt.Errorf("list credentials: %w", err)
	}
	for i := range items {
		items[i].Scopes = slices.Clone(items[i].Scopes)
	}
	return items, nil
}

// Verify checks the secret, current stored grant, expiry, revocation and every
// required scope. Caller-owned account status/authorization must also be checked.
// Revocation prevents later verifications, not already authorized work.
func (s *Service) Verify(ctx context.Context, raw string, required Access) (Metadata, error) {
	if err := ctx.Err(); err != nil {
		return Metadata{}, err
	}
	if !validAccess(required) {
		return Metadata{}, ErrInvalid
	}
	if len(raw) != 103 || !strings.HasPrefix(raw, "amsl1_") || raw[38] != '_' {
		return Metadata{}, ErrDenied
	}
	id := raw[6:38]
	if _, err := hex.DecodeString(id + raw[39:]); err != nil || strings.ToLower(raw) != raw {
		return Metadata{}, ErrDenied
	}
	r, err := s.store.Lookup(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return Metadata{}, ErrDenied
	}
	if err != nil {
		return Metadata{}, fmt.Errorf("lookup credential: %w", err)
	}
	digest := sha256.Sum256([]byte(raw))
	if subtle.ConstantTimeCompare(digest[:], r.Digest[:]) != 1 || r.ID != id || !validAccess(r.Access) || !contains(r.Access, required) || !r.RevokedAt.IsZero() || !r.ExpiresAt.After(s.now()) || r.CreatedAt.IsZero() || !r.ExpiresAt.After(r.CreatedAt) {
		return Metadata{}, ErrDenied
	}
	r.Scopes = slices.Clone(r.Scopes)
	return r.Metadata, nil
}

// Revoke requires a caller-authorized exact binding. There is no bearer-based
// delegation or management API; possession of a credential cannot mint another.
func (s *Service) Revoke(ctx context.Context, owner, resource, id string) error {
	if !validName(owner) || !validName(resource) || len(id) != 32 {
		return ErrInvalid
	}
	if _, err := hex.DecodeString(id); err != nil {
		return ErrInvalid
	}
	if err := s.store.Revoke(ctx, id, owner, resource, s.now().UTC()); err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrDenied) {
			return ErrDenied
		}
		return fmt.Errorf("revoke credential: %w", err)
	}
	return nil
}
