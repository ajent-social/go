package memory

import (
	"context"
	"sync"

	"github.com/ajent-social/go/oidc"
)

// Store is a process-local oidc.Store.
type Store struct {
	mu       sync.Mutex
	pending  map[[32]byte]oidc.Pending
	bindings map[string]oidc.Binding // provider\0subject
}

// New returns an empty Store.
func New() *Store {
	return &Store{
		pending:  map[[32]byte]oidc.Pending{},
		bindings: map[string]oidc.Binding{},
	}
}

func bindKey(p oidc.ProviderID, subject string) string {
	return string(p) + "\x00" + subject
}

func (s *Store) PutPending(_ context.Context, p oidc.Pending) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.pending[p.StateDigest]; ok {
		return oidc.ErrExists
	}
	s.pending[p.StateDigest] = p
	return nil
}

func (s *Store) TakePending(_ context.Context, digest [32]byte) (oidc.Pending, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[digest]
	if !ok {
		return oidc.Pending{}, oidc.ErrNotFound
	}
	delete(s.pending, digest)
	return p, nil
}

func (s *Store) PutBinding(_ context.Context, b oidc.Binding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := bindKey(b.Provider, b.Subject)
	if existing, ok := s.bindings[k]; ok && existing.AccountID != b.AccountID {
		return oidc.ErrExists
	}
	s.bindings[k] = b
	return nil
}

func (s *Store) LookupBinding(_ context.Context, provider oidc.ProviderID, subject string) (oidc.Binding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.bindings[bindKey(provider, subject)]
	if !ok {
		return oidc.Binding{}, oidc.ErrNotFound
	}
	return b, nil
}

func (s *Store) LookupBindingsByAccount(_ context.Context, accountID string) ([]oidc.Binding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []oidc.Binding
	for _, b := range s.bindings {
		if b.AccountID == accountID {
			out = append(out, b)
		}
	}
	return out, nil
}

var _ oidc.Store = (*Store)(nil)
