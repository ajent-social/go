package memory

import (
	"context"
	"sync"

	"github.com/ajent-social/go/mcpclientoauth"
)

// Store is a process-local mcpclientoauth.Store.
type Store struct {
	mu      sync.Mutex
	pending map[[32]byte]mcpclientoauth.Pending
	tokens  map[string]mcpclientoauth.TokenRecord // owner\0server
}

// New returns an empty Store.
func New() *Store {
	return &Store{
		pending: map[[32]byte]mcpclientoauth.Pending{},
		tokens:  map[string]mcpclientoauth.TokenRecord{},
	}
}

func tokenKey(owner, server string) string { return owner + "\x00" + server }

func (s *Store) PutPending(_ context.Context, p mcpclientoauth.Pending) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.pending[p.StateDigest]; ok {
		return mcpclientoauth.ErrExists
	}
	s.pending[p.StateDigest] = p
	return nil
}

func (s *Store) TakePending(_ context.Context, digest [32]byte) (mcpclientoauth.Pending, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[digest]
	if !ok {
		return mcpclientoauth.Pending{}, mcpclientoauth.ErrNotFound
	}
	delete(s.pending, digest)
	return p, nil
}

func (s *Store) PutToken(_ context.Context, t mcpclientoauth.TokenRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[tokenKey(t.OwnerID, t.ServerID)] = t
	return nil
}

func (s *Store) LookupToken(_ context.Context, ownerID, serverID string) (mcpclientoauth.TokenRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[tokenKey(ownerID, serverID)]
	if !ok {
		return mcpclientoauth.TokenRecord{}, mcpclientoauth.ErrNotFound
	}
	return t, nil
}

func (s *Store) DeleteToken(_ context.Context, ownerID, serverID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, tokenKey(ownerID, serverID))
	return nil
}

var _ mcpclientoauth.Store = (*Store)(nil)
