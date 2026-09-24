package memory

import (
	"context"
	"sync"
	"time"

	"github.com/ajent-social/go/publishablekey"
)

// Store is a process-local publishablekey.Store.
type Store struct {
	mu      sync.Mutex
	byID    map[string]publishablekey.Key
	byDigest map[[32]byte]string
}

// New returns an empty Store.
func New() *Store {
	return &Store{
		byID: map[string]publishablekey.Key{},
		byDigest: map[[32]byte]string{},
	}
}

func (s *Store) Create(_ context.Context, k publishablekey.Key) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[k.ID]; ok {
		return publishablekey.ErrExists
	}
	if _, ok := s.byDigest[k.Digest]; ok {
		return publishablekey.ErrExists
	}
	s.byID[k.ID] = k
	s.byDigest[k.Digest] = k.ID
	return nil
}

func (s *Store) Lookup(_ context.Context, id string) (publishablekey.Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.byID[id]
	if !ok {
		return publishablekey.Key{}, publishablekey.ErrNotFound
	}
	return k, nil
}

func (s *Store) LookupByDigest(_ context.Context, d [32]byte) (publishablekey.Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byDigest[d]
	if !ok {
		return publishablekey.Key{}, publishablekey.ErrNotFound
	}
	return s.byID[id], nil
}

func (s *Store) Revoke(_ context.Context, id, ownerID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.byID[id]
	if !ok || k.OwnerID != ownerID {
		return publishablekey.ErrNotFound
	}
	if k.RevokedAt.IsZero() {
		k.RevokedAt = at
		s.byID[id] = k
	}
	return nil
}

var _ publishablekey.Store = (*Store)(nil)
