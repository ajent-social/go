package memory

import (
	"context"
	"sync"

	"github.com/ajent-social/go/sealedvault"
)

// Store is a process-local sealedvault.Store.
type Store struct {
	mu   sync.Mutex
	byKey map[string]sealedvault.Record
}

// New returns an empty Store.
func New() *Store {
	return &Store{byKey: map[string]sealedvault.Record{}}
}

func key(owner, name string) string { return owner + "\x00" + name }

func (s *Store) Put(_ context.Context, r sealedvault.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byKey[key(r.Owner, r.Name)] = r
	return nil
}

func (s *Store) Get(_ context.Context, owner, name string) (sealedvault.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.byKey[key(owner, name)]
	if !ok {
		return sealedvault.Record{}, sealedvault.ErrNotFound
	}
	return r, nil
}

func (s *Store) Delete(_ context.Context, owner, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(owner, name)
	if _, ok := s.byKey[k]; !ok {
		return sealedvault.ErrNotFound
	}
	delete(s.byKey, k)
	return nil
}

var _ sealedvault.Store = (*Store)(nil)
