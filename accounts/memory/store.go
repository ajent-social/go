package memory

import (
	"context"
	"sync"

	"github.com/ajent-social/go/accounts"
)

// Store is a process-local accounts.Store.
type Store struct {
	mu       sync.Mutex
	byID     map[string]accounts.Account
	byEmail  map[string]string
}

// New returns an empty Store.
func New() *Store {
	return &Store{
		byID:    map[string]accounts.Account{},
		byEmail: map[string]string{},
	}
}

func (s *Store) Create(_ context.Context, a accounts.Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[a.ID]; ok {
		return accounts.ErrExists
	}
	if a.Email != "" {
		if _, ok := s.byEmail[a.Email]; ok {
			return accounts.ErrExists
		}
		s.byEmail[a.Email] = a.ID
	}
	s.byID[a.ID] = a
	return nil
}

func (s *Store) Lookup(_ context.Context, id string) (accounts.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.byID[id]
	if !ok {
		return accounts.Account{}, accounts.ErrNotFound
	}
	return a, nil
}

func (s *Store) LookupByEmail(_ context.Context, email string) (accounts.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byEmail[email]
	if !ok {
		return accounts.Account{}, accounts.ErrNotFound
	}
	return s.byID[id], nil
}

func (s *Store) Update(_ context.Context, a accounts.Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.byID[a.ID]
	if !ok {
		return accounts.ErrNotFound
	}
	if cur.Email != a.Email {
		if cur.Email != "" {
			delete(s.byEmail, cur.Email)
		}
		if a.Email != "" {
			if other, ok := s.byEmail[a.Email]; ok && other != a.ID {
				return accounts.ErrExists
			}
			s.byEmail[a.Email] = a.ID
		}
	}
	s.byID[a.ID] = a
	return nil
}

var _ accounts.Store = (*Store)(nil)
