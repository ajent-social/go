package memory

import (
	"context"
	"sync"

	"github.com/ajent-social/go/tenant"
)

// Store is a process-local tenant.Store.
type Store struct {
	mu        sync.Mutex
	byID      map[string]tenant.Instance
	bySlug    map[string]string
	byAccount map[string]string
}

// New returns an empty Store.
func New() *Store {
	return &Store{
		byID:      map[string]tenant.Instance{},
		bySlug:    map[string]string{},
		byAccount: map[string]string{},
	}
}

func (s *Store) Create(_ context.Context, in tenant.Instance) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[in.ID]; ok {
		return tenant.ErrExists
	}
	if _, ok := s.bySlug[in.Slug]; ok {
		return tenant.ErrExists
	}
	if id, ok := s.byAccount[in.AccountID]; ok {
		if cur := s.byID[id]; cur.Status != tenant.StatusDestroyed {
			return tenant.ErrExists
		}
	}
	s.byID[in.ID] = in
	s.bySlug[in.Slug] = in.ID
	s.byAccount[in.AccountID] = in.ID
	return nil
}

func (s *Store) Lookup(_ context.Context, id string) (tenant.Instance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	in, ok := s.byID[id]
	if !ok {
		return tenant.Instance{}, tenant.ErrNotFound
	}
	return in, nil
}

func (s *Store) LookupBySlug(_ context.Context, slug string) (tenant.Instance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.bySlug[slug]
	if !ok {
		return tenant.Instance{}, tenant.ErrNotFound
	}
	return s.byID[id], nil
}

func (s *Store) LookupByAccount(_ context.Context, accountID string) (tenant.Instance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byAccount[accountID]
	if !ok {
		return tenant.Instance{}, tenant.ErrNotFound
	}
	return s.byID[id], nil
}

func (s *Store) Apply(_ context.Context, id string, expectedEpoch uint64, next tenant.Instance) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.byID[id]
	if !ok {
		return tenant.ErrNotFound
	}
	if cur.LeaseEpoch != expectedEpoch {
		return tenant.ErrConflict
	}
	next.LeaseEpoch = expectedEpoch + 1
	s.byID[id] = next
	s.bySlug[next.Slug] = id
	s.byAccount[next.AccountID] = id
	return nil
}

var _ tenant.Store = (*Store)(nil)
