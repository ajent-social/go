// Package memory is an in-memory humanauth.Store for tests and single-process demos.
package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/ajent-social/go/humanauth"
)

// Store is a process-local humanauth.Store.
type Store struct {
	mu       sync.Mutex
	sessions map[[32]byte]humanauth.Record
}

// New returns an empty Store.
func New() *Store {
	return &Store{sessions: map[[32]byte]humanauth.Record{}}
}

func (s *Store) Create(_ context.Context, rec humanauth.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[rec.TokenDigest]; ok {
		return fmt.Errorf("%w: session digest already exists", humanauth.ErrInvalid)
	}
	s.sessions[rec.TokenDigest] = rec
	return nil
}

func (s *Store) Get(_ context.Context, digest [32]byte) (humanauth.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.sessions[digest]
	if !ok {
		return humanauth.Record{}, humanauth.ErrNotFound
	}
	return rec, nil
}

func (s *Store) Delete(_ context.Context, digest [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, digest)
	return nil
}

func (s *Store) ListSubject(_ context.Context, subjectID string) ([]humanauth.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []humanauth.Record
	for _, rec := range s.sessions {
		if rec.Subject.ID == subjectID {
			out = append(out, rec)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *Store) DeleteSubject(_ context.Context, subjectID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, rec := range s.sessions {
		if rec.Subject.ID == subjectID {
			delete(s.sessions, k)
			n++
		}
	}
	return n, nil
}

func (s *Store) DeleteExpired(_ context.Context, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, rec := range s.sessions {
		if !rec.ExpiresAt.After(now) {
			delete(s.sessions, k)
			n++
		}
	}
	return n, nil
}

var _ humanauth.Store = (*Store)(nil)
