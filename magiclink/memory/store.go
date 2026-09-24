package memory

import (
	"context"
	"sync"

	"github.com/ajent-social/go/magiclink"
)

// Store is a process-local magiclink.Store.
type Store struct {
	mu         sync.Mutex
	challenges map[[32]byte]magiclink.Challenge
}

// New returns an empty Store.
func New() *Store {
	return &Store{challenges: map[[32]byte]magiclink.Challenge{}}
}

func (s *Store) Put(_ context.Context, ch magiclink.Challenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.challenges[ch.TokenDigest]; ok {
		return magiclink.ErrExists
	}
	s.challenges[ch.TokenDigest] = ch
	return nil
}

func (s *Store) Consume(_ context.Context, digest [32]byte) (magiclink.Challenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.challenges[digest]
	if !ok {
		return magiclink.Challenge{}, magiclink.ErrNotFound
	}
	delete(s.challenges, digest)
	return ch, nil
}

func (s *Store) InvalidateEmail(_ context.Context, email string, purpose magiclink.Purpose) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, ch := range s.challenges {
		if ch.Email == email && ch.Purpose == purpose {
			delete(s.challenges, k)
		}
	}
	return nil
}

var _ magiclink.Store = (*Store)(nil)
