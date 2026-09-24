package memory

import (
	"context"
	"sync"

	"github.com/ajent-social/go/passwordreset"
)

// Store is a process-local passwordreset.Store.
type Store struct {
	mu         sync.Mutex
	byDigest   map[[32]byte]passwordreset.Challenge
	byAccount  map[string][][32]byte
}

// New returns an empty Store.
func New() *Store {
	return &Store{
		byDigest:  map[[32]byte]passwordreset.Challenge{},
		byAccount: map[string][][32]byte{},
	}
}

func (s *Store) Put(_ context.Context, ch passwordreset.Challenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byDigest[ch.TokenDigest]; ok {
		return passwordreset.ErrExists
	}
	s.byDigest[ch.TokenDigest] = ch
	s.byAccount[ch.AccountID] = append(s.byAccount[ch.AccountID], ch.TokenDigest)
	return nil
}

func (s *Store) Consume(_ context.Context, digest [32]byte) (passwordreset.Challenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.byDigest[digest]
	if !ok {
		return passwordreset.Challenge{}, passwordreset.ErrNotFound
	}
	delete(s.byDigest, digest)
	return ch, nil
}

func (s *Store) InvalidateAccount(_ context.Context, accountID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.byAccount[accountID] {
		delete(s.byDigest, d)
	}
	delete(s.byAccount, accountID)
	return nil
}

var _ passwordreset.Store = (*Store)(nil)
