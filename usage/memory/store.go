package memory

import (
	"context"
	"sync"

	"github.com/ajent-social/go/usage"
)

// Store is a process-local usage.Store.
type Store struct {
	mu   sync.Mutex
	byKey map[string]usage.Counter
}

// New returns an empty Store.
func New() *Store {
	return &Store{byKey: map[string]usage.Counter{}}
}

func key(k usage.Key) string {
	return k.Owner + "\x00" + k.Meter + "\x00" + k.Period
}

func (s *Store) Lookup(_ context.Context, k usage.Key) (usage.Counter, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.byKey[key(k)]
	if !ok {
		return usage.Counter{}, usage.ErrNotFound
	}
	return c, nil
}

func (s *Store) Apply(_ context.Context, expectedEpoch uint64, next usage.Counter) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(next.Key)
	cur, ok := s.byKey[k]
	if !ok {
		if expectedEpoch != 0 {
			return usage.ErrConflict
		}
		next.Epoch = 1
		s.byKey[k] = next
		return nil
	}
	if cur.Epoch != expectedEpoch {
		return usage.ErrConflict
	}
	next.Epoch = expectedEpoch + 1
	s.byKey[k] = next
	return nil
}

var _ usage.Store = (*Store)(nil)
