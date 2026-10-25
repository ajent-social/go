// Package memory provides an ephemeral lifecycle store. Share one Store between
// coordinators in a process; it provides no persistence or cross-process safety.
package memory

import (
	"context"
	"sync"

	"github.com/ajent-social/go/mcpclientoauth"
)

type binding struct{ owner, server string }
type connection struct {
	record mcpclientoauth.TokenRecord
	state  string
}

// Store serializes the same CAS transitions as the SQL adapter, in memory only.
type Store struct {
	mu      sync.Mutex
	pending map[[32]byte]mcpclientoauth.Pending
	tokens  map[binding]connection
}

func New() *Store {
	return &Store{pending: make(map[[32]byte]mcpclientoauth.Pending), tokens: make(map[binding]connection)}
}
func clone(t mcpclientoauth.TokenRecord) mcpclientoauth.TokenRecord {
	t.Ciphertext = append([]byte(nil), t.Ciphertext...)
	return t
}

func (s *Store) PutPending(ctx context.Context, p mcpclientoauth.Pending) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, ok := s.pending[p.StateDigest]; ok {
		return mcpclientoauth.ErrExists
	}
	s.pending[p.StateDigest] = p
	return nil
}
func (s *Store) TakePending(ctx context.Context, digest [32]byte) (mcpclientoauth.Pending, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return mcpclientoauth.Pending{}, err
	}
	p, ok := s.pending[digest]
	if !ok {
		return p, mcpclientoauth.ErrNotFound
	}
	delete(s.pending, digest)
	return p, nil
}

// PutToken is retained for source compatibility but unrestricted writes are disabled.
func (s *Store) PutToken(context.Context, mcpclientoauth.TokenRecord) error {
	return mcpclientoauth.ErrUnsupportedStore
}
func (s *Store) BeginConnection(ctx context.Context, owner, server, generation string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if owner == "" || server == "" || generation == "" {
		return mcpclientoauth.ErrInvalid
	}
	key := binding{owner, server}
	if s.tokens[key].record.Generation == generation {
		return mcpclientoauth.ErrConflict
	}
	s.tokens[key] = connection{record: mcpclientoauth.TokenRecord{OwnerID: owner, ServerID: server, Generation: generation}, state: "empty"}
	return nil
}
func (s *Store) LookupToken(ctx context.Context, owner, server string) (mcpclientoauth.TokenRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return mcpclientoauth.TokenRecord{}, err
	}
	c := s.tokens[binding{owner, server}]
	if c.state == "claimed" {
		return mcpclientoauth.TokenRecord{}, mcpclientoauth.ErrRefreshUncertain
	}
	if c.state != "ready" {
		return mcpclientoauth.TokenRecord{}, mcpclientoauth.ErrNotFound
	}
	return clone(c.record), nil
}
func (s *Store) ClaimRefresh(ctx context.Context, t mcpclientoauth.TokenRecord) (mcpclientoauth.TokenRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return mcpclientoauth.TokenRecord{}, err
	}
	key := binding{t.OwnerID, t.ServerID}
	c := s.tokens[key]
	if c.record.Generation != t.Generation || c.record.Version != t.Version || c.state != "ready" {
		return mcpclientoauth.TokenRecord{}, mcpclientoauth.ErrConflict
	}
	c.state = "claimed"
	c.record.Version++
	s.tokens[key] = c
	return clone(c.record), nil
}
func (s *Store) CompleteToken(ctx context.Context, t mcpclientoauth.TokenRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	key := binding{t.OwnerID, t.ServerID}
	c := s.tokens[key]
	if t.Generation == "" || c.record.Generation != t.Generation || c.record.Version != t.Version || (c.state != "empty" && c.state != "claimed") {
		return mcpclientoauth.ErrConflict
	}
	t.Version++
	s.tokens[key] = connection{record: clone(t), state: "ready"}
	return nil
}
func (s *Store) Disconnect(ctx context.Context, owner, server string) (mcpclientoauth.TokenRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return mcpclientoauth.TokenRecord{}, err
	}
	key := binding{owner, server}
	c := s.tokens[key]
	old := clone(c.record)
	c.state = "disconnected"
	c.record.Ciphertext = nil
	c.record.Version++
	s.tokens[key] = c
	return old, nil
}
func (s *Store) DeleteToken(ctx context.Context, owner, server string) error {
	_, err := s.Disconnect(ctx, owner, server)
	return err
}

var _ mcpclientoauth.LifecycleStore = (*Store)(nil)
