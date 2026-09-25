// Package usage meters bounded consumption per owner and period.
//
// It is not a billing ledger or Stripe meter. Callers choose period keys
// (e.g. "2026-09") and limits. Exceeding a limit returns ErrDenied.
//
// Status: CANDIDATE. Capability: billing.usage-meter.
package usage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrInvalid  = errors.New("usage: invalid input")
	ErrNotFound = errors.New("usage: not found")
	ErrDenied   = errors.New("usage: limit exceeded")
	ErrConflict = errors.New("usage: conflict")
)

// Key identifies one counter.
type Key struct {
	Owner  string // account or tenant id
	Meter  string // e.g. "model_steps"
	Period string // caller-defined bucket, e.g. "2026-09"
}

// Counter is durable usage state.
type Counter struct {
	Key
	Used      int64
	UpdatedAt time.Time
	Epoch     uint64
}

// Store persists counters with CAS on Epoch.
type Store interface {
	Lookup(context.Context, Key) (Counter, error)
	Apply(ctx context.Context, expectedEpoch uint64, next Counter) error
}

// Service increments and checks quotas.
type Service struct {
	store Store
	now   func() time.Time
}

// New constructs a Service.
func New(store Store) (*Service, error) {
	if store == nil {
		return nil, ErrInvalid
	}
	return &Service{store: store, now: time.Now}, nil
}

// Check returns the current used amount without mutating.
func (s *Service) Check(ctx context.Context, key Key) (int64, error) {
	if err := validateKey(key); err != nil {
		return 0, err
	}
	c, err := s.store.Lookup(ctx, key)
	if errors.Is(err, ErrNotFound) {
		return 0, nil
	}
	return c.Used, err
}

// Consume adds n to the counter if used+n <= limit. limit must be > 0.
func (s *Service) Consume(ctx context.Context, key Key, n, limit int64) (Counter, error) {
	if err := ctx.Err(); err != nil {
		return Counter{}, err
	}
	if err := validateKey(key); err != nil {
		return Counter{}, err
	}
	if n <= 0 || limit <= 0 {
		return Counter{}, ErrInvalid
	}
	for attempt := 0; attempt < 8; attempt++ {
		cur, err := s.store.Lookup(ctx, key)
		if errors.Is(err, ErrNotFound) {
			cur = Counter{Key: key, Epoch: 0}
		} else if err != nil {
			return Counter{}, err
		}
		if cur.Used+n > limit {
			return cur, ErrDenied
		}
		next := cur
		next.Used = cur.Used + n
		next.UpdatedAt = s.now().UTC()
		expected := cur.Epoch
		if err := s.store.Apply(ctx, expected, next); err != nil {
			if errors.Is(err, ErrConflict) {
				continue
			}
			return Counter{}, err
		}
		next.Epoch = expected + 1
		return next, nil
	}
	return Counter{}, fmt.Errorf("%w: exhausted retries", ErrConflict)
}

func validateKey(k Key) error {
	if strings.TrimSpace(k.Owner) == "" || strings.TrimSpace(k.Meter) == "" || strings.TrimSpace(k.Period) == "" {
		return ErrInvalid
	}
	return nil
}
