package memory

import (
	"context"
	"sync"

	"github.com/ajent-social/go/billing/subscription"
)

// Store is an in-memory subscription.Store for tests and single-process demos.
type Store struct {
	mu          sync.Mutex
	events      map[string]subscription.EventRecord
	projections map[subscription.CustomerRef]subscription.ProjectionRecord
}

// New returns an empty Store.
func New() *Store {
	return &Store{
		events:      map[string]subscription.EventRecord{},
		projections: map[subscription.CustomerRef]subscription.ProjectionRecord{},
	}
}

func eventKey(livemode subscription.Livemode, id subscription.EventID) string {
	if livemode {
		return "live\x00" + string(id)
	}
	return "test\x00" + string(id)
}

func (s *Store) LookupEvent(_ context.Context, livemode subscription.Livemode, id subscription.EventID) (subscription.EventRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.events[eventKey(livemode, id)]
	if !ok {
		return subscription.EventRecord{}, subscription.ErrNotFound
	}
	return rec, nil
}

func (s *Store) LookupProjection(_ context.Context, customer subscription.CustomerRef) (subscription.ProjectionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.projections[customer]
	if !ok {
		return subscription.ProjectionRecord{}, subscription.ErrNotFound
	}
	return rec, nil
}

func (s *Store) InsertEvent(_ context.Context, rec subscription.EventRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := eventKey(rec.Event.Livemode, rec.Event.ID)
	if _, ok := s.events[k]; ok {
		return subscription.ErrExists
	}
	s.events[k] = rec
	return nil
}

func (s *Store) ApplyProjection(_ context.Context, in subscription.ApplyProjectionInput) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.projections[in.Customer]
	if !ok {
		if in.ExpectedEpoch != 0 {
			return subscription.ErrStale
		}
		s.projections[in.Customer] = subscription.ProjectionRecord{
			Projection: in.Projection,
			LeaseEpoch: 1,
		}
		return nil
	}
	if cur.LeaseEpoch != in.ExpectedEpoch {
		return subscription.ErrStale
	}
	cur.Projection = in.Projection
	cur.LeaseEpoch++
	s.projections[in.Customer] = cur
	return nil
}
