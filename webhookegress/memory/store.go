package memory

import (
	"context"
	"sync"

	"github.com/ajent-social/go/webhookegress"
)

// Store is a process-local webhookegress.Store.
type Store struct {
	mu         sync.Mutex
	endpoints  map[string]webhookegress.Endpoint
	deliveries map[string]webhookegress.Delivery
}

// New returns an empty Store.
func New() *Store {
	return &Store{
		endpoints:  map[string]webhookegress.Endpoint{},
		deliveries: map[string]webhookegress.Delivery{},
	}
}

func (s *Store) CreateEndpoint(_ context.Context, ep webhookegress.Endpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.endpoints[ep.ID]; ok {
		return webhookegress.ErrExists
	}
	s.endpoints[ep.ID] = ep
	return nil
}

func (s *Store) LookupEndpoint(_ context.Context, id string) (webhookegress.Endpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ep, ok := s.endpoints[id]
	if !ok {
		return webhookegress.Endpoint{}, webhookegress.ErrNotFound
	}
	return ep, nil
}

func (s *Store) ListEndpointsByEvent(_ context.Context, ownerID, eventType string) ([]webhookegress.Endpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []webhookegress.Endpoint
	for _, ep := range s.endpoints {
		if ep.OwnerID != ownerID {
			continue
		}
		for _, e := range ep.Events {
			if e == eventType {
				out = append(out, ep)
				break
			}
		}
	}
	return out, nil
}

func (s *Store) PutDelivery(_ context.Context, d webhookegress.Delivery) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deliveries[d.ID] = d
	return nil
}

func (s *Store) UpdateDelivery(_ context.Context, d webhookegress.Delivery) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.deliveries[d.ID]; !ok {
		return webhookegress.ErrNotFound
	}
	s.deliveries[d.ID] = d
	return nil
}

// Delivery returns a delivery by id (test helper).
func (s *Store) Delivery(id string) (webhookegress.Delivery, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.deliveries[id]
	return d, ok
}

var _ webhookegress.Store = (*Store)(nil)
