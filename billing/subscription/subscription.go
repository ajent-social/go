// Package subscription keeps a durable inbox of signature-verified provider
// events and a local per-customer subscription projection.
//
// Callers verify provider signatures with a maintained SDK before calling
// AcceptVerifiedEvent. This package does not interpret redirects, grace
// periods, or past_due access policy — it exposes provider Status strings only.
//
// Status: CANDIDATE. Capability: billing.subscription-projection.
package subscription

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrInvalid  = errors.New("subscription: invalid input")
	ErrNotFound = errors.New("subscription: not found")
	ErrExists   = errors.New("subscription: already exists")
	ErrConflict = errors.New("subscription: conflict")
	ErrStale    = errors.New("subscription: stale lease")
)

// CustomerRef is a provider customer reference (never a card).
type CustomerRef string

// EventID is a provider event identity.
type EventID string

// Livemode distinguishes live vs test provider traffic for dedupe keys.
type Livemode bool

// SubscriptionRef is a provider subscription identity.
type SubscriptionRef string

// VerifiedEvent is a provider event already signature-verified by the caller.
// CustomerRef may be empty when the event is not yet matched to a local customer;
// such events are still persisted as unmatched for later retry.
type VerifiedEvent struct {
	ID              EventID
	Livemode        Livemode
	Type            string
	CustomerRef     CustomerRef
	SubscriptionRef SubscriptionRef
	Status          string
	PeriodEnd       time.Time
	PayloadHash     string
	ReceivedAt      time.Time
}

// Projection is the local view of a customer's subscription state.
// Status is the last applied provider status string; entitlement policy stays
// with the application.
type Projection struct {
	CustomerRef     CustomerRef
	SubscriptionRef SubscriptionRef
	Status          string
	PeriodEnd       time.Time
	UpdatedAt       time.Time
	EventID         EventID
}

// EventRecord is the durable inbox row for a verified event.
type EventRecord struct {
	Event     VerifiedEvent
	Unmatched bool
	CreatedAt time.Time
}

// ApplyProjectionInput applies a projection under a lease epoch CAS.
// ExpectedEpoch is 0 when creating the first projection for a customer.
type ApplyProjectionInput struct {
	Customer      CustomerRef
	ExpectedEpoch uint64
	Projection    Projection
	Now           time.Time
}

// ProjectionRecord pairs a projection with its CAS lease epoch.
type ProjectionRecord struct {
	Projection Projection
	LeaseEpoch uint64
}

// Store is durable event inbox and projection state.
// Implementations must treat InsertEvent as unique on (Livemode, EventID) and
// ApplyProjection as CAS on LeaseEpoch so concurrent AcceptVerifiedEvent calls
// are safe. Duplicates with the same PayloadHash are harmless; conflicting
// content for the same ID returns ErrConflict from the service layer.
type Store interface {
	LookupEvent(context.Context, Livemode, EventID) (EventRecord, error)
	LookupProjection(context.Context, CustomerRef) (ProjectionRecord, error)
	InsertEvent(context.Context, EventRecord) error
	ApplyProjection(context.Context, ApplyProjectionInput) error
}

// Service accepts verified events and serves projections.
type Service struct {
	store Store
	now   func() time.Time
}

// New constructs a Service. store is required.
func New(store Store) (*Service, error) {
	if store == nil {
		return nil, ErrInvalid
	}
	return &Service{store: store, now: time.Now}, nil
}

// AcceptVerifiedEvent records a signature-verified event and, when CustomerRef
// is set, applies it to the local projection under lease CAS.
//
// Deduplication key is (Livemode, EventID). A repeat with the same PayloadHash
// is a no-op. A repeat with a different PayloadHash returns ErrConflict.
//
// Out-of-order rules (documented, intentionally small):
//   - PeriodEnd never moves backward.
//   - If the current Status is terminal (canceled, unpaid, deleted) and the
//     incoming PeriodEnd is not strictly after the current PeriodEnd, a
//     non-terminal incoming Status does not revive the projection.
//
// Unmatched events (empty CustomerRef) are persisted and return nil without
// touching any projection.
func (s *Service) AcceptVerifiedEvent(ctx context.Context, ev VerifiedEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateEvent(ev); err != nil {
		return err
	}
	ev.PeriodEnd = ev.PeriodEnd.UTC()
	if ev.ReceivedAt.IsZero() {
		ev.ReceivedAt = s.now().UTC()
	} else {
		ev.ReceivedAt = ev.ReceivedAt.UTC()
	}

	if err := s.dedupeOrInsert(ctx, ev); err != nil {
		return err
	}
	if ev.CustomerRef == "" {
		return nil
	}
	return s.applyWithRetry(ctx, ev)
}

// GetProjection returns the local projection for a customer.
func (s *Service) GetProjection(ctx context.Context, customer CustomerRef) (Projection, error) {
	if err := ctx.Err(); err != nil {
		return Projection{}, err
	}
	if !validCustomer(customer) {
		return Projection{}, ErrInvalid
	}
	rec, err := s.store.LookupProjection(ctx, customer)
	if err != nil {
		return Projection{}, err
	}
	return rec.Projection, nil
}

func (s *Service) dedupeOrInsert(ctx context.Context, ev VerifiedEvent) error {
	existing, err := s.store.LookupEvent(ctx, ev.Livemode, ev.ID)
	if err == nil {
		if existing.Event.PayloadHash != ev.PayloadHash {
			return ErrConflict
		}
		return nil
	}
	if !errors.Is(err, ErrNotFound) {
		return err
	}

	rec := EventRecord{
		Event:     ev,
		Unmatched: ev.CustomerRef == "",
		CreatedAt: s.now().UTC(),
	}
	if err := s.store.InsertEvent(ctx, rec); err != nil {
		if errors.Is(err, ErrExists) {
			again, lerr := s.store.LookupEvent(ctx, ev.Livemode, ev.ID)
			if lerr != nil {
				return lerr
			}
			if again.Event.PayloadHash != ev.PayloadHash {
				return ErrConflict
			}
			return nil
		}
		return err
	}
	return nil
}

func (s *Service) applyWithRetry(ctx context.Context, ev VerifiedEvent) error {
	const maxAttempts = 8
	for i := 0; i < maxAttempts; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		now := s.now().UTC()
		cur, err := s.store.LookupProjection(ctx, ev.CustomerRef)
		expected := uint64(0)
		var base Projection
		switch {
		case err == nil:
			expected = cur.LeaseEpoch
			base = cur.Projection
		case errors.Is(err, ErrNotFound):
			base = Projection{CustomerRef: ev.CustomerRef}
		default:
			return err
		}
		next := mergeProjection(base, ev, now)
		if err := s.store.ApplyProjection(ctx, ApplyProjectionInput{
			Customer:      ev.CustomerRef,
			ExpectedEpoch: expected,
			Projection:    next,
			Now:           now,
		}); err != nil {
			if errors.Is(err, ErrStale) {
				continue
			}
			return err
		}
		return nil
	}
	return fmt.Errorf("apply projection: %w", ErrStale)
}

// mergeProjection applies out-of-order safeguards. See AcceptVerifiedEvent.
func mergeProjection(cur Projection, ev VerifiedEvent, now time.Time) Projection {
	out := Projection{
		CustomerRef:     ev.CustomerRef,
		SubscriptionRef: cur.SubscriptionRef,
		Status:          cur.Status,
		PeriodEnd:       cur.PeriodEnd,
		UpdatedAt:       now,
		EventID:         ev.ID,
	}
	if out.CustomerRef == "" {
		out.CustomerRef = cur.CustomerRef
	}
	if ev.SubscriptionRef != "" {
		out.SubscriptionRef = ev.SubscriptionRef
	} else if out.SubscriptionRef == "" {
		out.SubscriptionRef = cur.SubscriptionRef
	}

	periodAdvanced := ev.PeriodEnd.After(cur.PeriodEnd)
	if periodAdvanced || cur.PeriodEnd.IsZero() {
		out.PeriodEnd = ev.PeriodEnd
	}

	incomingTerminal := isTerminalStatus(ev.Status)
	currentTerminal := isTerminalStatus(cur.Status)
	switch {
	case cur.Status == "":
		out.Status = ev.Status
	case currentTerminal && !incomingTerminal && !periodAdvanced:
		// Keep terminal; do not revive from an older or same-period event.
		out.Status = cur.Status
	default:
		out.Status = ev.Status
	}
	return out
}

// isTerminalStatus reports provider statuses that should not be revived by
// older non-terminal events. Matching is case-insensitive on the final path
// segment so values like "canceled" and "subscription.deleted" both qualify
// when the trailing token is canceled, unpaid, or deleted.
func isTerminalStatus(status string) bool {
	s := strings.ToLower(strings.TrimSpace(status))
	if s == "" {
		return false
	}
	if i := strings.LastIndexByte(s, '.'); i >= 0 {
		s = s[i+1:]
	}
	switch s {
	case "canceled", "cancelled", "unpaid", "deleted":
		return true
	default:
		return false
	}
}

func validateEvent(ev VerifiedEvent) error {
	if !validEventID(ev.ID) || strings.TrimSpace(ev.PayloadHash) == "" || strings.TrimSpace(ev.Type) == "" {
		return ErrInvalid
	}
	if ev.CustomerRef != "" && !validCustomer(ev.CustomerRef) {
		return ErrInvalid
	}
	return nil
}

func validEventID(id EventID) bool {
	s := string(id)
	return len(s) > 0 && len(s) <= 256 && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\x00\r\n")
}

func validCustomer(c CustomerRef) bool {
	s := string(c)
	return len(s) > 0 && len(s) <= 256 && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\x00\r\n")
}
