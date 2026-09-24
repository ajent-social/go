package subscription_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ajent-social/go/billing/subscription"
	"github.com/ajent-social/go/billing/subscription/memory"
)

func newService(t *testing.T) *subscription.Service {
	t.Helper()
	svc, err := subscription.New(memory.New())
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func baseEvent(id string) subscription.VerifiedEvent {
	return subscription.VerifiedEvent{
		ID:              subscription.EventID(id),
		Livemode:        false,
		Type:            "customer.subscription.updated",
		CustomerRef:     "cus_1",
		SubscriptionRef: "sub_1",
		Status:          "active",
		PeriodEnd:       time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		PayloadHash:     "hash-" + id,
		ReceivedAt:      time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC),
	}
}

func TestDuplicateEventHarmless(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc := newService(t)
	ev := baseEvent("evt_dup")

	if err := svc.AcceptVerifiedEvent(ctx, ev); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := svc.AcceptVerifiedEvent(ctx, ev); err != nil {
		t.Fatalf("duplicate: %v", err)
	}
	proj, err := svc.GetProjection(ctx, "cus_1")
	if err != nil {
		t.Fatal(err)
	}
	if proj.Status != "active" || proj.EventID != "evt_dup" {
		t.Fatalf("projection: %#v", proj)
	}
}

func TestConflictingPayloadSameID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc := newService(t)
	ev := baseEvent("evt_conflict")
	if err := svc.AcceptVerifiedEvent(ctx, ev); err != nil {
		t.Fatal(err)
	}
	ev.PayloadHash = "other-hash"
	if err := svc.AcceptVerifiedEvent(ctx, ev); !errors.Is(err, subscription.ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
}

func TestOutOfOrderPeriodEndAndTerminal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc := newService(t)

	later := baseEvent("evt_later")
	later.Status = "canceled"
	later.PeriodEnd = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	if err := svc.AcceptVerifiedEvent(ctx, later); err != nil {
		t.Fatal(err)
	}

	earlier := baseEvent("evt_earlier")
	earlier.Status = "active"
	earlier.PeriodEnd = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if err := svc.AcceptVerifiedEvent(ctx, earlier); err != nil {
		t.Fatal(err)
	}

	proj, err := svc.GetProjection(ctx, "cus_1")
	if err != nil {
		t.Fatal(err)
	}
	if !proj.PeriodEnd.Equal(later.PeriodEnd) {
		t.Fatalf("PeriodEnd moved backward: got %v want %v", proj.PeriodEnd, later.PeriodEnd)
	}
	if proj.Status != "canceled" {
		t.Fatalf("revived terminal status: %#v", proj)
	}
	if proj.EventID != "evt_earlier" {
		t.Fatalf("last applied event: %q", proj.EventID)
	}
}

func TestGetProjection(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc := newService(t)

	if _, err := svc.GetProjection(ctx, "cus_missing"); !errors.Is(err, subscription.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	ev := baseEvent("evt_get")
	if err := svc.AcceptVerifiedEvent(ctx, ev); err != nil {
		t.Fatal(err)
	}
	proj, err := svc.GetProjection(ctx, "cus_1")
	if err != nil {
		t.Fatal(err)
	}
	if proj.CustomerRef != "cus_1" || proj.SubscriptionRef != "sub_1" || proj.Status != "active" {
		t.Fatalf("projection: %#v", proj)
	}
}

func TestUnmatchedCustomerPersists(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := memory.New()
	svc, err := subscription.New(store)
	if err != nil {
		t.Fatal(err)
	}
	ev := baseEvent("evt_unmatched")
	ev.CustomerRef = ""
	if err := svc.AcceptVerifiedEvent(ctx, ev); err != nil {
		t.Fatal(err)
	}
	rec, err := store.LookupEvent(ctx, false, "evt_unmatched")
	if err != nil {
		t.Fatal(err)
	}
	if !rec.Unmatched {
		t.Fatalf("expected unmatched record: %#v", rec)
	}
	if _, err := svc.GetProjection(ctx, "cus_1"); !errors.Is(err, subscription.ErrNotFound) {
		t.Fatalf("no projection expected: %v", err)
	}
}

func TestConcurrentDuplicateRace(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc := newService(t)
	ev := baseEvent("evt_race")

	const n = 32
	var wg sync.WaitGroup
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			errs[i] = svc.AcceptVerifiedEvent(ctx, ev)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}
	proj, err := svc.GetProjection(ctx, "cus_1")
	if err != nil {
		t.Fatal(err)
	}
	if proj.Status != "active" || proj.EventID != "evt_race" {
		t.Fatalf("projection: %#v", proj)
	}
}

func TestLivemodeSeparatesDedupe(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc := newService(t)
	testEv := baseEvent("evt_same")
	liveEv := testEv
	liveEv.Livemode = true
	liveEv.PayloadHash = "live-hash"
	liveEv.Status = "past_due"
	if err := svc.AcceptVerifiedEvent(ctx, testEv); err != nil {
		t.Fatal(err)
	}
	if err := svc.AcceptVerifiedEvent(ctx, liveEv); err != nil {
		t.Fatal(err)
	}
	// Both apply to same customer; last writer wins on status subject to OOO rules.
	proj, err := svc.GetProjection(ctx, "cus_1")
	if err != nil {
		t.Fatal(err)
	}
	if proj.EventID != "evt_same" {
		t.Fatalf("event id: %q", proj.EventID)
	}
}
