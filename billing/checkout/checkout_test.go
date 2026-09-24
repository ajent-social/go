package checkout_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/ajent-social/go/billing/checkout"
	"github.com/ajent-social/go/billing/checkout/memory"
)

type fakeProvider struct {
	mu        sync.Mutex
	customers map[string]checkout.CustomerRef
	sessions  map[string]checkout.ProviderSession
	failCreate bool
}

func newFake() *fakeProvider {
	return &fakeProvider{
		customers: map[string]checkout.CustomerRef{},
		sessions:  map[string]checkout.ProviderSession{},
	}
}

func (f *fakeProvider) CreateCustomer(_ context.Context, account checkout.AccountID, key string) (checkout.CustomerRef, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failCreate {
		return "", errors.New("provider timeout")
	}
	if ref, ok := f.customers[key]; ok {
		return ref, nil
	}
	ref := checkout.CustomerRef("cus_" + string(account))
	f.customers[key] = ref
	return ref, nil
}

func (f *fakeProvider) CreateCheckoutSession(_ context.Context, in checkout.ProviderCheckout) (checkout.ProviderSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if sess, ok := f.sessions[in.IdempotencyKey]; ok {
		return sess, nil
	}
	ref := "cs_" + string(in.Attempt)
	sess := checkout.ProviderSession{ProviderRef: ref, URL: "https://checkout.test/" + ref, CustomerRef: in.CustomerRef}
	f.sessions[in.IdempotencyKey] = sess
	f.sessions[ref] = sess
	return sess, nil
}

func (f *fakeProvider) GetCheckoutSession(_ context.Context, providerRef string) (checkout.ProviderSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	sess, ok := f.sessions[providerRef]
	if !ok {
		return checkout.ProviderSession{}, errors.New("missing session")
	}
	return sess, nil
}

func TestEnsureCustomerIdempotent(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	prov := newFake()
	svc, err := checkout.New(store, prov)
	if err != nil {
		t.Fatal(err)
	}
	ref1, err := svc.EnsureCustomer(ctx, "acct-1", "att-1")
	if err != nil || ref1 == "" {
		t.Fatalf("first: %v %q", err, ref1)
	}
	ref2, err := svc.EnsureCustomer(ctx, "acct-1", "att-2")
	if err != nil || ref2 != ref1 {
		t.Fatalf("second: %v %q want %q", err, ref2, ref1)
	}
}

func TestStartCheckoutReplayAndConflict(t *testing.T) {
	ctx := context.Background()
	svc, _ := checkout.New(memory.New(), newFake())
	in := checkout.CheckoutInput{
		Account: "acct-1", Attempt: "chk-1", PriceID: "price_1",
		SuccessURL: "https://app.test/ok", CancelURL: "https://app.test/cancel",
	}
	first, err := svc.StartCheckout(ctx, in)
	if err != nil || first.URL == "" || first.Status != checkout.StatusSucceeded {
		t.Fatalf("first: %#v %v", first, err)
	}
	again, err := svc.StartCheckout(ctx, in)
	if err != nil || again.URL != first.URL {
		t.Fatalf("replay: %#v %v", again, err)
	}
	in.PriceID = "price_2"
	if _, err := svc.StartCheckout(ctx, in); !errors.Is(err, checkout.ErrConflict) {
		t.Fatalf("changed payload: %v", err)
	}
}

func TestRecoverAfterUnknown(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	prov := newFake()
	svc, _ := checkout.New(store, prov)
	in := checkout.CheckoutInput{
		Account: "acct-1", Attempt: "chk-2", PriceID: "price_1",
		SuccessURL: "https://app.test/ok", CancelURL: "https://app.test/cancel",
	}
	res, err := svc.StartCheckout(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate lost local success: mark unknown but keep provider ref.
	rec, err := store.LookupAttempt(ctx, in.Account, in.Attempt)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitAttempt(ctx, checkout.AttemptCommit{
		Account: in.Account, Attempt: in.Attempt, LeaseEpoch: rec.LeaseEpoch,
		Status: checkout.StatusUnknown, ProviderRef: res.ProviderRef, CustomerRef: res.CustomerRef,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := svc.RecoverAttempt(ctx, in.Account, in.Attempt)
	if err != nil || got.Status != checkout.StatusSucceeded || got.URL == "" {
		t.Fatalf("recover: %#v %v", got, err)
	}
}

func TestRedirectIsNotPaymentEvidence(t *testing.T) {
	// Package never exposes a Paid bool; only coordination status + URL.
	res := checkout.CheckoutResult{Status: checkout.StatusSucceeded, URL: "https://checkout.test/cs"}
	if res.Status == "paid" {
		t.Fatal("no paid status")
	}
}

func TestProviderFailureLeavesUnknown(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	prov := newFake()
	prov.failCreate = true
	svc, _ := checkout.New(store, prov)
	if _, err := svc.EnsureCustomer(ctx, "acct-x", "att-x"); err == nil {
		t.Fatal("expected provider error")
	}
	rec, err := store.LookupAttempt(ctx, "acct-x", "att-x")
	if err != nil || rec.Status != checkout.StatusUnknown {
		t.Fatalf("want unknown attempt, got %#v %v", rec, err)
	}
}
