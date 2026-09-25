package entitlement_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ajent-social/go/billing/checkout"
	"github.com/ajent-social/go/billing/entitlement"
	"github.com/ajent-social/go/billing/subscription"
)

type fakeBindings struct {
	cust checkout.CustomerBinding
	err  error
}

func (f fakeBindings) LookupCustomer(context.Context, checkout.AccountID) (checkout.CustomerBinding, error) {
	return f.cust, f.err
}

type fakeSubs struct {
	proj subscription.Projection
	err  error
}

func (f fakeSubs) GetProjection(context.Context, subscription.CustomerRef) (subscription.Projection, error) {
	return f.proj, f.err
}

func TestRequireStatus(t *testing.T) {
	g, err := entitlement.New(entitlement.Config{}, fakeBindings{}, fakeSubs{})
	if err != nil {
		t.Fatal(err)
	}
	if err := g.RequireStatus("active"); err != nil {
		t.Fatal(err)
	}
	if err := g.RequireStatus("past_due"); !errors.Is(err, entitlement.ErrDenied) {
		t.Fatalf("got %v", err)
	}
}

func TestRequireAccount(t *testing.T) {
	g, err := entitlement.New(entitlement.Config{}, fakeBindings{
		cust: checkout.CustomerBinding{Account: "a1", CustomerRef: "cus_1"},
	}, fakeSubs{
		proj: subscription.Projection{Status: "trialing"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := g.RequireAccount(context.Background(), "a1"); err != nil {
		t.Fatal(err)
	}
	g2, _ := entitlement.New(entitlement.Config{}, fakeBindings{err: checkout.ErrNotFound}, fakeSubs{})
	if err := g2.RequireAccount(context.Background(), "a1"); !errors.Is(err, entitlement.ErrDenied) {
		t.Fatalf("got %v", err)
	}
}
