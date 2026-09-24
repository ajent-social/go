package portal_test

import (
	"context"
	"testing"
	"time"

	"github.com/ajent-social/go/billing/checkout"
	"github.com/ajent-social/go/billing/checkout/memory"
	"github.com/ajent-social/go/billing/portal"
)

type fakePortal struct{ url string }

func (f fakePortal) CreatePortalSession(_ context.Context, _ checkout.CustomerRef, _ string) (string, error) {
	return f.url, nil
}

func TestStartRequiresBinding(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	svc, err := portal.New(store, fakePortal{url: "https://billing.example/session"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Start(ctx, "a1", "https://app.example/account"); err != checkout.ErrNotFound && err == nil {
		t.Fatalf("got %v", err)
	}
	_ = store.InsertCustomer(ctx, checkout.CustomerBinding{
		Account: "a1", CustomerRef: "cus_1", CreatedAt: time.Now().UTC(),
	})
	url, err := svc.Start(ctx, "a1", "https://app.example/account")
	if err != nil || url == "" {
		t.Fatalf("%q %v", url, err)
	}
}
