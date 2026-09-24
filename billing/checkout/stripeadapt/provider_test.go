package stripeadapt_test

import (
	"testing"

	"github.com/ajent-social/go/billing/checkout"
	"github.com/ajent-social/go/billing/checkout/stripeadapt"
)

func TestNewRequiresKey(t *testing.T) {
	if _, err := stripeadapt.New(""); err != checkout.ErrInvalid && err == nil {
		t.Fatalf("want invalid, got %v", err)
	}
	p, err := stripeadapt.New("sk_test_dummy")
	if err != nil || p == nil {
		t.Fatalf("got %v %#v", err, p)
	}
}
