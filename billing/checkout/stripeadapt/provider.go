// Package stripeadapt implements checkout.Provider with the official Stripe Go SDK.
//
// Status: CANDIDATE. Callers pass the secret API key; this package does not
// persist secrets or decide entitlements. Prefer test-mode keys in development.
package stripeadapt

import (
	"context"
	"fmt"

	"github.com/ajent-social/go/billing/checkout"
	"github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/checkout/session"
	"github.com/stripe/stripe-go/v82/customer"
)

// Provider wraps Stripe customer and Checkout Session APIs.
type Provider struct {
	customers customer.Client
	sessions  session.Client
}

// New constructs a Provider for the given secret API key.
func New(apiKey string) (*Provider, error) {
	if apiKey == "" {
		return nil, checkout.ErrInvalid
	}
	b := stripe.GetBackend(stripe.APIBackend)
	return &Provider{
		customers: customer.Client{B: b, Key: apiKey},
		sessions:  session.Client{B: b, Key: apiKey},
	}, nil
}

func (p *Provider) CreateCustomer(ctx context.Context, account checkout.AccountID, idempotencyKey string) (checkout.CustomerRef, error) {
	params := &stripe.CustomerParams{}
	params.Context = ctx
	params.AddMetadata("amsl_account", string(account))
	params.SetIdempotencyKey(idempotencyKey)
	c, err := p.customers.New(params)
	if err != nil {
		return "", fmt.Errorf("stripe create customer: %w", err)
	}
	return checkout.CustomerRef(c.ID), nil
}

func (p *Provider) CreateCheckoutSession(ctx context.Context, in checkout.ProviderCheckout) (checkout.ProviderSession, error) {
	params := &stripe.CheckoutSessionParams{
		Mode:       stripe.String(string(stripe.CheckoutSessionModeSubscription)),
		SuccessURL: stripe.String(in.SuccessURL),
		CancelURL:  stripe.String(in.CancelURL),
		Customer:   stripe.String(string(in.CustomerRef)),
		LineItems: []*stripe.CheckoutSessionLineItemParams{{
			Price:    stripe.String(in.PriceID),
			Quantity: stripe.Int64(1),
		}},
	}
	params.Context = ctx
	params.AddMetadata("amsl_account", string(in.Account))
	params.AddMetadata("amsl_attempt", string(in.Attempt))
	params.SetIdempotencyKey(in.IdempotencyKey)
	s, err := p.sessions.New(params)
	if err != nil {
		return checkout.ProviderSession{}, fmt.Errorf("stripe create checkout session: %w", err)
	}
	return checkout.ProviderSession{
		ProviderRef: s.ID,
		URL:         s.URL,
		CustomerRef: in.CustomerRef,
		Completed:   s.Status == stripe.CheckoutSessionStatusComplete,
		Expired:     s.Status == stripe.CheckoutSessionStatusExpired,
	}, nil
}

func (p *Provider) GetCheckoutSession(ctx context.Context, providerRef string) (checkout.ProviderSession, error) {
	params := &stripe.CheckoutSessionParams{}
	params.Context = ctx
	s, err := p.sessions.Get(providerRef, params)
	if err != nil {
		return checkout.ProviderSession{}, fmt.Errorf("stripe get checkout session: %w", err)
	}
	var cust checkout.CustomerRef
	if s.Customer != nil {
		cust = checkout.CustomerRef(s.Customer.ID)
	}
	return checkout.ProviderSession{
		ProviderRef: s.ID,
		URL:         s.URL,
		CustomerRef: cust,
		Completed:   s.Status == stripe.CheckoutSessionStatusComplete,
		Expired:     s.Status == stripe.CheckoutSessionStatusExpired,
	}, nil
}

var _ checkout.Provider = (*Provider)(nil)
