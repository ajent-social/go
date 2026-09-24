// Package portal opens Stripe Billing Portal sessions for self-serve billing
// management (invoices, payment method, cancel) around an existing customer ref.
//
// Status: CANDIDATE companion to billing.customer-checkout.
package portal

import (
	"context"
	"fmt"

	"github.com/ajent-social/go/billing/checkout"
	"github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/billingportal/session"
)

// Provider creates portal sessions for a provider customer.
type Provider interface {
	CreatePortalSession(ctx context.Context, customer checkout.CustomerRef, returnURL string) (string, error)
}

// Service looks up the local customer binding then opens a portal session.
type Service struct {
	store    checkout.Store
	provider Provider
}

// New binds checkout customer lookups to a portal Provider.
func New(store checkout.Store, provider Provider) (*Service, error) {
	if store == nil || provider == nil {
		return nil, checkout.ErrInvalid
	}
	return &Service{store: store, provider: provider}, nil
}

// Start opens a billing portal for the account's bound customer.
func (s *Service) Start(ctx context.Context, account checkout.AccountID, returnURL string) (string, error) {
	if account == "" || returnURL == "" {
		return "", checkout.ErrInvalid
	}
	bind, err := s.store.LookupCustomer(ctx, account)
	if err != nil {
		return "", err
	}
	return s.provider.CreatePortalSession(ctx, bind.CustomerRef, returnURL)
}

// Stripe implements Provider with stripe-go Billing Portal sessions.
type Stripe struct {
	sessions session.Client
}

// NewStripe constructs a Stripe portal provider.
func NewStripe(apiKey string) (*Stripe, error) {
	if apiKey == "" {
		return nil, checkout.ErrInvalid
	}
	b := stripe.GetBackend(stripe.APIBackend)
	return &Stripe{sessions: session.Client{B: b, Key: apiKey}}, nil
}

func (p *Stripe) CreatePortalSession(ctx context.Context, customer checkout.CustomerRef, returnURL string) (string, error) {
	params := &stripe.BillingPortalSessionParams{
		Customer:  stripe.String(string(customer)),
		ReturnURL: stripe.String(returnURL),
	}
	params.Context = ctx
	s, err := p.sessions.New(params)
	if err != nil {
		return "", fmt.Errorf("stripe billing portal: %w", err)
	}
	return s.URL, nil
}

var _ Provider = (*Stripe)(nil)
