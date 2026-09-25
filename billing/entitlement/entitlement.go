// Package entitlement gates product actions on subscription projection status.
//
// It does not talk to Stripe. Callers pass a local projection (or look it up)
// and an explicit allow-list of status strings. Redirect success is never
// treated as paid.
//
// Status: CANDIDATE. Capability: billing.entitlement.
package entitlement

import (
	"context"
	"errors"
	"strings"

	"github.com/ajent-social/go/billing/checkout"
	"github.com/ajent-social/go/billing/subscription"
)

var (
	ErrInvalid = errors.New("entitlement: invalid input")
	ErrDenied  = errors.New("entitlement: denied")
)

// DefaultAllowedStatuses are common Stripe subscription statuses that mean
// the customer may use paid product features. past_due is intentionally
// excluded — applications that grant grace must list it explicitly.
var DefaultAllowedStatuses = []string{"active", "trialing"}

// CustomerBindings looks up the Stripe customer bound to a local account.
type CustomerBindings interface {
	LookupCustomer(ctx context.Context, account checkout.AccountID) (checkout.CustomerBinding, error)
}

// Projections reads local subscription projections.
type Projections interface {
	GetProjection(ctx context.Context, customer subscription.CustomerRef) (subscription.Projection, error)
}

// Gate checks entitlement from durable local state only.
type Gate struct {
	bindings CustomerBindings
	subs     Projections
	allowed  map[string]struct{}
}

// Config for New.
type Config struct {
	// AllowedStatuses defaults to DefaultAllowedStatuses when empty.
	AllowedStatuses []string
}

// New constructs a Gate. bindings and subs are required.
func New(cfg Config, bindings CustomerBindings, subs Projections) (*Gate, error) {
	if bindings == nil || subs == nil {
		return nil, ErrInvalid
	}
	statuses := cfg.AllowedStatuses
	if len(statuses) == 0 {
		statuses = DefaultAllowedStatuses
	}
	allowed := map[string]struct{}{}
	for _, s := range statuses {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			return nil, ErrInvalid
		}
		allowed[s] = struct{}{}
	}
	return &Gate{bindings: bindings, subs: subs, allowed: allowed}, nil
}

// RequireStatus returns nil when status is in the allow-list.
func (g *Gate) RequireStatus(status string) error {
	if g == nil {
		return ErrInvalid
	}
	s := strings.ToLower(strings.TrimSpace(status))
	if _, ok := g.allowed[s]; !ok {
		return ErrDenied
	}
	return nil
}

// RequireProjection checks a projection already loaded by the caller.
func (g *Gate) RequireProjection(p subscription.Projection) error {
	return g.RequireStatus(p.Status)
}

// RequireAccount looks up the account's customer binding and projection.
func (g *Gate) RequireAccount(ctx context.Context, accountID checkout.AccountID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(string(accountID)) == "" {
		return ErrInvalid
	}
	cust, err := g.bindings.LookupCustomer(ctx, accountID)
	if err != nil {
		if errors.Is(err, checkout.ErrNotFound) {
			return ErrDenied
		}
		return err
	}
	rec, err := g.subs.GetProjection(ctx, subscription.CustomerRef(cust.CustomerRef))
	if err != nil {
		if errors.Is(err, subscription.ErrNotFound) {
			return ErrDenied
		}
		return err
	}
	return g.RequireProjection(rec)
}
