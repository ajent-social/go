// Package stripeverify verifies Stripe webhook signatures using the official
// stripe-go webhook helpers and maps events into subscription.VerifiedEvent
// fields for AcceptVerifiedEvent.
//
// Status: CANDIDATE companion to billing.subscription-reconciliation.
package stripeverify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ajent-social/go/billing/subscription"
	"github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/webhook"
)

var (
	ErrInvalid = errors.New("stripeverify: invalid input")
	ErrDenied  = errors.New("stripeverify: signature denied")
)

// Verifier checks Stripe-Signature headers against a webhook signing secret.
type Verifier struct {
	secret               string
	tolerance            time.Duration
	ignoreAPIVersionMismatch bool
}

// Config for New. Secret is required (whsec_…).
type Config struct {
	Secret                   string
	Tolerance                time.Duration // default webhook.DefaultTolerance
	IgnoreAPIVersionMismatch bool          // allow endpoint API version ≠ stripe-go constant
}

// New constructs a Verifier.
func New(cfg Config) (*Verifier, error) {
	if strings.TrimSpace(cfg.Secret) == "" {
		return nil, ErrInvalid
	}
	tol := cfg.Tolerance
	if tol == 0 {
		tol = webhook.DefaultTolerance
	}
	return &Verifier{
		secret:                   cfg.Secret,
		tolerance:                tol,
		ignoreAPIVersionMismatch: cfg.IgnoreAPIVersionMismatch,
	}, nil
}

// Parse verifies the payload and returns a VerifiedEvent suitable for
// subscription.AcceptVerifiedEvent. Customer/subscription fields are extracted
// from common subscription.* event shapes; unmatched events still return a
// VerifiedEvent with empty CustomerRef for durable inbox storage.
func (v *Verifier) Parse(payload []byte, stripeSignatureHeader string) (subscription.VerifiedEvent, error) {
	if v == nil {
		return subscription.VerifiedEvent{}, ErrInvalid
	}
	if len(payload) == 0 || strings.TrimSpace(stripeSignatureHeader) == "" {
		return subscription.VerifiedEvent{}, ErrInvalid
	}
	ev, err := webhook.ConstructEventWithOptions(payload, stripeSignatureHeader, v.secret, webhook.ConstructEventOptions{
		Tolerance:                v.tolerance,
		IgnoreAPIVersionMismatch: v.ignoreAPIVersionMismatch,
	})
	if err != nil {
		return subscription.VerifiedEvent{}, fmt.Errorf("%w: %v", ErrDenied, err)
	}
	return MapEvent(ev, payload, time.Now().UTC())
}

// MapEvent converts a verified stripe.Event into a VerifiedEvent.
func MapEvent(ev stripe.Event, rawPayload []byte, receivedAt time.Time) (subscription.VerifiedEvent, error) {
	if ev.ID == "" || ev.Type == "" {
		return subscription.VerifiedEvent{}, ErrInvalid
	}
	sum := sha256.Sum256(rawPayload)
	out := subscription.VerifiedEvent{
		ID:          subscription.EventID(ev.ID),
		Livemode:    subscription.Livemode(ev.Livemode),
		Type:        string(ev.Type),
		PayloadHash: hex.EncodeToString(sum[:]),
		ReceivedAt:  receivedAt.UTC(),
	}
	obj := ev.Data.Object
	if obj == nil {
		var envelope struct {
			Data struct {
				Object map[string]any `json:"object"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rawPayload, &envelope); err == nil {
			obj = envelope.Data.Object
		}
	}
	if obj == nil && len(ev.Data.Raw) > 0 {
		_ = json.Unmarshal(ev.Data.Raw, &obj)
	}
	if obj == nil {
		return out, nil
	}
	if id, _ := obj["id"].(string); strings.HasPrefix(id, "sub_") {
		out.SubscriptionRef = subscription.SubscriptionRef(id)
	}
	switch c := obj["customer"].(type) {
	case string:
		out.CustomerRef = subscription.CustomerRef(c)
	case map[string]any:
		if id, _ := c["id"].(string); id != "" {
			out.CustomerRef = subscription.CustomerRef(id)
		}
	}
	if st, _ := obj["status"].(string); st != "" {
		out.Status = st
	}
	if pe, ok := obj["current_period_end"].(float64); ok && pe > 0 {
		out.PeriodEnd = time.Unix(int64(pe), 0).UTC()
	}
	return out, nil
}
