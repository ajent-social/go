// Package checkout coordinates durable local customer binding and hosted
// checkout attempts around an established payment provider.
//
// It is not a price engine, entitlement policy or payment processor. Callers
// authorize accounts, select approved prices and return URLs, and decide paid
// access from verified provider events — never from a success redirect alone.
//
// Status: CANDIDATE. Capability: billing.customer-checkout.
package checkout

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrInvalid     = errors.New("checkout: invalid input")
	ErrNotFound    = errors.New("checkout: not found")
	ErrExists      = errors.New("checkout: already exists")
	ErrConflict    = errors.New("checkout: conflict")
	ErrBusy        = errors.New("checkout: busy")
	ErrStaleLease  = errors.New("checkout: stale lease")
	ErrNeedsReview = errors.New("checkout: needs review")
)

// AccountID is the caller's local account identity.
type AccountID string

// AttemptID is a caller-stable logical attempt identity that survives retries.
type AttemptID string

// CustomerRef is a provider customer reference (never a card).
type CustomerRef string

// Kind classifies durable attempt rows.
type Kind string

const (
	KindEnsureCustomer Kind = "ensure_customer"
	KindCheckout       Kind = "checkout"
)

// Status is the durable attempt outcome. Redirect success is not a Status.
type Status string

const (
	StatusClaimed     Status = "claimed"
	StatusSucceeded   Status = "succeeded"
	StatusFailed      Status = "failed"
	StatusUnknown     Status = "unknown"
	StatusNeedsReview Status = "needs_review"
	StatusConflict    Status = "conflict"
)

// CustomerBinding associates one local account with one provider customer.
type CustomerBinding struct {
	Account     AccountID
	CustomerRef CustomerRef
	CreatedAt   time.Time
}

// AttemptRecord is storage-only durable attempt state.
type AttemptRecord struct {
	Account       AccountID
	Attempt       AttemptID
	Kind          Kind
	RequestHash   string
	IdempotencyKey string
	ProviderRef   string
	CustomerRef   CustomerRef
	CheckoutURL   string
	Status        Status
	LeaseEpoch    uint64
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// AttemptClaim requests exclusive work on an attempt.
type AttemptClaim struct {
	Account        AccountID
	Attempt        AttemptID
	Kind           Kind
	RequestHash    string
	IdempotencyKey string
	Now            time.Time
}

// AttemptCommit finalizes an attempt for a matching lease epoch.
type AttemptCommit struct {
	Account     AccountID
	Attempt     AttemptID
	LeaseEpoch  uint64
	Status      Status
	ProviderRef string
	CustomerRef CustomerRef
	CheckoutURL string
	Now         time.Time
}

// Store is durable local state. Implementations must not call the provider.
type Store interface {
	LookupCustomer(context.Context, AccountID) (CustomerBinding, error)
	InsertCustomer(context.Context, CustomerBinding) error
	LookupAttempt(context.Context, AccountID, AttemptID) (AttemptRecord, error)
	ClaimAttempt(context.Context, AttemptClaim) (AttemptRecord, error)
	CommitAttempt(context.Context, AttemptCommit) error
}

// Provider is the established payment SDK surface this package coordinates.
// Implementations should wrap the official Stripe SDK; this interface exists
// so tests can fake responses without live keys.
type Provider interface {
	CreateCustomer(ctx context.Context, account AccountID, idempotencyKey string) (CustomerRef, error)
	CreateCheckoutSession(ctx context.Context, in ProviderCheckout) (ProviderSession, error)
	GetCheckoutSession(ctx context.Context, providerRef string) (ProviderSession, error)
}

// ProviderCheckout is an approved hosted checkout request.
type ProviderCheckout struct {
	CustomerRef    CustomerRef
	PriceID        string
	SuccessURL     string
	CancelURL      string
	IdempotencyKey string
	Account        AccountID
	Attempt        AttemptID
}

// ProviderSession is provider-side checkout state.
type ProviderSession struct {
	ProviderRef string
	URL         string
	CustomerRef CustomerRef
	Completed   bool
	Expired     bool
}

// CheckoutInput is caller-approved checkout parameters.
type CheckoutInput struct {
	Account    AccountID
	Attempt    AttemptID
	PriceID    string
	SuccessURL string
	CancelURL  string
}

// CheckoutResult is local coordination output. URL is for redirect only.
type CheckoutResult struct {
	Status      Status
	CustomerRef CustomerRef
	ProviderRef string
	URL         string
}

// Service coordinates Store and Provider with lease-safe recovery.
type Service struct {
	store    Store
	provider Provider
	now      func() time.Time
}

// New constructs a Service. store and provider are required.
func New(store Store, provider Provider) (*Service, error) {
	if store == nil || provider == nil {
		return nil, ErrInvalid
	}
	return &Service{store: store, provider: provider, now: time.Now}, nil
}

func validAccount(a AccountID) bool {
	s := string(a)
	return len(s) > 0 && len(s) <= 256 && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\x00\r\n")
}

func validAttempt(a AttemptID) bool {
	s := string(a)
	return len(s) > 0 && len(s) <= 128 && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\x00\r\n")
}

func requestHash(parts ...string) string {
	h := sha256.New()
	for i, p := range parts {
		if i > 0 {
			_, _ = h.Write([]byte{0})
		}
		_, _ = h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func idempotencyKey(kind Kind, account AccountID, attempt AttemptID) string {
	return string(kind) + ":" + string(account) + ":" + string(attempt)
}

// ensureAttemptID derives a short, stable EnsureCustomer attempt from a
// checkout attempt so StartCheckout cannot exceed AttemptID length limits.
func ensureAttemptID(checkoutAttempt AttemptID) AttemptID {
	sum := sha256.Sum256([]byte("ensure|" + string(checkoutAttempt)))
	return AttemptID("e" + hex.EncodeToString(sum[:16]))
}

func resultFrom(rec AttemptRecord) CheckoutResult {
	return CheckoutResult{Status: rec.Status, CustomerRef: rec.CustomerRef, ProviderRef: rec.ProviderRef, URL: rec.CheckoutURL}
}

func terminalResult(rec AttemptRecord) (CheckoutResult, error, bool) {
	switch rec.Status {
	case StatusSucceeded, StatusFailed:
		return resultFrom(rec), nil, true
	case StatusNeedsReview, StatusConflict:
		return resultFrom(rec), ErrNeedsReview, true
	default:
		return CheckoutResult{}, nil, false
	}
}

// EnsureCustomer binds a local account to a provider customer using attempt
// identity for durable recovery after lost responses.
func (s *Service) EnsureCustomer(ctx context.Context, account AccountID, attempt AttemptID) (CustomerRef, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !validAccount(account) || !validAttempt(attempt) {
		return "", ErrInvalid
	}
	if b, err := s.store.LookupCustomer(ctx, account); err == nil {
		return b.CustomerRef, nil
	} else if !errors.Is(err, ErrNotFound) {
		return "", err
	}

	now := s.now().UTC()
	hash := requestHash("ensure_customer", string(account))
	key := idempotencyKey(KindEnsureCustomer, account, attempt)
	rec, err := s.store.ClaimAttempt(ctx, AttemptClaim{
		Account: account, Attempt: attempt, Kind: KindEnsureCustomer,
		RequestHash: hash, IdempotencyKey: key, Now: now,
	})
	if err != nil {
		return "", err
	}
	if rec.Status == StatusSucceeded && rec.CustomerRef != "" {
		return rec.CustomerRef, nil
	}

	ref, err := s.provider.CreateCustomer(ctx, account, key)
	if err != nil {
		_ = s.store.CommitAttempt(ctx, AttemptCommit{
			Account: account, Attempt: attempt, LeaseEpoch: rec.LeaseEpoch,
			Status: StatusUnknown, Now: s.now().UTC(),
		})
		return "", fmt.Errorf("create customer: %w", err)
	}
	if err := s.store.InsertCustomer(ctx, CustomerBinding{Account: account, CustomerRef: ref, CreatedAt: s.now().UTC()}); err != nil && !errors.Is(err, ErrExists) {
		_ = s.store.CommitAttempt(ctx, AttemptCommit{
			Account: account, Attempt: attempt, LeaseEpoch: rec.LeaseEpoch,
			Status: StatusUnknown, CustomerRef: ref, Now: s.now().UTC(),
		})
		return "", err
	}
	if err := s.store.CommitAttempt(ctx, AttemptCommit{
		Account: account, Attempt: attempt, LeaseEpoch: rec.LeaseEpoch,
		Status: StatusSucceeded, CustomerRef: ref, Now: s.now().UTC(),
	}); err != nil {
		return "", err
	}
	b, err := s.store.LookupCustomer(ctx, account)
	if err != nil {
		return ref, nil
	}
	return b.CustomerRef, nil
}

// StartCheckout begins a hosted checkout for an approved price and returns.
// The returned URL is not payment evidence.
func (s *Service) StartCheckout(ctx context.Context, in CheckoutInput) (CheckoutResult, error) {
	if err := ctx.Err(); err != nil {
		return CheckoutResult{}, err
	}
	if !validAccount(in.Account) || !validAttempt(in.Attempt) || strings.TrimSpace(in.PriceID) == "" ||
		strings.TrimSpace(in.SuccessURL) == "" || strings.TrimSpace(in.CancelURL) == "" {
		return CheckoutResult{}, ErrInvalid
	}
	customer, err := s.EnsureCustomer(ctx, in.Account, ensureAttemptID(in.Attempt))
	if err != nil {
		return CheckoutResult{}, err
	}

	now := s.now().UTC()
	hash := requestHash("checkout", string(in.Account), in.PriceID, in.SuccessURL, in.CancelURL)
	key := idempotencyKey(KindCheckout, in.Account, in.Attempt)
	rec, err := s.store.ClaimAttempt(ctx, AttemptClaim{
		Account: in.Account, Attempt: in.Attempt, Kind: KindCheckout,
		RequestHash: hash, IdempotencyKey: key, Now: now,
	})
	if err != nil {
		return CheckoutResult{}, err
	}
	if rec.Status == StatusSucceeded && rec.CheckoutURL != "" {
		return CheckoutResult{Status: rec.Status, CustomerRef: customer, ProviderRef: rec.ProviderRef, URL: rec.CheckoutURL}, nil
	}

	session, err := s.provider.CreateCheckoutSession(ctx, ProviderCheckout{
		CustomerRef: customer, PriceID: in.PriceID, SuccessURL: in.SuccessURL,
		CancelURL: in.CancelURL, IdempotencyKey: key, Account: in.Account, Attempt: in.Attempt,
	})
	if err != nil {
		_ = s.store.CommitAttempt(ctx, AttemptCommit{
			Account: in.Account, Attempt: in.Attempt, LeaseEpoch: rec.LeaseEpoch,
			Status: StatusUnknown, CustomerRef: customer, Now: s.now().UTC(),
		})
		return CheckoutResult{}, fmt.Errorf("create checkout session: %w", err)
	}
	if err := s.store.CommitAttempt(ctx, AttemptCommit{
		Account: in.Account, Attempt: in.Attempt, LeaseEpoch: rec.LeaseEpoch,
		Status: StatusSucceeded, ProviderRef: session.ProviderRef, CustomerRef: customer,
		CheckoutURL: session.URL, Now: s.now().UTC(),
	}); err != nil {
		return CheckoutResult{}, err
	}
	return CheckoutResult{Status: StatusSucceeded, CustomerRef: customer, ProviderRef: session.ProviderRef, URL: session.URL}, nil
}

// RecoverAttempt resolves an in-flight or unknown attempt without starting a
// new unguarded provider create. It claims a fresh lease before committing so
// it cannot overwrite another worker's terminal result on a stale epoch.
func (s *Service) RecoverAttempt(ctx context.Context, account AccountID, attempt AttemptID) (CheckoutResult, error) {
	if err := ctx.Err(); err != nil {
		return CheckoutResult{}, err
	}
	if !validAccount(account) || !validAttempt(attempt) {
		return CheckoutResult{}, ErrInvalid
	}
	rec, err := s.store.LookupAttempt(ctx, account, attempt)
	if err != nil {
		return CheckoutResult{}, err
	}
	if out, err, done := terminalResult(rec); done {
		return out, err
	}
	if rec.ProviderRef == "" {
		return CheckoutResult{Status: StatusNeedsReview}, ErrNeedsReview
	}

	now := s.now().UTC()
	rec, err = s.store.ClaimAttempt(ctx, AttemptClaim{
		Account: account, Attempt: attempt, Kind: rec.Kind,
		RequestHash: rec.RequestHash, IdempotencyKey: rec.IdempotencyKey, Now: now,
	})
	if err != nil {
		return CheckoutResult{}, err
	}
	if out, err, done := terminalResult(rec); done {
		return out, err
	}
	if rec.ProviderRef == "" {
		return CheckoutResult{Status: StatusNeedsReview}, ErrNeedsReview
	}

	session, err := s.provider.GetCheckoutSession(ctx, rec.ProviderRef)
	if err != nil {
		return CheckoutResult{Status: StatusUnknown, ProviderRef: rec.ProviderRef}, fmt.Errorf("recover session: %w", err)
	}
	status := StatusSucceeded
	if session.Expired {
		status = StatusFailed
	}
	if err := s.store.CommitAttempt(ctx, AttemptCommit{
		Account: account, Attempt: attempt, LeaseEpoch: rec.LeaseEpoch,
		Status: status, ProviderRef: session.ProviderRef, CustomerRef: session.CustomerRef,
		CheckoutURL: session.URL, Now: s.now().UTC(),
	}); err != nil {
		if errors.Is(err, ErrStaleLease) {
			latest, lerr := s.store.LookupAttempt(ctx, account, attempt)
			if lerr != nil {
				return CheckoutResult{}, lerr
			}
			if out, err, done := terminalResult(latest); done {
				return out, err
			}
			return resultFrom(latest), ErrBusy
		}
		return CheckoutResult{}, err
	}
	return CheckoutResult{Status: status, CustomerRef: session.CustomerRef, ProviderRef: session.ProviderRef, URL: session.URL}, nil
}
