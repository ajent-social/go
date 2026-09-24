// Package accounts is a thin subject registry for linking auth methods.
//
// It is not an organization model, RBAC engine, profile UI, or billing
// entitlement. Applications own workspace/tenant policy and store AMSL
// Owner IDs from Account.ID.
//
// Status: CANDIDATE. Capability: identity.accounts.
package accounts

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/mail"
	"strings"
	"time"
)

var (
	ErrInvalid  = errors.New("accounts: invalid input")
	ErrNotFound = errors.New("accounts: not found")
	ErrExists   = errors.New("accounts: already exists")
	ErrDenied   = errors.New("accounts: denied")
)

// Status is account lifecycle. Disabled accounts must fail closed at auth.
type Status string

const (
	StatusActive   Status = "active"
	StatusDisabled Status = "disabled"
)

// Account is the durable local subject.
type Account struct {
	ID          string
	Email       string // unique when non-empty; lowercased
	DisplayName string
	Status      Status
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Store persists accounts. Email uniqueness is enforced when Email != "".
type Store interface {
	Create(context.Context, Account) error
	Lookup(context.Context, string) (Account, error)
	LookupByEmail(context.Context, string) (Account, error)
	Update(context.Context, Account) error
}

// Service coordinates create/lookup/disable.
type Service struct {
	store Store
	now   func() time.Time
}

// New constructs a Service.
func New(store Store) (*Service, error) {
	if store == nil {
		return nil, ErrInvalid
	}
	return &Service{store: store, now: time.Now}, nil
}

// CreateInput creates an active account. ID is generated when empty.
type CreateInput struct {
	ID          string
	Email       string
	DisplayName string
}

// Create inserts an active account.
func (s *Service) Create(ctx context.Context, in CreateInput) (Account, error) {
	if err := ctx.Err(); err != nil {
		return Account{}, err
	}
	name := strings.TrimSpace(in.DisplayName)
	if name == "" || len(name) > 100 {
		return Account{}, ErrInvalid
	}
	email := ""
	if strings.TrimSpace(in.Email) != "" {
		var err error
		email, err = normalizeEmail(in.Email)
		if err != nil {
			return Account{}, err
		}
	}
	id := strings.TrimSpace(in.ID)
	if id == "" {
		var err error
		id, err = randomID()
		if err != nil {
			return Account{}, err
		}
	}
	now := s.now().UTC()
	a := Account{
		ID: id, Email: email, DisplayName: name,
		Status: StatusActive, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.store.Create(ctx, a); err != nil {
		return Account{}, err
	}
	return a, nil
}

// Get returns an account by ID.
func (s *Service) Get(ctx context.Context, id string) (Account, error) {
	if strings.TrimSpace(id) == "" {
		return Account{}, ErrInvalid
	}
	return s.store.Lookup(ctx, id)
}

// GetByEmail returns an account by normalized email.
func (s *Service) GetByEmail(ctx context.Context, email string) (Account, error) {
	e, err := normalizeEmail(email)
	if err != nil {
		return Account{}, err
	}
	return s.store.LookupByEmail(ctx, e)
}

// EnsureByEmail returns an existing account or creates one with displayName.
func (s *Service) EnsureByEmail(ctx context.Context, email, displayName string) (Account, error) {
	e, err := normalizeEmail(email)
	if err != nil {
		return Account{}, err
	}
	a, err := s.store.LookupByEmail(ctx, e)
	if err == nil {
		return a, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return Account{}, err
	}
	if displayName == "" {
		displayName = strings.Split(e, "@")[0]
	}
	return s.Create(ctx, CreateInput{Email: e, DisplayName: displayName})
}

// Disable marks an account disabled (fail closed for auth).
func (s *Service) Disable(ctx context.Context, id string) error {
	a, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if a.Status == StatusDisabled {
		return nil
	}
	a.Status = StatusDisabled
	a.UpdatedAt = s.now().UTC()
	return s.store.Update(ctx, a)
}

// RequireActive returns ErrDenied when missing or disabled.
func (s *Service) RequireActive(ctx context.Context, id string) (Account, error) {
	a, err := s.Get(ctx, id)
	if err != nil {
		return Account{}, err
	}
	if a.Status != StatusActive {
		return Account{}, ErrDenied
	}
	return a, nil
}

func normalizeEmail(raw string) (string, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" || len(raw) > 320 {
		return "", ErrInvalid
	}
	addr, err := mail.ParseAddress(raw)
	if err != nil || addr.Address != raw {
		return "", ErrInvalid
	}
	return raw, nil
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
