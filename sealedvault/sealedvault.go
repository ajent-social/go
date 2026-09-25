// Package sealedvault stores caller-sealed ciphertext blobs.
//
// The package never encrypts or decrypts. Callers seal with their KMS/AEAD and
// pass ciphertext only. Plaintext in Args is a contract violation.
//
// Status: CANDIDATE. Capability: infrastructure.sealed-vault.
package sealedvault

import (
	"context"
	"errors"
	"strings"
	"time"
)

var (
	ErrInvalid  = errors.New("sealedvault: invalid input")
	ErrNotFound = errors.New("sealedvault: not found")
	ErrExists   = errors.New("sealedvault: exists")
)

// Record is storage-only sealed material.
type Record struct {
	Owner      string
	Name       string
	Ciphertext []byte
	UpdatedAt  time.Time
}

// Store persists sealed records.
type Store interface {
	Put(context.Context, Record) error
	Get(ctx context.Context, owner, name string) (Record, error)
	Delete(ctx context.Context, owner, name string) error
}

// Service validates and forwards sealed blobs.
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

// PutInput is a sealed write. Ciphertext must be non-empty.
type PutInput struct {
	Owner      string
	Name       string
	Ciphertext []byte
}

// Put stores or replaces a sealed blob.
func (s *Service) Put(ctx context.Context, in PutInput) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	if err := validate(in.Owner, in.Name); err != nil {
		return Record{}, err
	}
	if len(in.Ciphertext) == 0 {
		return Record{}, ErrInvalid
	}
	rec := Record{
		Owner: in.Owner, Name: in.Name,
		Ciphertext: append([]byte(nil), in.Ciphertext...),
		UpdatedAt:  s.now().UTC(),
	}
	if err := s.store.Put(ctx, rec); err != nil {
		return Record{}, err
	}
	return rec, nil
}

// Get returns a sealed record (ciphertext only).
func (s *Service) Get(ctx context.Context, owner, name string) (Record, error) {
	if err := validate(owner, name); err != nil {
		return Record{}, err
	}
	return s.store.Get(ctx, owner, name)
}

// Delete removes a sealed record.
func (s *Service) Delete(ctx context.Context, owner, name string) error {
	if err := validate(owner, name); err != nil {
		return err
	}
	return s.store.Delete(ctx, owner, name)
}

func validate(owner, name string) error {
	if strings.TrimSpace(owner) == "" || strings.TrimSpace(name) == "" {
		return ErrInvalid
	}
	if strings.Contains(name, "/") {
		return ErrInvalid
	}
	return nil
}
