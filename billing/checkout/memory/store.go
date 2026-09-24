package memory

import (
	"context"
	"sync"

	"github.com/ajent-social/go/billing/checkout"
)

// Store is an in-memory checkout.Store for tests and single-process demos.
type Store struct {
	mu        sync.Mutex
	customers map[checkout.AccountID]checkout.CustomerBinding
	attempts  map[string]checkout.AttemptRecord
	active    map[string]string // kind|account -> attempt id
}

// New returns an empty Store.
func New() *Store {
	return &Store{
		customers: map[checkout.AccountID]checkout.CustomerBinding{},
		attempts:  map[string]checkout.AttemptRecord{},
		active:    map[string]string{},
	}
}

func key(account checkout.AccountID, attempt checkout.AttemptID) string {
	return string(account) + "\x00" + string(attempt)
}

func activeKey(kind checkout.Kind, account checkout.AccountID) string {
	return string(kind) + "|" + string(account)
}

func (s *Store) LookupCustomer(_ context.Context, account checkout.AccountID) (checkout.CustomerBinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.customers[account]
	if !ok {
		return checkout.CustomerBinding{}, checkout.ErrNotFound
	}
	return b, nil
}

func (s *Store) InsertCustomer(_ context.Context, b checkout.CustomerBinding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.customers[b.Account]; ok {
		return checkout.ErrExists
	}
	s.customers[b.Account] = b
	return nil
}

func (s *Store) LookupAttempt(_ context.Context, account checkout.AccountID, attempt checkout.AttemptID) (checkout.AttemptRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.attempts[key(account, attempt)]
	if !ok {
		return checkout.AttemptRecord{}, checkout.ErrNotFound
	}
	return rec, nil
}

func (s *Store) ClaimAttempt(_ context.Context, claim checkout.AttemptClaim) (checkout.AttemptRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(claim.Account, claim.Attempt)
	if rec, ok := s.attempts[k]; ok {
		if rec.RequestHash != claim.RequestHash {
			rec.Status = checkout.StatusConflict
			s.attempts[k] = rec
			return checkout.AttemptRecord{}, checkout.ErrConflict
		}
		if rec.Status == checkout.StatusSucceeded || rec.Status == checkout.StatusFailed || rec.Status == checkout.StatusNeedsReview {
			return rec, nil
		}
		rec.LeaseEpoch++
		rec.Status = checkout.StatusClaimed
		rec.UpdatedAt = claim.Now
		s.attempts[k] = rec
		s.active[activeKey(claim.Kind, claim.Account)] = string(claim.Attempt)
		return rec, nil
	}
	if other, ok := s.active[activeKey(claim.Kind, claim.Account)]; ok && other != string(claim.Attempt) {
		orecord, exists := s.attempts[key(claim.Account, checkout.AttemptID(other))]
		if exists && (orecord.Status == checkout.StatusClaimed || orecord.Status == checkout.StatusUnknown) {
			return checkout.AttemptRecord{}, checkout.ErrBusy
		}
	}
	rec := checkout.AttemptRecord{
		Account: claim.Account, Attempt: claim.Attempt, Kind: claim.Kind,
		RequestHash: claim.RequestHash, IdempotencyKey: claim.IdempotencyKey,
		Status: checkout.StatusClaimed, LeaseEpoch: 1,
		CreatedAt: claim.Now, UpdatedAt: claim.Now,
	}
	s.attempts[k] = rec
	s.active[activeKey(claim.Kind, claim.Account)] = string(claim.Attempt)
	return rec, nil
}

func (s *Store) CommitAttempt(_ context.Context, commit checkout.AttemptCommit) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(commit.Account, commit.Attempt)
	rec, ok := s.attempts[k]
	if !ok {
		return checkout.ErrNotFound
	}
	if rec.LeaseEpoch != commit.LeaseEpoch {
		return checkout.ErrStaleLease
	}
	rec.Status = commit.Status
	if commit.ProviderRef != "" {
		rec.ProviderRef = commit.ProviderRef
	}
	if commit.CustomerRef != "" {
		rec.CustomerRef = commit.CustomerRef
	}
	if commit.CheckoutURL != "" {
		rec.CheckoutURL = commit.CheckoutURL
	}
	rec.UpdatedAt = commit.Now
	s.attempts[k] = rec
	if commit.Status == checkout.StatusSucceeded || commit.Status == checkout.StatusFailed || commit.Status == checkout.StatusNeedsReview {
		ak := activeKey(rec.Kind, commit.Account)
		if s.active[ak] == string(commit.Attempt) {
			delete(s.active, ak)
		}
	}
	return nil
}
