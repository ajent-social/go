// Package sqlstore persists checkout bindings and attempts in PostgreSQL-compatible SQL.
package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/ajent-social/go/billing/checkout"
)

// Schema is applied idempotently by Open.
const Schema = `
CREATE TABLE IF NOT EXISTS amsl_billing_customers (
  account TEXT PRIMARY KEY,
  customer_ref TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS amsl_billing_attempts (
  account TEXT NOT NULL,
  attempt TEXT NOT NULL,
  kind TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  provider_ref TEXT NOT NULL DEFAULT '',
  customer_ref TEXT NOT NULL DEFAULT '',
  checkout_url TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL,
  lease_epoch BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (account, attempt)
);
CREATE INDEX IF NOT EXISTS amsl_billing_attempts_active_idx
  ON amsl_billing_attempts (kind, account, status);
`

// Store is a multi-host checkout.Store.
type Store struct{ db *sql.DB }

// Open pings db and applies Schema.
func Open(ctx context.Context, db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, checkout.ErrInvalid
	}
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping billing database: %w", err)
	}
	if _, err := db.ExecContext(ctx, Schema); err != nil {
		return nil, fmt.Errorf("apply billing schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) LookupCustomer(ctx context.Context, account checkout.AccountID) (checkout.CustomerBinding, error) {
	var b checkout.CustomerBinding
	err := s.db.QueryRowContext(ctx, `
SELECT account, customer_ref, created_at FROM amsl_billing_customers WHERE account = $1`, account).
		Scan(&b.Account, &b.CustomerRef, &b.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return checkout.CustomerBinding{}, checkout.ErrNotFound
	}
	if err != nil {
		return checkout.CustomerBinding{}, err
	}
	b.CreatedAt = b.CreatedAt.UTC()
	return b, nil
}

func (s *Store) InsertCustomer(ctx context.Context, b checkout.CustomerBinding) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO amsl_billing_customers (account, customer_ref, created_at) VALUES ($1, $2, $3)`,
		b.Account, b.CustomerRef, b.CreatedAt.UTC())
	if err != nil {
		if isUnique(err) {
			return checkout.ErrExists
		}
		return err
	}
	return nil
}

func (s *Store) LookupAttempt(ctx context.Context, account checkout.AccountID, attempt checkout.AttemptID) (checkout.AttemptRecord, error) {
	var r checkout.AttemptRecord
	err := s.db.QueryRowContext(ctx, `
SELECT account, attempt, kind, request_hash, idempotency_key, provider_ref, customer_ref,
       checkout_url, status, lease_epoch, created_at, updated_at
FROM amsl_billing_attempts WHERE account = $1 AND attempt = $2`, account, attempt).Scan(
		&r.Account, &r.Attempt, &r.Kind, &r.RequestHash, &r.IdempotencyKey, &r.ProviderRef,
		&r.CustomerRef, &r.CheckoutURL, &r.Status, &r.LeaseEpoch, &r.CreatedAt, &r.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return checkout.AttemptRecord{}, checkout.ErrNotFound
	}
	if err != nil {
		return checkout.AttemptRecord{}, err
	}
	r.CreatedAt, r.UpdatedAt = r.CreatedAt.UTC(), r.UpdatedAt.UTC()
	return r, nil
}

func (s *Store) ClaimAttempt(ctx context.Context, claim checkout.AttemptClaim) (checkout.AttemptRecord, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return checkout.AttemptRecord{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var r checkout.AttemptRecord
	err = tx.QueryRowContext(ctx, `
SELECT account, attempt, kind, request_hash, idempotency_key, provider_ref, customer_ref,
       checkout_url, status, lease_epoch, created_at, updated_at
FROM amsl_billing_attempts WHERE account = $1 AND attempt = $2 FOR UPDATE`, claim.Account, claim.Attempt).Scan(
		&r.Account, &r.Attempt, &r.Kind, &r.RequestHash, &r.IdempotencyKey, &r.ProviderRef,
		&r.CustomerRef, &r.CheckoutURL, &r.Status, &r.LeaseEpoch, &r.CreatedAt, &r.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		var busy string
		qerr := tx.QueryRowContext(ctx, `
SELECT attempt FROM amsl_billing_attempts
WHERE kind = $1 AND account = $2 AND status IN ('claimed', 'unknown') AND attempt <> $3
LIMIT 1 FOR UPDATE`, claim.Kind, claim.Account, claim.Attempt).Scan(&busy)
		if qerr == nil {
			return checkout.AttemptRecord{}, checkout.ErrBusy
		}
		if qerr != nil && !errors.Is(qerr, sql.ErrNoRows) {
			return checkout.AttemptRecord{}, qerr
		}
		r = checkout.AttemptRecord{
			Account: claim.Account, Attempt: claim.Attempt, Kind: claim.Kind,
			RequestHash: claim.RequestHash, IdempotencyKey: claim.IdempotencyKey,
			Status: checkout.StatusClaimed, LeaseEpoch: 1,
			CreatedAt: claim.Now, UpdatedAt: claim.Now,
		}
		_, err = tx.ExecContext(ctx, `
INSERT INTO amsl_billing_attempts
 (account, attempt, kind, request_hash, idempotency_key, provider_ref, customer_ref,
  checkout_url, status, lease_epoch, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,'','','',$6,$7,$8,$9)`,
			r.Account, r.Attempt, r.Kind, r.RequestHash, r.IdempotencyKey,
			r.Status, r.LeaseEpoch, r.CreatedAt.UTC(), r.UpdatedAt.UTC())
		if err != nil {
			return checkout.AttemptRecord{}, err
		}
		if err := tx.Commit(); err != nil {
			return checkout.AttemptRecord{}, err
		}
		return r, nil
	}
	if err != nil {
		return checkout.AttemptRecord{}, err
	}
	if r.RequestHash != claim.RequestHash {
		_, err = tx.ExecContext(ctx, `
UPDATE amsl_billing_attempts SET status = $3, updated_at = $4 WHERE account = $1 AND attempt = $2`,
			claim.Account, claim.Attempt, checkout.StatusConflict, claim.Now.UTC())
		if err != nil {
			return checkout.AttemptRecord{}, err
		}
		if err := tx.Commit(); err != nil {
			return checkout.AttemptRecord{}, err
		}
		return checkout.AttemptRecord{}, checkout.ErrConflict
	}
	if r.Status == checkout.StatusSucceeded || r.Status == checkout.StatusFailed || r.Status == checkout.StatusNeedsReview {
		if err := tx.Commit(); err != nil {
			return checkout.AttemptRecord{}, err
		}
		r.CreatedAt, r.UpdatedAt = r.CreatedAt.UTC(), r.UpdatedAt.UTC()
		return r, nil
	}
	r.LeaseEpoch++
	r.Status = checkout.StatusClaimed
	r.UpdatedAt = claim.Now
	_, err = tx.ExecContext(ctx, `
UPDATE amsl_billing_attempts SET status = $3, lease_epoch = $4, updated_at = $5
WHERE account = $1 AND attempt = $2`, claim.Account, claim.Attempt, r.Status, r.LeaseEpoch, r.UpdatedAt.UTC())
	if err != nil {
		return checkout.AttemptRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return checkout.AttemptRecord{}, err
	}
	r.CreatedAt = r.CreatedAt.UTC()
	return r, nil
}

func (s *Store) CommitAttempt(ctx context.Context, commit checkout.AttemptCommit) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var epoch uint64
	err = tx.QueryRowContext(ctx, `
SELECT lease_epoch FROM amsl_billing_attempts WHERE account = $1 AND attempt = $2 FOR UPDATE`,
		commit.Account, commit.Attempt).Scan(&epoch)
	if errors.Is(err, sql.ErrNoRows) {
		return checkout.ErrNotFound
	}
	if err != nil {
		return err
	}
	if epoch != commit.LeaseEpoch {
		return checkout.ErrStaleLease
	}
	_, err = tx.ExecContext(ctx, `
UPDATE amsl_billing_attempts SET
  status = $3,
  provider_ref = CASE WHEN $4 = '' THEN provider_ref ELSE $4 END,
  customer_ref = CASE WHEN $5 = '' THEN customer_ref ELSE $5 END,
  checkout_url = CASE WHEN $6 = '' THEN checkout_url ELSE $6 END,
  updated_at = $7
WHERE account = $1 AND attempt = $2`,
		commit.Account, commit.Attempt, commit.Status,
		commit.ProviderRef, commit.CustomerRef, commit.CheckoutURL, commit.Now.UTC())
	if err != nil {
		return err
	}
	return tx.Commit()
}

func isUnique(err error) bool {
	if err == nil {
		return false
	}
	type stater interface{ SQLState() string }
	var s stater
	if errors.As(err, &s) && s.SQLState() == "23505" {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "23505") || strings.Contains(msg, "unique constraint") || strings.Contains(msg, "duplicate key")
}