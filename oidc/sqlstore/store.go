// Package sqlstore persists OIDC pending states and bindings via database/sql.
package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/ajent-social/go/oidc"
)

// Schema is applied idempotently by Open.
const Schema = `
CREATE TABLE IF NOT EXISTS amsl_oidc_pending (
  state_digest BYTEA PRIMARY KEY,
  provider TEXT NOT NULL,
  nonce TEXT NOT NULL DEFAULT '',
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  CONSTRAINT amsl_oidc_pending_digest_len CHECK (octet_length(state_digest) = 32)
);
CREATE TABLE IF NOT EXISTS amsl_oidc_bindings (
  provider TEXT NOT NULL,
  subject TEXT NOT NULL,
  account_id TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (provider, subject)
);
CREATE INDEX IF NOT EXISTS amsl_oidc_bindings_account_idx
  ON amsl_oidc_bindings (account_id);
`

// Store is a multi-host oidc.Store.
type Store struct{ db *sql.DB }

// Open pings db and applies Schema.
func Open(ctx context.Context, db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, oidc.ErrInvalid
	}
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping oidc database: %w", err)
	}
	if _, err := db.ExecContext(ctx, Schema); err != nil {
		return nil, fmt.Errorf("apply oidc schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) PutPending(ctx context.Context, p oidc.Pending) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO amsl_oidc_pending (state_digest, provider, nonce, expires_at, created_at)
VALUES ($1,$2,$3,$4,$5)`,
		p.StateDigest[:], string(p.Provider), p.Nonce, p.ExpiresAt.UTC(), p.CreatedAt.UTC())
	if isUnique(err) {
		return oidc.ErrExists
	}
	return err
}

func (s *Store) TakePending(ctx context.Context, digest [32]byte) (oidc.Pending, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return oidc.Pending{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var p oidc.Pending
	var dig []byte
	var provider string
	err = tx.QueryRowContext(ctx, `
SELECT state_digest, provider, nonce, expires_at, created_at
FROM amsl_oidc_pending WHERE state_digest = $1 FOR UPDATE`, digest[:]).Scan(
		&dig, &provider, &p.Nonce, &p.ExpiresAt, &p.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return oidc.Pending{}, oidc.ErrNotFound
	}
	if err != nil {
		return oidc.Pending{}, err
	}
	if len(dig) != 32 {
		return oidc.Pending{}, fmt.Errorf("oidc: bad digest length")
	}
	copy(p.StateDigest[:], dig)
	p.Provider = oidc.ProviderID(provider)
	p.ExpiresAt, p.CreatedAt = p.ExpiresAt.UTC(), p.CreatedAt.UTC()
	if _, err := tx.ExecContext(ctx, `DELETE FROM amsl_oidc_pending WHERE state_digest = $1`, digest[:]); err != nil {
		return oidc.Pending{}, err
	}
	if err := tx.Commit(); err != nil {
		return oidc.Pending{}, err
	}
	return p, nil
}

func (s *Store) PutBinding(ctx context.Context, b oidc.Binding) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var existing string
	err = tx.QueryRowContext(ctx, `
SELECT account_id FROM amsl_oidc_bindings WHERE provider = $1 AND subject = $2 FOR UPDATE`,
		string(b.Provider), b.Subject).Scan(&existing)
	if errors.Is(err, sql.ErrNoRows) {
		_, err = tx.ExecContext(ctx, `
INSERT INTO amsl_oidc_bindings (provider, subject, account_id, created_at)
VALUES ($1,$2,$3,$4)`, string(b.Provider), b.Subject, b.AccountID, b.CreatedAt.UTC())
		if err != nil {
			return err
		}
		return tx.Commit()
	}
	if err != nil {
		return err
	}
	if existing != b.AccountID {
		return oidc.ErrExists
	}
	return tx.Commit()
}

func (s *Store) LookupBinding(ctx context.Context, provider oidc.ProviderID, subject string) (oidc.Binding, error) {
	var b oidc.Binding
	var p string
	err := s.db.QueryRowContext(ctx, `
SELECT provider, subject, account_id, created_at FROM amsl_oidc_bindings
WHERE provider = $1 AND subject = $2`, string(provider), subject).Scan(
		&p, &b.Subject, &b.AccountID, &b.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return oidc.Binding{}, oidc.ErrNotFound
	}
	if err != nil {
		return oidc.Binding{}, err
	}
	b.Provider = oidc.ProviderID(p)
	b.CreatedAt = b.CreatedAt.UTC()
	return b, nil
}

func (s *Store) LookupBindingsByAccount(ctx context.Context, accountID string) ([]oidc.Binding, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT provider, subject, account_id, created_at FROM amsl_oidc_bindings WHERE account_id = $1`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []oidc.Binding
	for rows.Next() {
		var b oidc.Binding
		var p string
		if err := rows.Scan(&p, &b.Subject, &b.AccountID, &b.CreatedAt); err != nil {
			return nil, err
		}
		b.Provider = oidc.ProviderID(p)
		b.CreatedAt = b.CreatedAt.UTC()
		out = append(out, b)
	}
	return out, rows.Err()
}

func isUnique(err error) bool {
	if err == nil {
		return false
	}
	type stater interface{ SQLState() string }
	var st stater
	if errors.As(err, &st) && st.SQLState() == "23505" {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "23505") || strings.Contains(msg, "unique constraint") || strings.Contains(msg, "duplicate key")
}

var _ oidc.Store = (*Store)(nil)
