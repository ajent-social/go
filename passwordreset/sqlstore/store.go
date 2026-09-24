// Package sqlstore persists password-reset challenges via database/sql.
package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/ajent-social/go/passwordreset"
)

const Schema = `
CREATE TABLE IF NOT EXISTS amsl_password_reset (
  token_digest BYTEA PRIMARY KEY,
  account_id TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  CONSTRAINT amsl_password_reset_digest_len CHECK (octet_length(token_digest) = 32)
);
CREATE INDEX IF NOT EXISTS amsl_password_reset_account_idx ON amsl_password_reset (account_id);
`

// Store is a SQL adapter.
type Store struct{ db *sql.DB }

// Open applies Schema.
func Open(ctx context.Context, db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, passwordreset.ErrInvalid
	}
	if err := db.PingContext(ctx); err != nil {
		return nil, err
	}
	if _, err := db.ExecContext(ctx, Schema); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Put(ctx context.Context, ch passwordreset.Challenge) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO amsl_password_reset (token_digest, account_id, expires_at, created_at)
VALUES ($1,$2,$3,$4)`, ch.TokenDigest[:], ch.AccountID, ch.ExpiresAt.UTC(), ch.CreatedAt.UTC())
	if err != nil && (strings.Contains(strings.ToLower(err.Error()), "unique") || strings.Contains(strings.ToLower(err.Error()), "duplicate")) {
		return passwordreset.ErrExists
	}
	return err
}

func (s *Store) Consume(ctx context.Context, digest [32]byte) (passwordreset.Challenge, error) {
	var ch passwordreset.Challenge
	var dig []byte
	err := s.db.QueryRowContext(ctx, `
DELETE FROM amsl_password_reset WHERE token_digest = $1
RETURNING token_digest, account_id, expires_at, created_at`, digest[:]).Scan(
		&dig, &ch.AccountID, &ch.ExpiresAt, &ch.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return passwordreset.Challenge{}, passwordreset.ErrNotFound
	}
	if err != nil {
		return passwordreset.Challenge{}, err
	}
	copy(ch.TokenDigest[:], dig)
	return ch, nil
}

func (s *Store) InvalidateAccount(ctx context.Context, accountID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM amsl_password_reset WHERE account_id = $1`, accountID)
	return err
}

var _ passwordreset.Store = (*Store)(nil)
