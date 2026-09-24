// Package sqlstore persists accounts via database/sql against PostgreSQL-compatible
// servers (PostgreSQL, SereneDB, and others that speak the same dialect).
package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/ajent-social/go/accounts"
)

// Schema is applied idempotently by Open.
const Schema = `
CREATE TABLE IF NOT EXISTS amsl_accounts (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL DEFAULT '',
  display_name TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS amsl_accounts_email_uidx
  ON amsl_accounts (email) WHERE email <> '';
`

// Store is a multi-host accounts.Store.
type Store struct{ db *sql.DB }

// Open pings db and applies Schema.
func Open(ctx context.Context, db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, accounts.ErrInvalid
	}
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping accounts database: %w", err)
	}
	if _, err := db.ExecContext(ctx, Schema); err != nil {
		return nil, fmt.Errorf("apply accounts schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Create(ctx context.Context, a accounts.Account) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO amsl_accounts (id, email, display_name, status, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6)`,
		a.ID, a.Email, a.DisplayName, string(a.Status), a.CreatedAt.UTC(), a.UpdatedAt.UTC())
	if isUnique(err) {
		return accounts.ErrExists
	}
	return err
}

func (s *Store) Lookup(ctx context.Context, id string) (accounts.Account, error) {
	return scanAccount(s.db.QueryRowContext(ctx, `
SELECT id, email, display_name, status, created_at, updated_at FROM amsl_accounts WHERE id = $1`, id))
}

func (s *Store) LookupByEmail(ctx context.Context, email string) (accounts.Account, error) {
	return scanAccount(s.db.QueryRowContext(ctx, `
SELECT id, email, display_name, status, created_at, updated_at FROM amsl_accounts WHERE email = $1`, email))
}

func (s *Store) Update(ctx context.Context, a accounts.Account) error {
	res, err := s.db.ExecContext(ctx, `
UPDATE amsl_accounts SET email = $2, display_name = $3, status = $4, updated_at = $5 WHERE id = $1`,
		a.ID, a.Email, a.DisplayName, string(a.Status), a.UpdatedAt.UTC())
	if err != nil {
		if isUnique(err) {
			return accounts.ErrExists
		}
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return accounts.ErrNotFound
	}
	return nil
}

func scanAccount(row *sql.Row) (accounts.Account, error) {
	var a accounts.Account
	var status string
	err := row.Scan(&a.ID, &a.Email, &a.DisplayName, &status, &a.CreatedAt, &a.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return accounts.Account{}, accounts.ErrNotFound
	}
	if err != nil {
		return accounts.Account{}, err
	}
	a.Status = accounts.Status(status)
	a.CreatedAt, a.UpdatedAt = a.CreatedAt.UTC(), a.UpdatedAt.UTC()
	return a, nil
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

var _ accounts.Store = (*Store)(nil)
