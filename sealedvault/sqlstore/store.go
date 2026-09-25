// Package sqlstore persists sealed vault records via database/sql.
package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ajent-social/go/sealedvault"
)

// Schema is applied idempotently by Open.
const Schema = `
CREATE TABLE IF NOT EXISTS amsl_sealed_vault (
  owner TEXT NOT NULL,
  name TEXT NOT NULL,
  ciphertext BYTEA NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (owner, name),
  CONSTRAINT amsl_sealed_vault_ct_nonempty CHECK (octet_length(ciphertext) > 0)
);
`

// Store is a multi-host sealedvault.Store.
type Store struct{ db *sql.DB }

// Open pings db and applies Schema.
func Open(ctx context.Context, db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, sealedvault.ErrInvalid
	}
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping sealedvault database: %w", err)
	}
	if _, err := db.ExecContext(ctx, Schema); err != nil {
		return nil, fmt.Errorf("apply sealedvault schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Put(ctx context.Context, r sealedvault.Record) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO amsl_sealed_vault (owner, name, ciphertext, updated_at)
VALUES ($1,$2,$3,$4)
ON CONFLICT (owner, name) DO UPDATE SET
 ciphertext = EXCLUDED.ciphertext, updated_at = EXCLUDED.updated_at`,
		r.Owner, r.Name, r.Ciphertext, r.UpdatedAt.UTC())
	return err
}

func (s *Store) Get(ctx context.Context, owner, name string) (sealedvault.Record, error) {
	var r sealedvault.Record
	err := s.db.QueryRowContext(ctx, `
SELECT owner, name, ciphertext, updated_at FROM amsl_sealed_vault
WHERE owner=$1 AND name=$2`, owner, name).Scan(&r.Owner, &r.Name, &r.Ciphertext, &r.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return sealedvault.Record{}, sealedvault.ErrNotFound
	}
	if err != nil {
		return sealedvault.Record{}, err
	}
	r.UpdatedAt = r.UpdatedAt.UTC()
	return r, nil
}

func (s *Store) Delete(ctx context.Context, owner, name string) error {
	res, err := s.db.ExecContext(ctx, `
DELETE FROM amsl_sealed_vault WHERE owner=$1 AND name=$2`, owner, name)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sealedvault.ErrNotFound
	}
	return nil
}

var _ sealedvault.Store = (*Store)(nil)
