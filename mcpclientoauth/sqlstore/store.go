// Package sqlstore persists mcpclientoauth state via database/sql.
package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/ajent-social/go/mcpclientoauth"
)

const Schema = `
CREATE TABLE IF NOT EXISTS amsl_mcp_client_pending (
  state_digest BYTEA PRIMARY KEY,
  server_id TEXT NOT NULL,
  owner_id TEXT NOT NULL,
  verifier TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  CONSTRAINT amsl_mcp_client_pending_digest_len CHECK (octet_length(state_digest) = 32)
);
CREATE TABLE IF NOT EXISTS amsl_mcp_client_tokens (
  owner_id TEXT NOT NULL,
  server_id TEXT NOT NULL,
  ciphertext BYTEA NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (owner_id, server_id)
);
`

// Store is a SQL adapter.
type Store struct{ db *sql.DB }

// Open applies Schema and returns a Store.
func Open(ctx context.Context, db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, mcpclientoauth.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping: %w", err)
	}
	if _, err := db.ExecContext(ctx, Schema); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) PutPending(ctx context.Context, p mcpclientoauth.Pending) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO amsl_mcp_client_pending
  (state_digest, server_id, owner_id, verifier, expires_at, created_at)
VALUES ($1,$2,$3,$4,$5,$6)`,
		p.StateDigest[:], p.ServerID, p.OwnerID, p.Verifier,
		p.ExpiresAt.UTC(), p.CreatedAt.UTC())
	if err != nil {
		if isUnique(err) {
			return mcpclientoauth.ErrExists
		}
		return err
	}
	return nil
}

func (s *Store) TakePending(ctx context.Context, digest [32]byte) (mcpclientoauth.Pending, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return mcpclientoauth.Pending{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var p mcpclientoauth.Pending
	var dig []byte
	err = tx.QueryRowContext(ctx, `
DELETE FROM amsl_mcp_client_pending WHERE state_digest = $1
RETURNING state_digest, server_id, owner_id, verifier, expires_at, created_at`, digest[:]).Scan(
		&dig, &p.ServerID, &p.OwnerID, &p.Verifier, &p.ExpiresAt, &p.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return mcpclientoauth.Pending{}, mcpclientoauth.ErrNotFound
	}
	if err != nil {
		return mcpclientoauth.Pending{}, err
	}
	copy(p.StateDigest[:], dig)
	if err := tx.Commit(); err != nil {
		return mcpclientoauth.Pending{}, err
	}
	return p, nil
}

func (s *Store) PutToken(ctx context.Context, t mcpclientoauth.TokenRecord) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO amsl_mcp_client_tokens (owner_id, server_id, ciphertext, expires_at, updated_at)
VALUES ($1,$2,$3,$4,$5)
ON CONFLICT (owner_id, server_id) DO UPDATE SET
  ciphertext = EXCLUDED.ciphertext,
  expires_at = EXCLUDED.expires_at,
  updated_at = EXCLUDED.updated_at`,
		t.OwnerID, t.ServerID, t.Ciphertext, t.ExpiresAt.UTC(), t.UpdatedAt.UTC())
	return err
}

func (s *Store) LookupToken(ctx context.Context, ownerID, serverID string) (mcpclientoauth.TokenRecord, error) {
	var t mcpclientoauth.TokenRecord
	err := s.db.QueryRowContext(ctx, `
SELECT owner_id, server_id, ciphertext, expires_at, updated_at
FROM amsl_mcp_client_tokens WHERE owner_id = $1 AND server_id = $2`,
		ownerID, serverID).Scan(&t.OwnerID, &t.ServerID, &t.Ciphertext, &t.ExpiresAt, &t.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return mcpclientoauth.TokenRecord{}, mcpclientoauth.ErrNotFound
	}
	return t, err
}

func (s *Store) DeleteToken(ctx context.Context, ownerID, serverID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM amsl_mcp_client_tokens WHERE owner_id = $1 AND server_id = $2`,
		ownerID, serverID)
	return err
}

func isUnique(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique") || strings.Contains(msg, "duplicate")
}

var _ mcpclientoauth.Store = (*Store)(nil)
