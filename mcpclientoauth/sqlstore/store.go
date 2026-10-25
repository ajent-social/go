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
CREATE TABLE IF NOT EXISTS amsl_mcp_client_pending_v2 (
  state_digest BYTEA PRIMARY KEY,
  server_id TEXT NOT NULL,
  owner_id TEXT NOT NULL,
  verifier TEXT NOT NULL,
  generation TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  CONSTRAINT amsl_mcp_client_pending_v2_digest_len CHECK (octet_length(state_digest) = 32)
);
CREATE TABLE IF NOT EXISTS amsl_mcp_client_tokens_v2 (
  owner_id TEXT NOT NULL,
  server_id TEXT NOT NULL,
  generation TEXT NOT NULL,
  version BIGINT NOT NULL DEFAULT 0 CHECK (version >= 0),
  state TEXT NOT NULL CHECK (state IN ('empty', 'ready', 'claimed', 'disconnected')),
  ciphertext BYTEA NOT NULL DEFAULT ''::bytea,
  expires_at TIMESTAMPTZ NOT NULL DEFAULT 'epoch',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT 'epoch',
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
INSERT INTO amsl_mcp_client_pending_v2
  (state_digest, server_id, owner_id, verifier, expires_at, created_at, generation)
VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		p.StateDigest[:], p.ServerID, p.OwnerID, p.Verifier,
		p.ExpiresAt.UTC(), p.CreatedAt.UTC(), p.Generation)
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
DELETE FROM amsl_mcp_client_pending_v2 WHERE state_digest = $1
RETURNING state_digest, server_id, owner_id, verifier, expires_at, created_at, generation`, digest[:]).Scan(
		&dig, &p.ServerID, &p.OwnerID, &p.Verifier, &p.ExpiresAt, &p.CreatedAt, &p.Generation)
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

// PutToken is retained for source compatibility; v1 unconditional writes fail closed.
func (s *Store) PutToken(context.Context, mcpclientoauth.TokenRecord) error {
	return mcpclientoauth.ErrUnsupportedStore
}

func (s *Store) BeginConnection(ctx context.Context, owner, server, generation string) error {
	if owner == "" || server == "" || generation == "" {
		return mcpclientoauth.ErrInvalid
	}
	result, err := s.db.ExecContext(ctx, `
INSERT INTO amsl_mcp_client_tokens_v2 (owner_id, server_id, generation, state)
VALUES ($1,$2,$3,'empty')
ON CONFLICT (owner_id,server_id) DO UPDATE SET generation=EXCLUDED.generation,
 version=0, state='empty', ciphertext=''::bytea, expires_at='epoch', updated_at='epoch'
WHERE amsl_mcp_client_tokens_v2.generation <> EXCLUDED.generation`, owner, server, generation)
	return changed(result, err)
}

func (s *Store) LookupToken(ctx context.Context, owner, server string) (mcpclientoauth.TokenRecord, error) {
	var t mcpclientoauth.TokenRecord
	var state string
	err := s.db.QueryRowContext(ctx, `SELECT owner_id,server_id,generation,version,state,ciphertext,expires_at,updated_at
 FROM amsl_mcp_client_tokens_v2 WHERE owner_id=$1 AND server_id=$2`, owner, server).Scan(
		&t.OwnerID, &t.ServerID, &t.Generation, &t.Version, &state, &t.Ciphertext, &t.ExpiresAt, &t.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return t, mcpclientoauth.ErrNotFound
	}
	if err != nil {
		return t, err
	}
	if state == "claimed" {
		return mcpclientoauth.TokenRecord{}, mcpclientoauth.ErrRefreshUncertain
	}
	if state != "ready" {
		return mcpclientoauth.TokenRecord{}, mcpclientoauth.ErrNotFound
	}
	return t, nil
}

func (s *Store) ClaimRefresh(ctx context.Context, t mcpclientoauth.TokenRecord) (mcpclientoauth.TokenRecord, error) {
	var claimed mcpclientoauth.TokenRecord
	err := s.db.QueryRowContext(ctx, `UPDATE amsl_mcp_client_tokens_v2 SET state='claimed',version=version+1
 WHERE owner_id=$1 AND server_id=$2 AND generation=$3 AND version=$4 AND state='ready'
 RETURNING owner_id,server_id,generation,version,ciphertext,expires_at,updated_at`,
		t.OwnerID, t.ServerID, t.Generation, t.Version).Scan(&claimed.OwnerID, &claimed.ServerID, &claimed.Generation,
		&claimed.Version, &claimed.Ciphertext, &claimed.ExpiresAt, &claimed.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return claimed, mcpclientoauth.ErrConflict
	}
	return claimed, err
}

func (s *Store) CompleteToken(ctx context.Context, t mcpclientoauth.TokenRecord) error {
	if t.Generation == "" {
		return mcpclientoauth.ErrConflict
	}
	result, err := s.db.ExecContext(ctx, `UPDATE amsl_mcp_client_tokens_v2
 SET ciphertext=$5,expires_at=$6,updated_at=$7,state='ready',version=version+1
 WHERE owner_id=$1 AND server_id=$2 AND generation=$3 AND version=$4 AND state IN ('empty','claimed')`,
		t.OwnerID, t.ServerID, t.Generation, t.Version, t.Ciphertext, t.ExpiresAt.UTC(), t.UpdatedAt.UTC())
	return changed(result, err)
}

// Disconnect serializes with BeginConnection, claims and completions using the
// database row lock. The tombstone is committed before the provider is contacted.
func (s *Store) Disconnect(ctx context.Context, owner, server string) (mcpclientoauth.TokenRecord, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return mcpclientoauth.TokenRecord{}, err
	}
	defer func() { _ = tx.Rollback() }()
	_, err = tx.ExecContext(ctx, `INSERT INTO amsl_mcp_client_tokens_v2 (owner_id,server_id,generation,state)
 VALUES ($1,$2,'','disconnected') ON CONFLICT (owner_id,server_id) DO NOTHING`, owner, server)
	if err != nil {
		return mcpclientoauth.TokenRecord{}, err
	}
	var t mcpclientoauth.TokenRecord
	err = tx.QueryRowContext(ctx, `SELECT owner_id,server_id,generation,version,ciphertext,expires_at,updated_at
 FROM amsl_mcp_client_tokens_v2 WHERE owner_id=$1 AND server_id=$2 FOR UPDATE`, owner, server).Scan(
		&t.OwnerID, &t.ServerID, &t.Generation, &t.Version, &t.Ciphertext, &t.ExpiresAt, &t.UpdatedAt)
	if err != nil {
		return mcpclientoauth.TokenRecord{}, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE amsl_mcp_client_tokens_v2 SET state='disconnected',version=version+1,
 ciphertext=''::bytea WHERE owner_id=$1 AND server_id=$2`, owner, server)
	if err != nil {
		return mcpclientoauth.TokenRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return mcpclientoauth.TokenRecord{}, err
	}
	return t, nil
}
func (s *Store) DeleteToken(ctx context.Context, owner, server string) error {
	_, err := s.Disconnect(ctx, owner, server)
	return err
}
func changed(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return mcpclientoauth.ErrConflict
	}
	return nil
}

func isUnique(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique") || strings.Contains(msg, "duplicate")
}

var _ mcpclientoauth.LifecycleStore = (*Store)(nil)
