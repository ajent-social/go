// Package sqlstore persists publishable keys via database/sql.
package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ajent-social/go/publishablekey"
)

const Schema = `
CREATE TABLE IF NOT EXISTS amsl_publishable_keys (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  prefix TEXT NOT NULL,
  digest BYTEA NOT NULL UNIQUE,
  allowed_origins TEXT NOT NULL,
  scopes TEXT NOT NULL,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  CONSTRAINT amsl_publishable_keys_digest_len CHECK (octet_length(digest) = 32)
);
`

// Store is a SQL adapter.
type Store struct{ db *sql.DB }

// Open applies Schema.
func Open(ctx context.Context, db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, publishablekey.ErrInvalid
	}
	if err := db.PingContext(ctx); err != nil {
		return nil, err
	}
	if _, err := db.ExecContext(ctx, Schema); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Create(ctx context.Context, k publishablekey.Key) error {
	origins, _ := json.Marshal(k.AllowedOrigins)
	scopes, _ := json.Marshal(k.Scopes)
	var exp any
	if !k.ExpiresAt.IsZero() {
		exp = k.ExpiresAt.UTC()
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO amsl_publishable_keys
 (id, owner_id, prefix, digest, allowed_origins, scopes, expires_at, created_at, revoked_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NULL)`,
		k.ID, k.OwnerID, k.Prefix, k.Digest[:], string(origins), string(scopes), exp, k.CreatedAt.UTC())
	if err != nil && (strings.Contains(strings.ToLower(err.Error()), "unique") || strings.Contains(strings.ToLower(err.Error()), "duplicate")) {
		return publishablekey.ErrExists
	}
	return err
}

func (s *Store) Lookup(ctx context.Context, id string) (publishablekey.Key, error) {
	return s.scan(ctx, `SELECT id, owner_id, prefix, digest, allowed_origins, scopes, expires_at, created_at, revoked_at
FROM amsl_publishable_keys WHERE id = $1`, id)
}

func (s *Store) LookupByDigest(ctx context.Context, d [32]byte) (publishablekey.Key, error) {
	return s.scan(ctx, `SELECT id, owner_id, prefix, digest, allowed_origins, scopes, expires_at, created_at, revoked_at
FROM amsl_publishable_keys WHERE digest = $1`, d[:])
}

func (s *Store) scan(ctx context.Context, q string, arg any) (publishablekey.Key, error) {
	var k publishablekey.Key
	var dig, origins, scopes []byte
	var exp, rev sql.NullTime
	err := s.db.QueryRowContext(ctx, q, arg).Scan(
		&k.ID, &k.OwnerID, &k.Prefix, &dig, &origins, &scopes, &exp, &k.CreatedAt, &rev)
	if errors.Is(err, sql.ErrNoRows) {
		return publishablekey.Key{}, publishablekey.ErrNotFound
	}
	if err != nil {
		return publishablekey.Key{}, err
	}
	if len(dig) != 32 {
		return publishablekey.Key{}, fmt.Errorf("corrupt digest")
	}
	copy(k.Digest[:], dig)
	_ = json.Unmarshal(origins, &k.AllowedOrigins)
	_ = json.Unmarshal(scopes, &k.Scopes)
	if exp.Valid {
		k.ExpiresAt = exp.Time
	}
	if rev.Valid {
		k.RevokedAt = rev.Time
	}
	return k, nil
}

func (s *Store) Revoke(ctx context.Context, id, ownerID string, at time.Time) error {
	res, err := s.db.ExecContext(ctx, `
UPDATE amsl_publishable_keys SET revoked_at = $1
WHERE id = $2 AND owner_id = $3 AND revoked_at IS NULL`, at.UTC(), id, ownerID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return publishablekey.ErrNotFound
	}
	return nil
}

var _ publishablekey.Store = (*Store)(nil)
