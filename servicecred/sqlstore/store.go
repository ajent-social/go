// Package sqlstore persists service credentials via database/sql against
// PostgreSQL-compatible servers (PostgreSQL, SereneDB, and others that speak
// the same SQL dialect and wire protocol).
//
// Swap backends by changing the driver registration and DSN used to open
// *sql.DB; this package does not embed a vendor client. Connection pooling,
// TLS and migration ownership remain with the application.
package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ajent-social/go/servicecred"
)

// Schema is the DDL applied by Open. Applications may apply it out-of-band
// instead; Open is idempotent (IF NOT EXISTS).
//
// Types stay within the common PostgreSQL-compatible subset so a DSN swap to
// SereneDB (or another compatible server) does not require package changes.
const Schema = `
CREATE TABLE IF NOT EXISTS amsl_service_credentials (
  id TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  resource TEXT NOT NULL,
  scopes TEXT NOT NULL,
  digest BYTEA NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  CONSTRAINT amsl_service_credentials_digest_len CHECK (octet_length(digest) = 32),
  CONSTRAINT amsl_service_credentials_id_len CHECK (char_length(id) = 32)
);
CREATE INDEX IF NOT EXISTS amsl_service_credentials_binding_idx
  ON amsl_service_credentials (owner, resource);
`

// Store is a SQL adapter. Concurrent callers share the provided *sql.DB.
type Store struct {
	db *sql.DB
}

// Open verifies connectivity, applies Schema, and returns a Store.
// db must already be opened against a PostgreSQL-compatible server
// (for example lib/pq, pgx/stdlib, or a SereneDB driver).
func Open(ctx context.Context, db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, servicecred.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping credential database: %w", err)
	}
	if _, err := db.ExecContext(ctx, Schema); err != nil {
		return nil, fmt.Errorf("apply credential schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Create(ctx context.Context, r servicecred.Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.ID == "" || len(r.Digest) != 32 {
		return servicecred.ErrInvalid
	}
	scopes, err := json.Marshal(r.Scopes)
	if err != nil {
		return fmt.Errorf("encode scopes: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO amsl_service_credentials
  (id, owner, resource, scopes, digest, created_at, expires_at, revoked_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, NULL)`,
		r.ID, r.Owner, r.Resource, string(scopes), r.Digest[:],
		r.CreatedAt.UTC(), r.ExpiresAt.UTC())
	if err != nil {
		if isUniqueViolation(err) {
			return servicecred.ErrExists
		}
		return fmt.Errorf("persist credential: %w", err)
	}
	return nil
}

func (s *Store) Lookup(ctx context.Context, id string) (servicecred.Record, error) {
	if err := ctx.Err(); err != nil {
		return servicecred.Record{}, err
	}
	var r servicecred.Record
	var digest []byte
	var scopes string
	var revoked sql.NullTime
	err := s.db.QueryRowContext(ctx, `
SELECT id, owner, resource, scopes, digest, created_at, expires_at, revoked_at
FROM amsl_service_credentials WHERE id = $1`, id).Scan(
		&r.ID, &r.Owner, &r.Resource, &scopes, &digest,
		&r.CreatedAt, &r.ExpiresAt, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return servicecred.Record{}, servicecred.ErrNotFound
	}
	if err != nil {
		return servicecred.Record{}, fmt.Errorf("lookup credential: %w", err)
	}
	if r.ID != id || len(digest) != 32 {
		return servicecred.Record{}, fmt.Errorf("credential record corrupt")
	}
	if err := json.Unmarshal([]byte(scopes), &r.Scopes); err != nil {
		return servicecred.Record{}, fmt.Errorf("decode scopes: %w", err)
	}
	copy(r.Digest[:], digest)
	if revoked.Valid {
		r.RevokedAt = revoked.Time.UTC()
	}
	r.CreatedAt = r.CreatedAt.UTC()
	r.ExpiresAt = r.ExpiresAt.UTC()
	return r, nil
}

func (s *Store) Revoke(ctx context.Context, id, owner, resource string, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if at.IsZero() {
		return servicecred.ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin revoke: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var storedOwner, storedResource string
	var revoked sql.NullTime
	err = tx.QueryRowContext(ctx, `
SELECT owner, resource, revoked_at FROM amsl_service_credentials
WHERE id = $1 FOR UPDATE`, id).Scan(&storedOwner, &storedResource, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return servicecred.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("lock credential for revoke: %w", err)
	}
	if storedOwner != owner || storedResource != resource {
		return servicecred.ErrNotFound
	}
	if revoked.Valid {
		return tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE amsl_service_credentials SET revoked_at = $2 WHERE id = $1`, id, at.UTC()); err != nil {
		return fmt.Errorf("write revocation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit revocation: %w", err)
	}
	return nil
}

// List returns metadata for an exact authorized owner/resource, including revoked
// records. The caller must authorize this administrative access before calling.
func (s *Store) List(ctx context.Context, owner, resource string) ([]servicecred.Metadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if owner == "" || resource == "" {
		return nil, servicecred.ErrInvalid
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, owner, resource, scopes, created_at, expires_at, revoked_at
FROM amsl_service_credentials
WHERE owner = $1 AND resource = $2
ORDER BY created_at ASC, id ASC`, owner, resource)
	if err != nil {
		return nil, fmt.Errorf("list credentials: %w", err)
	}
	defer rows.Close()

	out := []servicecred.Metadata{}
	for rows.Next() {
		var m servicecred.Metadata
		var scopes string
		var revoked sql.NullTime
		if err := rows.Scan(&m.ID, &m.Owner, &m.Resource, &scopes,
			&m.CreatedAt, &m.ExpiresAt, &revoked); err != nil {
			return nil, fmt.Errorf("decode credential metadata: %w", err)
		}
		if err := json.Unmarshal([]byte(scopes), &m.Scopes); err != nil {
			return nil, fmt.Errorf("decode scopes: %w", err)
		}
		m.CreatedAt = m.CreatedAt.UTC()
		m.ExpiresAt = m.ExpiresAt.UTC()
		if revoked.Valid {
			m.RevokedAt = revoked.Time.UTC()
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate credential metadata: %w", err)
	}
	return out, nil
}

// sqlStater is implemented by several PostgreSQL drivers (for example pgx).
type sqlStater interface {
	SQLState() string
}

func isUniqueViolation(err error) bool {
	var st sqlStater
	if errors.As(err, &st) && st.SQLState() == "23505" {
		return true
	}
	// Drivers without SQLState() (lib/pq) still expose SQLSTATE in the message.
	msg := err.Error()
	return strings.Contains(msg, "23505") || strings.Contains(msg, "unique constraint") || strings.Contains(msg, "duplicate key")
}
