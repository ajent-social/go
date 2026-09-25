// Package sqlstore persists tenant instances via database/sql against
// PostgreSQL-compatible servers.
package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/ajent-social/go/tenant"
)

// Schema is applied idempotently by Open.
const Schema = `
CREATE TABLE IF NOT EXISTS amsl_tenant_instances (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  slug TEXT NOT NULL,
  image_digest TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL,
  hostname TEXT NOT NULL,
  lease_epoch BIGINT NOT NULL,
  last_error TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS amsl_tenant_slug_uidx ON amsl_tenant_instances (slug);
CREATE UNIQUE INDEX IF NOT EXISTS amsl_tenant_account_active_uidx
  ON amsl_tenant_instances (account_id) WHERE status <> 'destroyed';
`

// Store is a multi-host tenant.Store.
type Store struct{ db *sql.DB }

// Open pings db and applies Schema.
func Open(ctx context.Context, db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, tenant.ErrInvalid
	}
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping tenant database: %w", err)
	}
	if _, err := db.ExecContext(ctx, Schema); err != nil {
		return nil, fmt.Errorf("apply tenant schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Create(ctx context.Context, in tenant.Instance) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO amsl_tenant_instances
 (id, account_id, slug, image_digest, status, hostname, lease_epoch, last_error, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		in.ID, in.AccountID, in.Slug, in.ImageDigest, string(in.Status), in.Hostname,
		int64(in.LeaseEpoch), in.LastError, in.CreatedAt.UTC(), in.UpdatedAt.UTC())
	if isUnique(err) {
		return tenant.ErrExists
	}
	return err
}

func (s *Store) Lookup(ctx context.Context, id string) (tenant.Instance, error) {
	return scan(s.db.QueryRowContext(ctx, `
SELECT id, account_id, slug, image_digest, status, hostname, lease_epoch, last_error, created_at, updated_at
FROM amsl_tenant_instances WHERE id = $1`, id))
}

func (s *Store) LookupBySlug(ctx context.Context, slug string) (tenant.Instance, error) {
	return scan(s.db.QueryRowContext(ctx, `
SELECT id, account_id, slug, image_digest, status, hostname, lease_epoch, last_error, created_at, updated_at
FROM amsl_tenant_instances WHERE slug = $1`, slug))
}

func (s *Store) LookupByAccount(ctx context.Context, accountID string) (tenant.Instance, error) {
	return scan(s.db.QueryRowContext(ctx, `
SELECT id, account_id, slug, image_digest, status, hostname, lease_epoch, last_error, created_at, updated_at
FROM amsl_tenant_instances WHERE account_id = $1
ORDER BY CASE WHEN status = 'destroyed' THEN 1 ELSE 0 END, updated_at DESC
LIMIT 1`, accountID))
}

func (s *Store) Apply(ctx context.Context, id string, expectedEpoch uint64, next tenant.Instance) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var curEpoch int64
	err = tx.QueryRowContext(ctx, `
SELECT lease_epoch FROM amsl_tenant_instances WHERE id = $1 FOR UPDATE`, id).Scan(&curEpoch)
	if errors.Is(err, sql.ErrNoRows) {
		return tenant.ErrNotFound
	}
	if err != nil {
		return err
	}
	if uint64(curEpoch) != expectedEpoch {
		return tenant.ErrConflict
	}
	next.LeaseEpoch = expectedEpoch + 1
	_, err = tx.ExecContext(ctx, `
UPDATE amsl_tenant_instances SET
 account_id=$2, slug=$3, image_digest=$4, status=$5, hostname=$6,
 lease_epoch=$7, last_error=$8, updated_at=$9
WHERE id=$1`,
		id, next.AccountID, next.Slug, next.ImageDigest, string(next.Status), next.Hostname,
		int64(next.LeaseEpoch), next.LastError, next.UpdatedAt.UTC())
	if isUnique(err) {
		return tenant.ErrExists
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

func scan(row *sql.Row) (tenant.Instance, error) {
	var in tenant.Instance
	var status string
	var epoch int64
	err := row.Scan(&in.ID, &in.AccountID, &in.Slug, &in.ImageDigest, &status, &in.Hostname,
		&epoch, &in.LastError, &in.CreatedAt, &in.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return tenant.Instance{}, tenant.ErrNotFound
	}
	if err != nil {
		return tenant.Instance{}, err
	}
	in.Status = tenant.Status(status)
	in.LeaseEpoch = uint64(epoch)
	in.CreatedAt, in.UpdatedAt = in.CreatedAt.UTC(), in.UpdatedAt.UTC()
	return in, nil
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

var _ tenant.Store = (*Store)(nil)
