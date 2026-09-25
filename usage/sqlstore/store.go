// Package sqlstore persists usage counters via database/sql.
package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/ajent-social/go/usage"
)

// Schema is applied idempotently by Open.
const Schema = `
CREATE TABLE IF NOT EXISTS amsl_usage_counters (
  owner TEXT NOT NULL,
  meter TEXT NOT NULL,
  period TEXT NOT NULL,
  used BIGINT NOT NULL,
  epoch BIGINT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (owner, meter, period)
);
`

// Store is a multi-host usage.Store.
type Store struct{ db *sql.DB }

// Open pings db and applies Schema.
func Open(ctx context.Context, db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, usage.ErrInvalid
	}
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping usage database: %w", err)
	}
	if _, err := db.ExecContext(ctx, Schema); err != nil {
		return nil, fmt.Errorf("apply usage schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Lookup(ctx context.Context, k usage.Key) (usage.Counter, error) {
	var c usage.Counter
	var epoch int64
	err := s.db.QueryRowContext(ctx, `
SELECT owner, meter, period, used, epoch, updated_at FROM amsl_usage_counters
WHERE owner=$1 AND meter=$2 AND period=$3`, k.Owner, k.Meter, k.Period).Scan(
		&c.Owner, &c.Meter, &c.Period, &c.Used, &epoch, &c.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return usage.Counter{}, usage.ErrNotFound
	}
	if err != nil {
		return usage.Counter{}, err
	}
	c.Epoch = uint64(epoch)
	c.UpdatedAt = c.UpdatedAt.UTC()
	return c, nil
}

func (s *Store) Apply(ctx context.Context, expectedEpoch uint64, next usage.Counter) error {
	if expectedEpoch == 0 {
		_, err := s.db.ExecContext(ctx, `
INSERT INTO amsl_usage_counters (owner, meter, period, used, epoch, updated_at)
VALUES ($1,$2,$3,$4,1,$5)`,
			next.Owner, next.Meter, next.Period, next.Used, next.UpdatedAt.UTC())
		if isUnique(err) {
			return usage.ErrConflict
		}
		return err
	}
	res, err := s.db.ExecContext(ctx, `
UPDATE amsl_usage_counters SET used=$4, epoch=$5, updated_at=$6
WHERE owner=$1 AND meter=$2 AND period=$3 AND epoch=$7`,
		next.Owner, next.Meter, next.Period, next.Used, int64(expectedEpoch+1), next.UpdatedAt.UTC(), int64(expectedEpoch))
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return usage.ErrConflict
	}
	return nil
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

var _ usage.Store = (*Store)(nil)
