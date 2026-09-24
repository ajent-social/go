// Package sqlstore persists subscription event inbox and projections in
// PostgreSQL-compatible SQL (PostgreSQL, SereneDB, and similar).
package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/ajent-social/go/billing/subscription"
)

// Schema is applied idempotently by Open.
const Schema = `
CREATE TABLE IF NOT EXISTS amsl_billing_subscription_events (
  livemode BOOLEAN NOT NULL,
  event_id TEXT NOT NULL,
  type TEXT NOT NULL,
  customer_ref TEXT NOT NULL DEFAULT '',
  subscription_ref TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT '',
  period_end TIMESTAMPTZ,
  payload_hash TEXT NOT NULL,
  received_at TIMESTAMPTZ NOT NULL,
  unmatched BOOLEAN NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (livemode, event_id)
);
CREATE TABLE IF NOT EXISTS amsl_billing_subscription_projections (
  customer_ref TEXT PRIMARY KEY,
  subscription_ref TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT '',
  period_end TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL,
  event_id TEXT NOT NULL DEFAULT '',
  lease_epoch BIGINT NOT NULL
);
`

// Store is a multi-host subscription.Store.
type Store struct{ db *sql.DB }

// Open pings db and applies Schema.
func Open(ctx context.Context, db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, subscription.ErrInvalid
	}
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping subscription database: %w", err)
	}
	if _, err := db.ExecContext(ctx, Schema); err != nil {
		return nil, fmt.Errorf("apply subscription schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) LookupEvent(ctx context.Context, livemode subscription.Livemode, id subscription.EventID) (subscription.EventRecord, error) {
	var rec subscription.EventRecord
	var periodEnd sql.NullTime
	err := s.db.QueryRowContext(ctx, `
SELECT livemode, event_id, type, customer_ref, subscription_ref, status, period_end,
       payload_hash, received_at, unmatched, created_at
FROM amsl_billing_subscription_events WHERE livemode = $1 AND event_id = $2`, bool(livemode), string(id)).Scan(
		&rec.Event.Livemode, &rec.Event.ID, &rec.Event.Type, &rec.Event.CustomerRef,
		&rec.Event.SubscriptionRef, &rec.Event.Status, &periodEnd, &rec.Event.PayloadHash,
		&rec.Event.ReceivedAt, &rec.Unmatched, &rec.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return subscription.EventRecord{}, subscription.ErrNotFound
	}
	if err != nil {
		return subscription.EventRecord{}, err
	}
	if periodEnd.Valid {
		rec.Event.PeriodEnd = periodEnd.Time.UTC()
	}
	rec.Event.ReceivedAt = rec.Event.ReceivedAt.UTC()
	rec.CreatedAt = rec.CreatedAt.UTC()
	return rec, nil
}

func (s *Store) LookupProjection(ctx context.Context, customer subscription.CustomerRef) (subscription.ProjectionRecord, error) {
	var rec subscription.ProjectionRecord
	var periodEnd sql.NullTime
	err := s.db.QueryRowContext(ctx, `
SELECT customer_ref, subscription_ref, status, period_end, updated_at, event_id, lease_epoch
FROM amsl_billing_subscription_projections WHERE customer_ref = $1`, string(customer)).Scan(
		&rec.Projection.CustomerRef, &rec.Projection.SubscriptionRef, &rec.Projection.Status,
		&periodEnd, &rec.Projection.UpdatedAt, &rec.Projection.EventID, &rec.LeaseEpoch)
	if errors.Is(err, sql.ErrNoRows) {
		return subscription.ProjectionRecord{}, subscription.ErrNotFound
	}
	if err != nil {
		return subscription.ProjectionRecord{}, err
	}
	if periodEnd.Valid {
		rec.Projection.PeriodEnd = periodEnd.Time.UTC()
	}
	rec.Projection.UpdatedAt = rec.Projection.UpdatedAt.UTC()
	return rec, nil
}

func (s *Store) InsertEvent(ctx context.Context, rec subscription.EventRecord) error {
	var period any
	if !rec.Event.PeriodEnd.IsZero() {
		period = rec.Event.PeriodEnd.UTC()
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO amsl_billing_subscription_events
 (livemode, event_id, type, customer_ref, subscription_ref, status, period_end,
  payload_hash, received_at, unmatched, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		bool(rec.Event.Livemode), string(rec.Event.ID), rec.Event.Type,
		string(rec.Event.CustomerRef), string(rec.Event.SubscriptionRef), rec.Event.Status,
		period, rec.Event.PayloadHash, rec.Event.ReceivedAt.UTC(), rec.Unmatched, rec.CreatedAt.UTC())
	if err != nil {
		if isUnique(err) {
			return subscription.ErrExists
		}
		return err
	}
	return nil
}

func (s *Store) ApplyProjection(ctx context.Context, in subscription.ApplyProjectionInput) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var epoch uint64
	err = tx.QueryRowContext(ctx, `
SELECT lease_epoch FROM amsl_billing_subscription_projections
WHERE customer_ref = $1 FOR UPDATE`, string(in.Customer)).Scan(&epoch)
	if errors.Is(err, sql.ErrNoRows) {
		if in.ExpectedEpoch != 0 {
			return subscription.ErrStale
		}
		var period any
		if !in.Projection.PeriodEnd.IsZero() {
			period = in.Projection.PeriodEnd.UTC()
		}
		_, err = tx.ExecContext(ctx, `
INSERT INTO amsl_billing_subscription_projections
 (customer_ref, subscription_ref, status, period_end, updated_at, event_id, lease_epoch)
VALUES ($1,$2,$3,$4,$5,$6,1)`,
			string(in.Customer), string(in.Projection.SubscriptionRef), in.Projection.Status,
			period, in.Now.UTC(), string(in.Projection.EventID))
		if err != nil {
			if isUnique(err) {
				return subscription.ErrStale
			}
			return err
		}
		return tx.Commit()
	}
	if err != nil {
		return err
	}
	if epoch != in.ExpectedEpoch {
		return subscription.ErrStale
	}
	var period any
	if !in.Projection.PeriodEnd.IsZero() {
		period = in.Projection.PeriodEnd.UTC()
	}
	_, err = tx.ExecContext(ctx, `
UPDATE amsl_billing_subscription_projections SET
  subscription_ref = $2, status = $3, period_end = $4, updated_at = $5,
  event_id = $6, lease_epoch = lease_epoch + 1
WHERE customer_ref = $1 AND lease_epoch = $7`,
		string(in.Customer), string(in.Projection.SubscriptionRef), in.Projection.Status,
		period, in.Now.UTC(), string(in.Projection.EventID), in.ExpectedEpoch)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func isUnique(err error) bool {
	type stater interface{ SQLState() string }
	var st stater
	if errors.As(err, &st) && st.SQLState() == "23505" {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "23505") || strings.Contains(msg, "unique constraint") || strings.Contains(msg, "duplicate key")
}

var _ subscription.Store = (*Store)(nil)
