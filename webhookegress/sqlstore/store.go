// Package sqlstore persists webhook endpoints and deliveries via database/sql.
package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	"github.com/ajent-social/go/webhookegress"
)

const Schema = `
CREATE TABLE IF NOT EXISTS amsl_webhook_endpoints (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  url TEXT NOT NULL,
  secret_digest BYTEA NOT NULL,
  events TEXT NOT NULL,
  active BOOLEAN NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  CONSTRAINT amsl_webhook_endpoints_digest_len CHECK (octet_length(secret_digest) = 32)
);
CREATE TABLE IF NOT EXISTS amsl_webhook_deliveries (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  endpoint_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  payload BYTEA NOT NULL,
  status TEXT NOT NULL,
  attempts INT NOT NULL,
  last_error TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL,
  delivered_at TIMESTAMPTZ
);
`

// Store is a SQL adapter.
type Store struct{ db *sql.DB }

// Open applies Schema.
func Open(ctx context.Context, db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, webhookegress.ErrInvalid
	}
	if err := db.PingContext(ctx); err != nil {
		return nil, err
	}
	if _, err := db.ExecContext(ctx, Schema); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) CreateEndpoint(ctx context.Context, ep webhookegress.Endpoint) error {
	events, _ := json.Marshal(ep.Events)
	_, err := s.db.ExecContext(ctx, `
INSERT INTO amsl_webhook_endpoints (id, owner_id, url, secret_digest, events, active, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		ep.ID, ep.OwnerID, ep.URL, ep.SecretDigest[:], string(events), ep.Active, ep.CreatedAt.UTC())
	if err != nil && (strings.Contains(strings.ToLower(err.Error()), "unique") || strings.Contains(strings.ToLower(err.Error()), "duplicate")) {
		return webhookegress.ErrExists
	}
	return err
}

func (s *Store) LookupEndpoint(ctx context.Context, id string) (webhookegress.Endpoint, error) {
	var ep webhookegress.Endpoint
	var dig, events []byte
	err := s.db.QueryRowContext(ctx, `
SELECT id, owner_id, url, secret_digest, events, active, created_at
FROM amsl_webhook_endpoints WHERE id = $1`, id).Scan(
		&ep.ID, &ep.OwnerID, &ep.URL, &dig, &events, &ep.Active, &ep.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return webhookegress.Endpoint{}, webhookegress.ErrNotFound
	}
	if err != nil {
		return webhookegress.Endpoint{}, err
	}
	copy(ep.SecretDigest[:], dig)
	_ = json.Unmarshal(events, &ep.Events)
	return ep, nil
}

func (s *Store) ListEndpointsByEvent(ctx context.Context, ownerID, eventType string) ([]webhookegress.Endpoint, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, owner_id, url, secret_digest, events, active, created_at
FROM amsl_webhook_endpoints WHERE owner_id = $1 AND active = TRUE`, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []webhookegress.Endpoint
	for rows.Next() {
		var ep webhookegress.Endpoint
		var dig, events []byte
		if err := rows.Scan(&ep.ID, &ep.OwnerID, &ep.URL, &dig, &events, &ep.Active, &ep.CreatedAt); err != nil {
			return nil, err
		}
		copy(ep.SecretDigest[:], dig)
		_ = json.Unmarshal(events, &ep.Events)
		for _, e := range ep.Events {
			if e == eventType {
				out = append(out, ep)
				break
			}
		}
	}
	return out, rows.Err()
}

func (s *Store) PutDelivery(ctx context.Context, d webhookegress.Delivery) error {
	var delivered any
	if !d.DeliveredAt.IsZero() {
		delivered = d.DeliveredAt.UTC()
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO amsl_webhook_deliveries
 (id, owner_id, endpoint_id, event_type, payload, status, attempts, last_error, created_at, delivered_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		d.ID, d.OwnerID, d.EndpointID, d.EventType, d.Payload, d.Status, d.Attempts, d.LastError,
		d.CreatedAt.UTC(), delivered)
	return err
}

func (s *Store) UpdateDelivery(ctx context.Context, d webhookegress.Delivery) error {
	var delivered any
	if !d.DeliveredAt.IsZero() {
		delivered = d.DeliveredAt.UTC()
	}
	res, err := s.db.ExecContext(ctx, `
UPDATE amsl_webhook_deliveries SET status=$1, attempts=$2, last_error=$3, delivered_at=$4
WHERE id=$5`, d.Status, d.Attempts, d.LastError, delivered, d.ID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return webhookegress.ErrNotFound
	}
	return nil
}

var _ webhookegress.Store = (*Store)(nil)
