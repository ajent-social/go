// Package sqlstore persists mcpoauth.Store state via database/sql against
// PostgreSQL-compatible servers (PostgreSQL, SereneDB, and others that speak
// the same SQL dialect and wire protocol).
//
// Swap backends by changing the driver and DSN used to open *sql.DB. This
// package does not embed a vendor client. Connection pooling, TLS and
// migration ownership remain with the application.
//
// Status: CANDIDATE companion to mcpoauth. Required for multi-host MCP OAuth;
// boltstore remains the single-host reference adapter.
package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ajent-social/go/mcpoauth"
)

// Schema is applied idempotently by Open.
const Schema = `
CREATE TABLE IF NOT EXISTS amsl_mcpoauth_clients (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  redirect_uris TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS amsl_mcpoauth_consents (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  state TEXT NOT NULL,
  resource TEXT NOT NULL,
  scopes TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS amsl_mcpoauth_codes (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  subject TEXT NOT NULL,
  binding TEXT NOT NULL,
  resource TEXT NOT NULL,
  scopes TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS amsl_mcpoauth_grants (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  subject TEXT NOT NULL,
  binding TEXT NOT NULL,
  resource TEXT NOT NULL,
  scopes TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS amsl_mcpoauth_tokens (
  id TEXT PRIMARY KEY,
  grant_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  subject TEXT NOT NULL,
  binding TEXT NOT NULL,
  resource TEXT NOT NULL,
  scopes TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS amsl_mcpoauth_refresh (
  id TEXT PRIMARY KEY,
  grant_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  generation INT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ,
  replaced_by TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS amsl_mcpoauth_tokens_grant_idx ON amsl_mcpoauth_tokens (grant_id);
CREATE INDEX IF NOT EXISTS amsl_mcpoauth_refresh_grant_idx ON amsl_mcpoauth_refresh (grant_id);
`

// Store is a multi-host mcpoauth.Store.
type Store struct{ db *sql.DB }

// Open pings db and applies Schema.
func Open(ctx context.Context, db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, mcpoauth.ErrInvalid
	}
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping oauth database: %w", err)
	}
	if _, err := db.ExecContext(ctx, Schema); err != nil {
		return nil, fmt.Errorf("apply oauth schema: %w", err)
	}
	return &Store{db: db}, nil
}

func encodeStrings(v []string) (string, error) {
	if v == nil {
		v = []string{}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func decodeStrings(s string) ([]string, error) {
	if s == "" {
		return []string{}, nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, err
	}
	return out, nil
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

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}

func scanNullTime(n sql.NullTime) time.Time {
	if n.Valid {
		return n.Time.UTC()
	}
	return time.Time{}
}

func (s *Store) CreateClient(ctx context.Context, c mcpoauth.Client) error {
	uris, err := encodeStrings(c.RedirectURIs)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO amsl_mcpoauth_clients (id, name, redirect_uris, created_at) VALUES ($1,$2,$3,$4)`,
		c.ID, c.Name, uris, c.CreatedAt.UTC())
	if isUnique(err) {
		return mcpoauth.ErrExists
	}
	return err
}

func (s *Store) Client(ctx context.Context, id string) (mcpoauth.Client, error) {
	var c mcpoauth.Client
	var uris string
	err := s.db.QueryRowContext(ctx, `
SELECT id, name, redirect_uris, created_at FROM amsl_mcpoauth_clients WHERE id = $1`, id).
		Scan(&c.ID, &c.Name, &uris, &c.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return mcpoauth.Client{}, mcpoauth.ErrNotFound
	}
	if err != nil {
		return mcpoauth.Client{}, err
	}
	c.RedirectURIs, err = decodeStrings(uris)
	c.CreatedAt = c.CreatedAt.UTC()
	return c, err
}

func (s *Store) CreateConsent(ctx context.Context, c mcpoauth.ConsentRecord) error {
	scopes, err := encodeStrings(c.Scopes)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO amsl_mcpoauth_consents
 (id, client_id, redirect_uri, code_challenge, state, resource, scopes, created_at, expires_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		c.ID, c.ClientID, c.RedirectURI, c.CodeChallenge, c.State, c.Resource, scopes,
		c.CreatedAt.UTC(), c.ExpiresAt.UTC())
	if isUnique(err) {
		return mcpoauth.ErrExists
	}
	return err
}

func (s *Store) Consent(ctx context.Context, id string) (mcpoauth.ConsentRecord, error) {
	return scanConsent(s.db.QueryRowContext(ctx, `
SELECT id, client_id, redirect_uri, code_challenge, state, resource, scopes, created_at, expires_at
FROM amsl_mcpoauth_consents WHERE id = $1`, id))
}

func (s *Store) ConsumeConsent(ctx context.Context, id string) (mcpoauth.ConsentRecord, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return mcpoauth.ConsentRecord{}, err
	}
	defer func() { _ = tx.Rollback() }()
	c, err := scanConsent(tx.QueryRowContext(ctx, `
SELECT id, client_id, redirect_uri, code_challenge, state, resource, scopes, created_at, expires_at
FROM amsl_mcpoauth_consents WHERE id = $1 FOR UPDATE`, id))
	if err != nil {
		return mcpoauth.ConsentRecord{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM amsl_mcpoauth_consents WHERE id = $1`, id); err != nil {
		return mcpoauth.ConsentRecord{}, err
	}
	return c, tx.Commit()
}

func scanConsent(row *sql.Row) (mcpoauth.ConsentRecord, error) {
	var c mcpoauth.ConsentRecord
	var scopes string
	err := row.Scan(&c.ID, &c.ClientID, &c.RedirectURI, &c.CodeChallenge, &c.State, &c.Resource,
		&scopes, &c.CreatedAt, &c.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return mcpoauth.ConsentRecord{}, mcpoauth.ErrNotFound
	}
	if err != nil {
		return mcpoauth.ConsentRecord{}, err
	}
	c.Scopes, err = decodeStrings(scopes)
	c.CreatedAt, c.ExpiresAt = c.CreatedAt.UTC(), c.ExpiresAt.UTC()
	return c, err
}

func (s *Store) CreateCode(ctx context.Context, c mcpoauth.CodeRecord) error {
	scopes, err := encodeStrings(c.Scopes)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO amsl_mcpoauth_codes
 (id, client_id, redirect_uri, code_challenge, subject, binding, resource, scopes, created_at, expires_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		c.ID, c.ClientID, c.RedirectURI, c.CodeChallenge, c.Subject, c.Binding, c.Resource, scopes,
		c.CreatedAt.UTC(), c.ExpiresAt.UTC())
	if isUnique(err) {
		return mcpoauth.ErrExists
	}
	return err
}

func (s *Store) ConsumeCode(ctx context.Context, id string) (mcpoauth.CodeRecord, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return mcpoauth.CodeRecord{}, err
	}
	defer func() { _ = tx.Rollback() }()
	c, err := scanCode(tx.QueryRowContext(ctx, `
SELECT id, client_id, redirect_uri, code_challenge, subject, binding, resource, scopes, created_at, expires_at
FROM amsl_mcpoauth_codes WHERE id = $1 FOR UPDATE`, id))
	if err != nil {
		return mcpoauth.CodeRecord{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM amsl_mcpoauth_codes WHERE id = $1`, id); err != nil {
		return mcpoauth.CodeRecord{}, err
	}
	return c, tx.Commit()
}

func scanCode(row *sql.Row) (mcpoauth.CodeRecord, error) {
	var c mcpoauth.CodeRecord
	var scopes string
	err := row.Scan(&c.ID, &c.ClientID, &c.RedirectURI, &c.CodeChallenge, &c.Subject, &c.Binding,
		&c.Resource, &scopes, &c.CreatedAt, &c.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return mcpoauth.CodeRecord{}, mcpoauth.ErrNotFound
	}
	if err != nil {
		return mcpoauth.CodeRecord{}, err
	}
	c.Scopes, err = decodeStrings(scopes)
	c.CreatedAt, c.ExpiresAt = c.CreatedAt.UTC(), c.ExpiresAt.UTC()
	return c, err
}

func (s *Store) Grant(ctx context.Context, id string) (mcpoauth.GrantRecord, error) {
	return scanGrant(s.db.QueryRowContext(ctx, `
SELECT id, client_id, subject, binding, resource, scopes, created_at, expires_at, revoked_at
FROM amsl_mcpoauth_grants WHERE id = $1`, id))
}

func scanGrant(row *sql.Row) (mcpoauth.GrantRecord, error) {
	var g mcpoauth.GrantRecord
	var scopes string
	var revoked sql.NullTime
	err := row.Scan(&g.ID, &g.ClientID, &g.Subject, &g.Binding, &g.Resource, &scopes,
		&g.CreatedAt, &g.ExpiresAt, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return mcpoauth.GrantRecord{}, mcpoauth.ErrNotFound
	}
	if err != nil {
		return mcpoauth.GrantRecord{}, err
	}
	g.Scopes, err = decodeStrings(scopes)
	g.CreatedAt, g.ExpiresAt = g.CreatedAt.UTC(), g.ExpiresAt.UTC()
	g.RevokedAt = scanNullTime(revoked)
	return g, err
}

func (s *Store) Token(ctx context.Context, id string) (mcpoauth.TokenRecord, error) {
	var t mcpoauth.TokenRecord
	var scopes string
	err := s.db.QueryRowContext(ctx, `
SELECT id, grant_id, client_id, subject, binding, resource, scopes, created_at, expires_at
FROM amsl_mcpoauth_tokens WHERE id = $1`, id).Scan(
		&t.ID, &t.GrantID, &t.ClientID, &t.Subject, &t.Binding, &t.Resource, &scopes,
		&t.CreatedAt, &t.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return mcpoauth.TokenRecord{}, mcpoauth.ErrNotFound
	}
	if err != nil {
		return mcpoauth.TokenRecord{}, err
	}
	t.Scopes, err = decodeStrings(scopes)
	t.CreatedAt, t.ExpiresAt = t.CreatedAt.UTC(), t.ExpiresAt.UTC()
	return t, err
}

func (s *Store) Refresh(ctx context.Context, id string) (mcpoauth.RefreshRecord, error) {
	return scanRefresh(s.db.QueryRowContext(ctx, `
SELECT id, grant_id, client_id, generation, created_at, expires_at, used_at, replaced_by
FROM amsl_mcpoauth_refresh WHERE id = $1`, id))
}

func scanRefresh(row *sql.Row) (mcpoauth.RefreshRecord, error) {
	var r mcpoauth.RefreshRecord
	var used sql.NullTime
	err := row.Scan(&r.ID, &r.GrantID, &r.ClientID, &r.Generation, &r.CreatedAt, &r.ExpiresAt, &used, &r.ReplacedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return mcpoauth.RefreshRecord{}, mcpoauth.ErrNotFound
	}
	if err != nil {
		return mcpoauth.RefreshRecord{}, err
	}
	r.CreatedAt, r.ExpiresAt = r.CreatedAt.UTC(), r.ExpiresAt.UTC()
	r.UsedAt = scanNullTime(used)
	return r, nil
}

func (s *Store) CreateGrant(ctx context.Context, g mcpoauth.GrantIssue) error {
	if g.Grant.ID == "" || g.Token.GrantID != g.Grant.ID || (g.Refresh != nil && g.Refresh.GrantID != g.Grant.ID) {
		return mcpoauth.ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	gScopes, err := encodeStrings(g.Grant.Scopes)
	if err != nil {
		return err
	}
	tScopes, err := encodeStrings(g.Token.Scopes)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO amsl_mcpoauth_grants
 (id, client_id, subject, binding, resource, scopes, created_at, expires_at, revoked_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		g.Grant.ID, g.Grant.ClientID, g.Grant.Subject, g.Grant.Binding, g.Grant.Resource, gScopes,
		g.Grant.CreatedAt.UTC(), g.Grant.ExpiresAt.UTC(), nullTime(g.Grant.RevokedAt))
	if isUnique(err) {
		return mcpoauth.ErrExists
	}
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO amsl_mcpoauth_tokens
 (id, grant_id, client_id, subject, binding, resource, scopes, created_at, expires_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		g.Token.ID, g.Token.GrantID, g.Token.ClientID, g.Token.Subject, g.Token.Binding, g.Token.Resource,
		tScopes, g.Token.CreatedAt.UTC(), g.Token.ExpiresAt.UTC())
	if isUnique(err) {
		return mcpoauth.ErrExists
	}
	if err != nil {
		return err
	}
	if g.Refresh != nil {
		_, err = tx.ExecContext(ctx, `
INSERT INTO amsl_mcpoauth_refresh
 (id, grant_id, client_id, generation, created_at, expires_at, used_at, replaced_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			g.Refresh.ID, g.Refresh.GrantID, g.Refresh.ClientID, g.Refresh.Generation,
			g.Refresh.CreatedAt.UTC(), g.Refresh.ExpiresAt.UTC(), nullTime(g.Refresh.UsedAt), g.Refresh.ReplacedBy)
		if isUnique(err) {
			return mcpoauth.ErrExists
		}
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) RotateRefresh(ctx context.Context, r mcpoauth.RefreshRotation) error {
	if r.RefreshID == "" || r.At.IsZero() || r.Token.ID == "" || r.Refresh.ID == "" {
		return mcpoauth.ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	old, err := scanRefresh(tx.QueryRowContext(ctx, `
SELECT id, grant_id, client_id, generation, created_at, expires_at, used_at, replaced_by
FROM amsl_mcpoauth_refresh WHERE id = $1 FOR UPDATE`, r.RefreshID))
	if err != nil {
		return err
	}
	if !old.UsedAt.IsZero() {
		g, gerr := scanGrant(tx.QueryRowContext(ctx, `
SELECT id, client_id, subject, binding, resource, scopes, created_at, expires_at, revoked_at
FROM amsl_mcpoauth_grants WHERE id = $1 FOR UPDATE`, old.GrantID))
		if gerr != nil && !errors.Is(gerr, mcpoauth.ErrNotFound) {
			return gerr
		}
		if gerr == nil && g.RevokedAt.IsZero() {
			if _, err := tx.ExecContext(ctx, `
UPDATE amsl_mcpoauth_grants SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL`,
				g.ID, r.At.UTC()); err != nil {
				return err
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		return mcpoauth.ErrReused
	}

	g, err := scanGrant(tx.QueryRowContext(ctx, `
SELECT id, client_id, subject, binding, resource, scopes, created_at, expires_at, revoked_at
FROM amsl_mcpoauth_grants WHERE id = $1 FOR UPDATE`, old.GrantID))
	if err != nil {
		return err
	}
	if !g.RevokedAt.IsZero() {
		return mcpoauth.ErrDenied
	}
	if r.Token.GrantID != g.ID || r.Refresh.GrantID != g.ID {
		return mcpoauth.ErrInvalid
	}
	tScopes, err := encodeStrings(r.Token.Scopes)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO amsl_mcpoauth_tokens
 (id, grant_id, client_id, subject, binding, resource, scopes, created_at, expires_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		r.Token.ID, r.Token.GrantID, r.Token.ClientID, r.Token.Subject, r.Token.Binding, r.Token.Resource,
		tScopes, r.Token.CreatedAt.UTC(), r.Token.ExpiresAt.UTC())
	if isUnique(err) {
		return mcpoauth.ErrExists
	}
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO amsl_mcpoauth_refresh
 (id, grant_id, client_id, generation, created_at, expires_at, used_at, replaced_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		r.Refresh.ID, r.Refresh.GrantID, r.Refresh.ClientID, r.Refresh.Generation,
		r.Refresh.CreatedAt.UTC(), r.Refresh.ExpiresAt.UTC(), nullTime(r.Refresh.UsedAt), r.Refresh.ReplacedBy)
	if isUnique(err) {
		return mcpoauth.ErrExists
	}
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
UPDATE amsl_mcpoauth_refresh SET used_at = $2, replaced_by = $3 WHERE id = $1`,
		old.ID, r.At.UTC(), r.Refresh.ID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RevokeGrant(ctx context.Context, id string, at time.Time) error {
	if at.IsZero() {
		return mcpoauth.ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	g, err := scanGrant(tx.QueryRowContext(ctx, `
SELECT id, client_id, subject, binding, resource, scopes, created_at, expires_at, revoked_at
FROM amsl_mcpoauth_grants WHERE id = $1 FOR UPDATE`, id))
	if err != nil {
		return err
	}
	if !g.RevokedAt.IsZero() {
		return tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE amsl_mcpoauth_grants SET revoked_at = $2 WHERE id = $1`, id, at.UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

var _ mcpoauth.Store = (*Store)(nil)
