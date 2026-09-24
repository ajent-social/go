// Package sqlstore persists passkey ceremonies and credentials via database/sql
// against PostgreSQL-compatible servers (PostgreSQL, SereneDB, and similar).
package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ajent-social/go/passkey"
)

// Schema is applied idempotently by Open.
const Schema = `
CREATE TABLE IF NOT EXISTS amsl_passkey_ceremonies (
  handle_digest BYTEA PRIMARY KEY,
  kind TEXT NOT NULL,
  subject_id TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL DEFAULT '',
  session_json TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  CONSTRAINT amsl_passkey_ceremony_digest_len CHECK (octet_length(handle_digest) = 32)
);
CREATE TABLE IF NOT EXISTS amsl_passkey_credentials (
  credential_id BYTEA NOT NULL,
  subject_id TEXT NOT NULL,
  credential_json TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (subject_id, credential_id)
);
CREATE INDEX IF NOT EXISTS amsl_passkey_credentials_id_idx
  ON amsl_passkey_credentials (credential_id);
`

// Store is a multi-host passkey.Store.
type Store struct{ db *sql.DB }

// Open pings db and applies Schema.
func Open(ctx context.Context, db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, passkey.ErrInvalid
	}
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping passkey database: %w", err)
	}
	if _, err := db.ExecContext(ctx, Schema); err != nil {
		return nil, fmt.Errorf("apply passkey schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) PutCeremony(ctx context.Context, c passkey.Ceremony) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO amsl_passkey_ceremonies
 (handle_digest, kind, subject_id, name, session_json, expires_at)
VALUES ($1,$2,$3,$4,$5,$6)`,
		c.HandleDigest[:], string(c.Kind), c.SubjectID, c.Name, string(c.SessionJSON), c.ExpiresAt.UTC())
	if isUnique(err) {
		return passkey.ErrExists
	}
	return err
}

func (s *Store) TakeCeremony(ctx context.Context, digest [32]byte) (passkey.Ceremony, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return passkey.Ceremony{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var c passkey.Ceremony
	var dig []byte
	var kind string
	var session string
	err = tx.QueryRowContext(ctx, `
SELECT handle_digest, kind, subject_id, name, session_json, expires_at
FROM amsl_passkey_ceremonies WHERE handle_digest = $1 FOR UPDATE`, digest[:]).Scan(
		&dig, &kind, &c.SubjectID, &c.Name, &session, &c.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return passkey.Ceremony{}, passkey.ErrNotFound
	}
	if err != nil {
		return passkey.Ceremony{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM amsl_passkey_ceremonies WHERE handle_digest = $1`, digest[:]); err != nil {
		return passkey.Ceremony{}, err
	}
	if err := tx.Commit(); err != nil {
		return passkey.Ceremony{}, err
	}
	if len(dig) != 32 {
		return passkey.Ceremony{}, fmt.Errorf("passkey: bad ceremony digest")
	}
	copy(c.HandleDigest[:], dig)
	c.Kind = passkey.Kind(kind)
	c.SessionJSON = []byte(session)
	c.ExpiresAt = c.ExpiresAt.UTC()
	return c, nil
}

func (s *Store) PutCredential(ctx context.Context, rec passkey.CredentialRecord) error {
	raw, err := json.Marshal(rec.Credential)
	if err != nil {
		return err
	}
	created := rec.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO amsl_passkey_credentials (credential_id, subject_id, credential_json, created_at)
VALUES ($1,$2,$3,$4)`, rec.Credential.ID, rec.SubjectID, string(raw), created.UTC())
	if isUnique(err) {
		return passkey.ErrExists
	}
	return err
}

func (s *Store) UpdateCredential(ctx context.Context, rec passkey.CredentialRecord) error {
	raw, err := json.Marshal(rec.Credential)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `
UPDATE amsl_passkey_credentials SET credential_json = $3 WHERE subject_id = $1 AND credential_id = $2`,
		rec.SubjectID, rec.Credential.ID, string(raw))
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return passkey.ErrNotFound
	}
	return nil
}

func (s *Store) LookupCredential(ctx context.Context, credentialID []byte, subjectID string) (passkey.CredentialRecord, error) {
	var rec passkey.CredentialRecord
	var raw string
	err := s.db.QueryRowContext(ctx, `
SELECT subject_id, credential_json, created_at FROM amsl_passkey_credentials
WHERE subject_id = $1 AND credential_id = $2`, subjectID, credentialID).Scan(&rec.SubjectID, &raw, &rec.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return passkey.CredentialRecord{}, passkey.ErrNotFound
	}
	if err != nil {
		return passkey.CredentialRecord{}, err
	}
	if err := json.Unmarshal([]byte(raw), &rec.Credential); err != nil {
		return passkey.CredentialRecord{}, err
	}
	rec.CreatedAt = rec.CreatedAt.UTC()
	return rec, nil
}

func (s *Store) ListCredentials(ctx context.Context, subjectID string) ([]passkey.CredentialRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT subject_id, credential_json, created_at FROM amsl_passkey_credentials
WHERE subject_id = $1 ORDER BY created_at ASC`, subjectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []passkey.CredentialRecord
	for rows.Next() {
		var rec passkey.CredentialRecord
		var raw string
		if err := rows.Scan(&rec.SubjectID, &raw, &rec.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &rec.Credential); err != nil {
			return nil, err
		}
		rec.CreatedAt = rec.CreatedAt.UTC()
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *Store) CountCredentials(ctx context.Context, subjectID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `
SELECT count(*) FROM amsl_passkey_credentials WHERE subject_id = $1`, subjectID).Scan(&n)
	return n, err
}

func (s *Store) DeleteCredential(ctx context.Context, subjectID string, credentialID []byte) error {
	res, err := s.db.ExecContext(ctx, `
DELETE FROM amsl_passkey_credentials WHERE subject_id = $1 AND credential_id = $2`, subjectID, credentialID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return passkey.ErrNotFound
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

var _ passkey.Store = (*Store)(nil)
