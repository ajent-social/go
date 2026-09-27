// Package sqlstore persists humanauth session records via database/sql
// against PostgreSQL-compatible servers. Only the SHA-256 digest of each
// session cookie is stored.
package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ajent-social/go/humanauth"
)

// Schema is applied idempotently by Open.
const Schema = `
CREATE TABLE IF NOT EXISTS amsl_humanauth_sessions (
    token_digest  BYTEA PRIMARY KEY,
    subject_id    TEXT NOT NULL,
    subject_name  TEXT NOT NULL,
    subject_display TEXT NOT NULL,
    method        TEXT NOT NULL,
    csrf          TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS amsl_humanauth_sessions_subject ON amsl_humanauth_sessions (subject_id, created_at DESC);
CREATE INDEX IF NOT EXISTS amsl_humanauth_sessions_expiry ON amsl_humanauth_sessions (expires_at);
`

// Store is a multi-host humanauth.Store.
type Store struct{ db *sql.DB }

// Open pings db and applies Schema.
func Open(ctx context.Context, db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, humanauth.ErrInvalid
	}
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping humanauth database: %w", err)
	}
	if _, err := db.ExecContext(ctx, Schema); err != nil {
		return nil, fmt.Errorf("apply humanauth schema: %w", err)
	}
	return &Store{db: db}, nil
}

const columns = `token_digest, subject_id, subject_name, subject_display, method, csrf, created_at, expires_at`

func (s *Store) Create(ctx context.Context, rec humanauth.Record) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO amsl_humanauth_sessions (`+columns+`)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		rec.TokenDigest[:], rec.Subject.ID, rec.Subject.Name, rec.Subject.DisplayName,
		string(rec.Method), rec.CSRF, rec.CreatedAt.UTC(), rec.ExpiresAt.UTC())
	return err
}

func (s *Store) Get(ctx context.Context, digest [32]byte) (humanauth.Record, error) {
	rec, err := scanRecord(s.db.QueryRowContext(ctx, `
SELECT `+columns+` FROM amsl_humanauth_sessions WHERE token_digest = $1`, digest[:]))
	if errors.Is(err, sql.ErrNoRows) {
		return humanauth.Record{}, humanauth.ErrNotFound
	}
	return rec, err
}

func (s *Store) Delete(ctx context.Context, digest [32]byte) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM amsl_humanauth_sessions WHERE token_digest = $1`, digest[:])
	return err
}

func (s *Store) ListSubject(ctx context.Context, subjectID string) ([]humanauth.Record, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT `+columns+` FROM amsl_humanauth_sessions
WHERE subject_id = $1 ORDER BY created_at DESC, token_digest`, subjectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []humanauth.Record
	for rows.Next() {
		rec, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *Store) DeleteSubject(ctx context.Context, subjectID string) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM amsl_humanauth_sessions WHERE subject_id = $1`, subjectID)
	return affected(res, err)
}

func (s *Store) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM amsl_humanauth_sessions WHERE expires_at <= $1`, now.UTC())
	return affected(res, err)
}

type scanner interface{ Scan(...any) error }

func scanRecord(row scanner) (humanauth.Record, error) {
	var rec humanauth.Record
	var digest []byte
	var method string
	err := row.Scan(&digest, &rec.Subject.ID, &rec.Subject.Name, &rec.Subject.DisplayName,
		&method, &rec.CSRF, &rec.CreatedAt, &rec.ExpiresAt)
	if err != nil {
		return humanauth.Record{}, err
	}
	if len(digest) != len(rec.TokenDigest) {
		return humanauth.Record{}, fmt.Errorf("humanauth: bad digest length")
	}
	copy(rec.TokenDigest[:], digest)
	rec.Method = humanauth.Method(method)
	rec.CreatedAt, rec.ExpiresAt = rec.CreatedAt.UTC(), rec.ExpiresAt.UTC()
	return rec, nil
}

func affected(res sql.Result, err error) (int, error) {
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

var _ humanauth.Store = (*Store)(nil)
