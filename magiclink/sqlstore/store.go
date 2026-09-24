// Package sqlstore persists magiclink challenges via database/sql against
// PostgreSQL-compatible servers (PostgreSQL, SereneDB, and similar).
package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/ajent-social/go/magiclink"
)

// Schema is applied idempotently by Open.
const Schema = `
CREATE TABLE IF NOT EXISTS amsl_magiclink_challenges (
  token_digest BYTEA PRIMARY KEY,
  purpose TEXT NOT NULL,
  email TEXT NOT NULL,
  subject_id TEXT NOT NULL DEFAULT '',
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  CONSTRAINT amsl_magiclink_digest_len CHECK (octet_length(token_digest) = 32)
);
CREATE INDEX IF NOT EXISTS amsl_magiclink_email_purpose_idx
  ON amsl_magiclink_challenges (email, purpose);
`

// Store is a multi-host magiclink.Store.
type Store struct{ db *sql.DB }

// Open pings db and applies Schema.
func Open(ctx context.Context, db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, magiclink.ErrInvalid
	}
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping magiclink database: %w", err)
	}
	if _, err := db.ExecContext(ctx, Schema); err != nil {
		return nil, fmt.Errorf("apply magiclink schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Put(ctx context.Context, ch magiclink.Challenge) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO amsl_magiclink_challenges
 (token_digest, purpose, email, subject_id, expires_at, created_at)
VALUES ($1,$2,$3,$4,$5,$6)`,
		ch.TokenDigest[:], string(ch.Purpose), ch.Email, ch.SubjectID,
		ch.ExpiresAt.UTC(), ch.CreatedAt.UTC())
	if isUnique(err) {
		return magiclink.ErrExists
	}
	return err
}

func (s *Store) Consume(ctx context.Context, digest [32]byte) (magiclink.Challenge, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return magiclink.Challenge{}, err
	}
	defer func() { _ = tx.Rollback() }()
	ch, err := scanChallenge(tx.QueryRowContext(ctx, `
SELECT token_digest, purpose, email, subject_id, expires_at, created_at
FROM amsl_magiclink_challenges WHERE token_digest = $1 FOR UPDATE`, digest[:]))
	if err != nil {
		return magiclink.Challenge{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM amsl_magiclink_challenges WHERE token_digest = $1`, digest[:]); err != nil {
		return magiclink.Challenge{}, err
	}
	if err := tx.Commit(); err != nil {
		return magiclink.Challenge{}, err
	}
	return ch, nil
}

func (s *Store) InvalidateEmail(ctx context.Context, email string, purpose magiclink.Purpose) error {
	_, err := s.db.ExecContext(ctx, `
DELETE FROM amsl_magiclink_challenges WHERE email = $1 AND purpose = $2`, email, string(purpose))
	return err
}

func scanChallenge(row *sql.Row) (magiclink.Challenge, error) {
	var ch magiclink.Challenge
	var digest []byte
	var purpose string
	err := row.Scan(&digest, &purpose, &ch.Email, &ch.SubjectID, &ch.ExpiresAt, &ch.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return magiclink.Challenge{}, magiclink.ErrNotFound
	}
	if err != nil {
		return magiclink.Challenge{}, err
	}
	if len(digest) != 32 {
		return magiclink.Challenge{}, fmt.Errorf("magiclink: bad digest length")
	}
	copy(ch.TokenDigest[:], digest)
	ch.Purpose = magiclink.Purpose(purpose)
	ch.ExpiresAt, ch.CreatedAt = ch.ExpiresAt.UTC(), ch.CreatedAt.UTC()
	return ch, nil
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

var _ magiclink.Store = (*Store)(nil)
