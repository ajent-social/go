// Package boltstore is a durable single-process mcpoauth.Store backed by bbolt.
// It follows the JSON-record/bbolt-transaction pattern of the servicecred
// adapter (see docs/provenance-servicecred.md). Each Store method is one bbolt
// transaction, so create-without-overwrite, consume and revoke are atomic
// across concurrent goroutines; bbolt's file lock excludes other processes.
// It is a reference adapter for modest local deployments, not a multi-host
// database. Nothing is cached: every read observes committed state.
package boltstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ajent-social/go/mcpoauth"
	bolt "go.etcd.io/bbolt"
)

var (
	bucketClients  = []byte("amsl-mcpoauth-clients-v1")
	bucketConsents = []byte("amsl-mcpoauth-consents-v1")
	bucketCodes    = []byte("amsl-mcpoauth-codes-v1")
	bucketTokens   = []byte("amsl-mcpoauth-tokens-v1")
	bucketGrants   = []byte("amsl-mcpoauth-grants-v1")
	bucketRefresh  = []byte("amsl-mcpoauth-refresh-v1")
)

// Store holds an open database until Close.
type Store struct{ db *bolt.DB }

// Open creates or opens the database at path. The parent must be a private
// directory owned by the application account. Existing data is never reset.
func Open(ctx context.Context, path string) (*Store, error) {
	if path == "" {
		return nil, mcpoauth.ErrInvalid
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve oauth database path: %w", err)
	}
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("check oauth database directory: %w", err)
	}
	if !parent.IsDir() || parent.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("%w: oauth database directory must be private", mcpoauth.ErrInvalid)
	}
	if fi, statErr := os.Lstat(path); statErr == nil && (!fi.Mode().IsRegular() || fi.Mode().Perm()&0077 != 0) {
		return nil, fmt.Errorf("%w: oauth database must be a private regular file", mcpoauth.ErrInvalid)
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return nil, fmt.Errorf("check oauth database: %w", statErr)
	}
	timeout := 5 * time.Second
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < timeout {
		timeout = time.Until(deadline)
		if timeout <= 0 {
			return nil, context.DeadlineExceeded
		}
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: timeout})
	if err != nil {
		return nil, fmt.Errorf("open oauth database: %w", err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketClients, bucketConsents, bucketCodes, bucketTokens, bucketGrants, bucketRefresh} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, errors.Join(fmt.Errorf("initialize oauth database: %w", err), db.Close())
	}
	return &Store{db: db}, nil
}

// Close releases the database. Subsequent calls fail closed.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) tx(ctx context.Context, write bool, bucket []byte, fn func(*bolt.Bucket) error) error {
	return s.multi(ctx, write, func(tx *bolt.Tx) error {
		b, err := bucketOf(tx, bucket)
		if err != nil {
			return err
		}
		return fn(b)
	})
}

// multi runs one transaction that may touch several buckets.
func (s *Store) multi(ctx context.Context, write bool, fn func(*bolt.Tx) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if write {
		return s.db.Update(fn)
	}
	return s.db.View(fn)
}

func bucketOf(tx *bolt.Tx, name []byte) (*bolt.Bucket, error) {
	b := tx.Bucket(name)
	if b == nil {
		return nil, fmt.Errorf("oauth database schema missing")
	}
	return b, nil
}

// putNew inserts without overwrite inside an open transaction.
func putNew[T any](b *bolt.Bucket, id string, rec T) error {
	if id == "" {
		return mcpoauth.ErrInvalid
	}
	if b.Get([]byte(id)) != nil {
		return mcpoauth.ErrExists
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("encode oauth record: %w", err)
	}
	return b.Put([]byte(id), data)
}

func put[T any](b *bolt.Bucket, id string, rec T) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("encode oauth record: %w", err)
	}
	return b.Put([]byte(id), data)
}

func create[T any](s *Store, ctx context.Context, bucket []byte, id string, rec T) error {
	if id == "" {
		return mcpoauth.ErrInvalid
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("encode oauth record: %w", err)
	}
	return s.tx(ctx, true, bucket, func(b *bolt.Bucket) error {
		if b.Get([]byte(id)) != nil {
			return mcpoauth.ErrExists
		}
		return b.Put([]byte(id), data)
	})
}

func decode[T any](data []byte, id string, idOf func(T) string) (T, error) {
	var rec T
	if data == nil {
		return rec, mcpoauth.ErrNotFound
	}
	if err := json.Unmarshal(data, &rec); err != nil {
		return rec, fmt.Errorf("decode oauth record: %w", err)
	}
	if idOf(rec) != id {
		return rec, fmt.Errorf("oauth record ID mismatch")
	}
	return rec, nil
}

func get[T any](s *Store, ctx context.Context, bucket []byte, id string, idOf func(T) string) (rec T, err error) {
	err = s.tx(ctx, false, bucket, func(b *bolt.Bucket) error {
		rec, err = decode(b.Get([]byte(id)), id, idOf)
		return err
	})
	return
}

// consume deletes and returns in one write transaction; exactly one caller wins.
func consume[T any](s *Store, ctx context.Context, bucket []byte, id string, idOf func(T) string) (rec T, err error) {
	err = s.tx(ctx, true, bucket, func(b *bolt.Bucket) error {
		if rec, err = decode(b.Get([]byte(id)), id, idOf); err != nil {
			return err
		}
		return b.Delete([]byte(id))
	})
	return
}

func clientID(c mcpoauth.Client) string         { return c.ID }
func consentID(c mcpoauth.ConsentRecord) string { return c.ID }
func codeID(c mcpoauth.CodeRecord) string       { return c.ID }
func tokenID(t mcpoauth.TokenRecord) string     { return t.ID }
func grantID(g mcpoauth.GrantRecord) string     { return g.ID }
func refreshID(r mcpoauth.RefreshRecord) string { return r.ID }

func (s *Store) CreateClient(ctx context.Context, c mcpoauth.Client) error {
	return create(s, ctx, bucketClients, c.ID, c)
}
func (s *Store) Client(ctx context.Context, id string) (mcpoauth.Client, error) {
	return get(s, ctx, bucketClients, id, clientID)
}
func (s *Store) CreateConsent(ctx context.Context, c mcpoauth.ConsentRecord) error {
	return create(s, ctx, bucketConsents, c.ID, c)
}
func (s *Store) Consent(ctx context.Context, id string) (mcpoauth.ConsentRecord, error) {
	return get(s, ctx, bucketConsents, id, consentID)
}
func (s *Store) ConsumeConsent(ctx context.Context, id string) (mcpoauth.ConsentRecord, error) {
	return consume(s, ctx, bucketConsents, id, consentID)
}
func (s *Store) CreateCode(ctx context.Context, c mcpoauth.CodeRecord) error {
	return create(s, ctx, bucketCodes, c.ID, c)
}
func (s *Store) ConsumeCode(ctx context.Context, id string) (mcpoauth.CodeRecord, error) {
	return consume(s, ctx, bucketCodes, id, codeID)
}
func (s *Store) Grant(ctx context.Context, id string) (mcpoauth.GrantRecord, error) {
	return get(s, ctx, bucketGrants, id, grantID)
}
func (s *Store) Token(ctx context.Context, id string) (mcpoauth.TokenRecord, error) {
	return get(s, ctx, bucketTokens, id, tokenID)
}
func (s *Store) Refresh(ctx context.Context, id string) (mcpoauth.RefreshRecord, error) {
	return get(s, ctx, bucketRefresh, id, refreshID)
}

// CreateGrant writes grant, token and optional refresh record in one
// transaction; any collision or mismatch rolls everything back.
func (s *Store) CreateGrant(ctx context.Context, g mcpoauth.GrantIssue) error {
	if g.Grant.ID == "" || g.Token.GrantID != g.Grant.ID || (g.Refresh != nil && g.Refresh.GrantID != g.Grant.ID) {
		return mcpoauth.ErrInvalid
	}
	return s.multi(ctx, true, func(tx *bolt.Tx) error {
		grants, err := bucketOf(tx, bucketGrants)
		if err != nil {
			return err
		}
		tokens, err := bucketOf(tx, bucketTokens)
		if err != nil {
			return err
		}
		refresh, err := bucketOf(tx, bucketRefresh)
		if err != nil {
			return err
		}
		if err := putNew(grants, g.Grant.ID, g.Grant); err != nil {
			return err
		}
		if err := putNew(tokens, g.Token.ID, g.Token); err != nil {
			return err
		}
		if g.Refresh != nil {
			return putNew(refresh, g.Refresh.ID, *g.Refresh)
		}
		return nil
	})
}

// RotateRefresh implements the mark-used-or-detect-reuse step. On reuse the
// family revocation is committed in its own right and ErrReused is returned
// after the commit; bbolt would roll back a write if the closure errored.
func (s *Store) RotateRefresh(ctx context.Context, r mcpoauth.RefreshRotation) error {
	if r.RefreshID == "" || r.At.IsZero() || r.Token.ID == "" || r.Refresh.ID == "" {
		return mcpoauth.ErrInvalid
	}
	reused := false
	err := s.multi(ctx, true, func(tx *bolt.Tx) error {
		grants, err := bucketOf(tx, bucketGrants)
		if err != nil {
			return err
		}
		tokens, err := bucketOf(tx, bucketTokens)
		if err != nil {
			return err
		}
		refresh, err := bucketOf(tx, bucketRefresh)
		if err != nil {
			return err
		}
		old, err := decode(refresh.Get([]byte(r.RefreshID)), r.RefreshID, refreshID)
		if err != nil {
			return err
		}
		if !old.UsedAt.IsZero() {
			reused = true
			g, err := decode(grants.Get([]byte(old.GrantID)), old.GrantID, grantID)
			if err != nil && !errors.Is(err, mcpoauth.ErrNotFound) {
				return err
			}
			if err == nil && g.RevokedAt.IsZero() {
				g.RevokedAt = r.At
				return put(grants, g.ID, g)
			}
			return nil
		}
		g, err := decode(grants.Get([]byte(old.GrantID)), old.GrantID, grantID)
		if err != nil {
			return err
		}
		if !g.RevokedAt.IsZero() {
			return mcpoauth.ErrDenied
		}
		if r.Token.GrantID != g.ID || r.Refresh.GrantID != g.ID {
			return mcpoauth.ErrInvalid
		}
		if err := putNew(tokens, r.Token.ID, r.Token); err != nil {
			return err
		}
		if err := putNew(refresh, r.Refresh.ID, r.Refresh); err != nil {
			return err
		}
		old.UsedAt, old.ReplacedBy = r.At, r.Refresh.ID
		return put(refresh, old.ID, old)
	})
	if err != nil {
		return err
	}
	if reused {
		return mcpoauth.ErrReused
	}
	return nil
}

// RevokeGrant is idempotent and never alters other fields.
func (s *Store) RevokeGrant(ctx context.Context, id string, at time.Time) error {
	if at.IsZero() {
		return mcpoauth.ErrInvalid
	}
	return s.tx(ctx, true, bucketGrants, func(b *bolt.Bucket) error {
		g, err := decode(b.Get([]byte(id)), id, grantID)
		if err != nil {
			return err
		}
		if !g.RevokedAt.IsZero() {
			return nil
		}
		g.RevokedAt = at
		return put(b, id, g)
	})
}

// Sweep deletes consent, code, token, refresh and grant records whose
// ExpiresAt is before cutoff. Tokens never outlive their grant, so one cutoff
// is safe for all buckets. It is housekeeping only; the server never relies
// on it and fails closed if a grant is missing.
func (s *Store) Sweep(ctx context.Context, cutoff time.Time) (int, error) {
	n := 0
	type expiring struct {
		ExpiresAt time.Time `json:"expires_at"`
	}
	for _, bucket := range [][]byte{bucketConsents, bucketCodes, bucketTokens, bucketRefresh, bucketGrants} {
		err := s.tx(ctx, true, bucket, func(b *bolt.Bucket) error {
			var stale [][]byte
			err := b.ForEach(func(k, v []byte) error {
				if err := ctx.Err(); err != nil {
					return err
				}
				var e expiring
				if err := json.Unmarshal(v, &e); err != nil {
					return fmt.Errorf("decode oauth record: %w", err)
				}
				if e.ExpiresAt.Before(cutoff) {
					stale = append(stale, append([]byte(nil), k...))
				}
				return nil
			})
			if err != nil {
				return err
			}
			for _, k := range stale {
				if err := b.Delete(k); err != nil {
					return err
				}
				n++
			}
			return nil
		})
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
