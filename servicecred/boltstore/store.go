// Package boltstore persists service credentials in bbolt on a local filesystem
// on platforms with Unix flock support.
// Derived from the bbolt credential-storage pattern in zerfoo/zerfoo,
// serve/security/apikey_bbolt.go (Apache-2.0), moved to this path in
// https://github.com/zerfoo/zerfoo/blob/51ab5efe2a78534bcb5da19ee6df98dddd2e633c/serve/security/apikey_bbolt.go;
// see docs/provenance-servicecred.md.
// Changes: atomic create/revoke, exact bindings, explicit errors, scoped metadata
// listing, per-operation locking and fail-closed missing/corrupt storage.
package boltstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ajent-social/go/servicecred"
	bolt "go.etcd.io/bbolt"
)

var bucket = []byte("amsl-service-credentials-v1")

// Store opens the DB for each operation. Sidecar locks coordinate adapter
// transactions before bbolt access; this adapter is for modest-volume local
// filesystems, not distributed storage.
type Store struct{ path string }

// Open explicitly initializes storage if absent. It never resets existing data.
// The parent must be a private directory controlled by the application account.
func Open(ctx context.Context, path string) (*Store, error) {
	if path == "" {
		return nil, servicecred.ErrInvalid
	}
	if !platformLockSupported() {
		return nil, fmt.Errorf("cross-process credential store locks are unavailable on this platform: %w", errors.ErrUnsupported)
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve credential database path: %w", err)
	}
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("check credential directory: %w", err)
	}
	if !parent.IsDir() || parent.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("credential directory must be private")
	}
	s := &Store{path: path}
	if _, statErr := os.Lstat(path); statErr == nil {
		if err = ensureLockFiles(path); err == nil {
			err = s.transaction(ctx, false, false, func(b *bolt.Bucket) error { return nil })
		}
	} else if errors.Is(statErr, os.ErrNotExist) {
		err = s.transaction(ctx, true, true, func(b *bolt.Bucket) error { return nil })
	} else {
		err = fmt.Errorf("check credential database: %w", statErr)
	}
	if err != nil {
		return nil, err
	}
	return s, nil
}
func (s *Store) transaction(ctx context.Context, write, initialize bool, fn func(*bolt.Bucket) error) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	release, err := acquireLock(ctx, s.path, write)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, release()) }()
	fi, statErr := os.Lstat(s.path)
	if statErr != nil && !(initialize && errors.Is(statErr, os.ErrNotExist)) {
		return fmt.Errorf("check credential database: %w", statErr)
	}
	if statErr == nil && (!fi.Mode().IsRegular() || fi.Mode().Perm()&0077 != 0) {
		return fmt.Errorf("credential database must be a private regular file")
	}
	timeout := time.Second
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < timeout {
		timeout = time.Until(deadline)
		if timeout <= 0 {
			return context.DeadlineExceeded
		}
	}
	db, err := bolt.Open(s.path, 0600, &bolt.Options{Timeout: timeout, ReadOnly: !write})
	if err != nil {
		return fmt.Errorf("open credential database: %w", err)
	}
	defer func() { err = errors.Join(err, db.Close()) }()
	run := func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket(bucket)
		if b == nil && initialize {
			var err error
			b, err = tx.CreateBucket(bucket)
			if err != nil {
				return err
			}
		}
		if b == nil {
			return fmt.Errorf("credential database schema missing")
		}
		return fn(b)
	}
	if write {
		return db.Update(run)
	}
	return db.View(run)
}
func (s *Store) Create(ctx context.Context, r servicecred.Record) error {
	data, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("encode credential: %w", err)
	}
	return s.transaction(ctx, true, false, func(b *bolt.Bucket) error {
		if b.Get([]byte(r.ID)) != nil {
			return servicecred.ErrExists
		}
		return b.Put([]byte(r.ID), data)
	})
}
func (s *Store) Lookup(ctx context.Context, id string) (r servicecred.Record, err error) {
	err = s.transaction(ctx, false, false, func(b *bolt.Bucket) error {
		data := b.Get([]byte(id))
		if data == nil {
			return servicecred.ErrNotFound
		}
		if err := json.Unmarshal(data, &r); err != nil {
			return fmt.Errorf("decode credential record: %w", err)
		}
		if r.ID != id {
			return fmt.Errorf("credential ID mismatch")
		}
		return nil
	})
	return
}
func (s *Store) Revoke(ctx context.Context, id, owner, resource string, at time.Time) error {
	if at.IsZero() {
		return servicecred.ErrInvalid
	}
	return s.transaction(ctx, true, false, func(b *bolt.Bucket) error {
		data := b.Get([]byte(id))
		if data == nil {
			return servicecred.ErrNotFound
		}
		var r servicecred.Record
		if err := json.Unmarshal(data, &r); err != nil {
			return fmt.Errorf("decode credential record: %w", err)
		}
		if r.ID != id || r.Owner != owner || r.Resource != resource {
			return servicecred.ErrNotFound
		}
		if !r.RevokedAt.IsZero() {
			return nil
		}
		r.RevokedAt = at
		data, err := json.Marshal(r)
		if err != nil {
			return fmt.Errorf("encode revocation: %w", err)
		}
		return b.Put([]byte(id), data)
	})
}

// List returns metadata for an exact authorized owner/resource, including revoked
// records. The caller must authorize this administrative access before calling.
func (s *Store) List(ctx context.Context, owner, resource string) (out []servicecred.Metadata, err error) {
	if owner == "" || resource == "" {
		return nil, servicecred.ErrInvalid
	}
	out = []servicecred.Metadata{}
	err = s.transaction(ctx, false, false, func(b *bolt.Bucket) error {
		return b.ForEach(func(k, v []byte) error {
			var r servicecred.Record
			if err := json.Unmarshal(v, &r); err != nil {
				return fmt.Errorf("decode credential metadata: %w", err)
			}
			if string(k) != r.ID {
				return fmt.Errorf("credential ID mismatch")
			}
			if r.Owner == owner && r.Resource == resource {
				out = append(out, r.Metadata)
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return
}
