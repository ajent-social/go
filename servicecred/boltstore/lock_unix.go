//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package boltstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// acquireLock gives pending writers priority over later readers. Readers hold
// a shared intent lock only until they hold the gate; a writer then holds the
// intent exclusively while draining existing readers and updating bbolt.
func acquireLock(ctx context.Context, path string, write bool) (func() error, error) {
	intent, err := openLock(path + ".intent")
	if err != nil {
		return nil, err
	}
	gate, err := openLock(path + ".gate")
	if err != nil {
		return nil, errors.Join(err, intent.Close())
	}
	closeFiles := func() error { return errors.Join(intent.Close(), gate.Close()) }
	intentOp, gateOp := unix.LOCK_SH, unix.LOCK_SH
	if write {
		intentOp, gateOp = unix.LOCK_EX, unix.LOCK_EX
	}
	if err := lockFile(ctx, intent, intentOp); err != nil {
		return nil, errors.Join(err, closeFiles())
	}
	if err := lockFile(ctx, gate, gateOp); err != nil {
		return nil, errors.Join(err, unlock(intent), closeFiles())
	}
	if !write {
		if err := unlock(intent); err != nil {
			return nil, errors.Join(err, unlock(gate), closeFiles())
		}
	}
	return func() error {
		if write {
			return errors.Join(unlock(gate), unlock(intent), closeFiles())
		}
		return errors.Join(unlock(gate), closeFiles())
	}, nil
}

func openLock(path string) (*os.File, error) {
	if fi, err := os.Lstat(path); err == nil {
		if !fi.Mode().IsRegular() || fi.Mode().Perm()&0077 != 0 {
			return nil, fmt.Errorf("lock file must be a private regular file: %s", filepath.Base(path))
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect lock file: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0077 != 0 {
		return nil, errors.Join(fmt.Errorf("lock file must be a private regular file"), err, f.Close())
	}
	return f, nil
}

func lockFile(ctx context.Context, f *os.File, op int) error {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		if err := unix.Flock(int(f.Fd()), op|unix.LOCK_NB); err == nil {
			return nil
		} else if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
			return fmt.Errorf("lock credential store: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			timer.Reset(2 * time.Millisecond)
		}
	}
}

func unlock(f *os.File) error {
	if err := unix.Flock(int(f.Fd()), unix.LOCK_UN); err != nil {
		return fmt.Errorf("unlock credential store: %w", err)
	}
	return nil
}
