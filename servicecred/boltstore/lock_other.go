//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package boltstore

import (
	"context"
	"errors"
	"fmt"
)

func platformLockSupported() bool { return false }

func ensureLockFiles(string) error {
	return fmt.Errorf("cross-process credential store locks are unavailable on this platform: %w", errors.ErrUnsupported)
}

func acquireLock(context.Context, string, bool) (func() error, error) {
	return nil, ensureLockFiles("")
}
