//go:build !aix && !darwin && !dragonfly && !freebsd && !illumos && !linux && !netbsd && !openbsd && !solaris

package boltstore

import (
	"context"
	"errors"
	"fmt"
)

func acquireLock(context.Context, string, bool) (func() error, error) {
	return nil, fmt.Errorf("writer-priority credential store locks are unavailable on this platform: %w", errors.ErrUnsupported)
}
