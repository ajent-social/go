//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package boltstore

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestOpenReportsUnsupportedPlatform(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.db")
	if _, err := Open(context.Background(), path); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("want errors.ErrUnsupported on this platform, got %v", err)
	}
}
