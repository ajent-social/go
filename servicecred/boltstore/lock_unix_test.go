//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package boltstore

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestAcquireLockHonorsCancellation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.db")
	release, err := acquireLock(context.Background(), path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := release(); err != nil {
			t.Error(err)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := acquireLock(ctx, path, false)
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected cancellation, got %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("lock acquisition ignored cancellation")
	}
}
