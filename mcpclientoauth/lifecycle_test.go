package mcpclientoauth_test

import (
	"github.com/ajent-social/go/mcpclientoauth/internal/lifecycletest"
	"github.com/ajent-social/go/mcpclientoauth/memory"
	"testing"
)

func TestMemoryLifecycle(t *testing.T) { store := memory.New(); lifecycletest.Run(t, store, store) }
