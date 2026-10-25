package sqlstore_test

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/ajent-social/go/mcpclientoauth/internal/lifecycletest"
	"github.com/ajent-social/go/mcpclientoauth/sqlstore"
	_ "github.com/lib/pq"
)

func TestSQLLifecycle(t *testing.T) {
	dsn := os.Getenv("AMSL_SQLSTORE_TEST_DSN")
	if dsn == "" {
		if os.Getenv("AMSL_MCP_CLIENT_SQL_REQUIRED") != "" {
			t.Fatal("SQL qualification requested: AMSL_SQLSTORE_TEST_DSN is required")
		}
		t.Skip("SQL unqualified: set AMSL_SQLSTORE_TEST_DSN; memory tests are not SQL evidence")
	}
	open := func() *sqlstore.Store {
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s, err := sqlstore.Open(ctx, db)
		if err != nil {
			t.Fatalf("required SQL service failed: %v", err)
		}
		return s
	}
	// Separate database pools and adapter instances exercise database coordination.
	lifecycletest.Run(t, open(), open())
}
