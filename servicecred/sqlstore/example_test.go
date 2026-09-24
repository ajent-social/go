package sqlstore_test

import (
	"context"
	"database/sql"
	"log"

	"github.com/ajent-social/go/servicecred"
	"github.com/ajent-social/go/servicecred/sqlstore"
	_ "github.com/lib/pq"
)

// ExampleOpen shows opening a Store against any PostgreSQL-compatible *sql.DB
// (PostgreSQL, SereneDB, …). Swap backends by changing the driver and DSN.
func ExampleOpen() {
	db, err := sql.Open("postgres", "host=/tmp dbname=amsl_servicecred_test sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	store, err := sqlstore.Open(context.Background(), db)
	if err != nil {
		log.Fatal(err)
	}
	_, err = servicecred.New(store)
	if err != nil {
		log.Fatal(err)
	}
}
