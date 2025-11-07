package main

import (
	"database/sql"
	"log"
	"time"

	"github.com/cazocarma/rac-user-service/internal/config"
	httpapi "github.com/cazocarma/rac-user-service/internal/http"
	_ "github.com/lib/pq"
)

func main() {
	cfg := config.Get()

	var db *sql.DB
	var err error

	// Retry: espera a Postgres con backoff (hasta ~60s)
	for i := 0; i < 12; i++ {
		db, err = sql.Open("postgres", cfg.DatabaseURL)
		if err == nil {
			if pingErr := db.Ping(); pingErr == nil {
				break
			} else {
				err = pingErr
			}
		}
		wait := time.Duration(5*(i+1)) * time.Second
		log.Printf("[user-svc] waiting for postgres: %v (retry in %s)", err, wait)
		time.Sleep(wait)
	}
	if err != nil {
		log.Fatalf("[user-svc] cannot reach postgres: %v", err)
	}

	srv := httpapi.New(db)
	addr := ":" + cfg.Port
	log.Printf("user service listening on %s", addr)
	if err := srv.Router().Run(addr); err != nil {
		log.Fatal(err)
	}
}
