package main

import (
	"database/sql"
	"log"
	"net/http"
	"time"

	"github.com/cazocarma/rac-user-service/internal/config"
	httpapi "github.com/cazocarma/rac-user-service/internal/http"
	"github.com/cazocarma/rac-user-service/internal/photostore"
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

	store, err := photostore.FromEnvironment()
	if err != nil {
		log.Fatal("invalid profile photo storage configuration")
	}
	srv := httpapi.New(db, cfg)
	srv.SetPhotoStore(store)
	addr := ":" + cfg.Port
	log.Printf("user service listening on %s", addr)
	server := &http.Server{Addr: addr, Handler: srv.Router(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
