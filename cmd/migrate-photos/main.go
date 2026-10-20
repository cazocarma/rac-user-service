// migrate-photos copies referenced local photos to S3 and verifies their bytes.
// Keep the user service stopped until this command and activation finish.
package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"log"
	"os"
	"time"

	"github.com/cazocarma/rac-user-service/internal/photostore"
	_ "github.com/lib/pq"
)

func migratePhotos(ctx context.Context, db *sql.DB, source, target photostore.Store) (copied int, err error) {
	if err = target.Check(ctx); err != nil {
		return 0, errors.New("target bucket unavailable")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, errors.New("migration transaction failed")
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock_shared(726224,1)`); err != nil {
		return 0, errors.New("photo migration blocked by backup or cancelled")
	}
	rows, err := tx.QueryContext(ctx, `SELECT foto_clave FROM usuario WHERE foto_clave IS NOT NULL ORDER BY id FOR UPDATE`)
	if err != nil {
		return 0, errors.New("could not lock photo references")
	}
	var keys []string
	for rows.Next() {
		var key string
		if err = rows.Scan(&key); err != nil {
			rows.Close()
			return 0, errors.New("invalid photo reference")
		}
		keys = append(keys, key)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, errors.New("could not read photo references")
	}
	for _, key := range keys {
		raw, err := source.Get(ctx, key)
		if err != nil {
			return copied, errors.New("referenced source photo missing or unreadable; activation aborted")
		}
		existing, err := target.Get(ctx, key)
		if errors.Is(err, photostore.ErrNotFound) {
			if err = target.Put(ctx, key, raw); err != nil {
				return copied, errors.New("photo copy failed; source preserved")
			}
			copied++
		} else if err != nil {
			return copied, errors.New("target verification failed")
		} else if !bytes.Equal(raw, existing) {
			return copied, errors.New("target conflict; object not overwritten")
		}
		check, err := target.Get(ctx, key)
		if err != nil || !bytes.Equal(raw, check) {
			return copied, errors.New("integrity verification failed")
		}
	}
	if err = tx.Commit(); err != nil {
		return copied, errors.New("migration transaction failed")
	}
	return copied, nil
}
func main() {
	if os.Getenv("PROFILE_PHOTO_STORAGE") != "s3" {
		log.Fatal("migration requires S3 target")
	}
	target, err := photostore.FromEnvironment()
	if err != nil {
		log.Fatal("invalid S3 configuration")
	}
	db, err := sql.Open("postgres", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal("database configuration failed")
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	copied, err := migratePhotos(ctx, db, photostore.Local{Directory: os.Getenv("PROFILE_PHOTO_DIR")}, target)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("photo migration verified: copied=%d; source preserved", copied)
}
