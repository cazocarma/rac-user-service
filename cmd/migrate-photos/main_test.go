package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"os"
	"testing"

	"github.com/cazocarma/rac-user-service/internal/photostore"
)

func TestCopyPhotosIntegrityAndRetry(t *testing.T) {
	dsn := os.Getenv("RAC_ONBOARDING_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable migrated DB")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var id string
	var random [16]byte
	_, _ = rand.Read(random[:])
	key := hex.EncodeToString(random[:]) + ".jpg"
	err = db.QueryRow(`INSERT INTO usuario(id,nombre,correo,rol,keycloak_id,foto_clave) VALUES(gen_random_uuid(),'Migration',$1,'cliente',gen_random_uuid()::text,$2) RETURNING id::text`, key+"@fixture.test", key).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Exec(`DELETE FROM usuario WHERE id=$1`, id)
	ctx := context.Background()
	source := photostore.Local{Directory: t.TempDir()}
	var target photostore.Store = photostore.Local{Directory: t.TempDir()}
	if os.Getenv("RAC_PHOTO_TEST_S3_ENDPOINT") != "" {
		target, err = photostore.NewS3(os.Getenv("RAC_PHOTO_TEST_S3_ENDPOINT"), "us-east-1", os.Getenv("PROFILE_S3_BUCKET"), os.Getenv("PROFILE_S3_ACCESS_KEY"), os.Getenv("PROFILE_S3_SECRET_KEY"))
		if err != nil {
			t.Fatal(err)
		}
	}
	defer target.Delete(ctx, key)
	// Missing reference must abort before activation.
	if _, err = migratePhotos(ctx, db, source, target); err == nil {
		t.Fatal("missing source accepted")
	}
	payload := []byte("normalized JPEG fixture")
	if err = source.Put(ctx, key, payload); err != nil {
		t.Fatal(err)
	}
	if copied, err := migratePhotos(ctx, db, source, target); err != nil || copied != 1 {
		t.Fatal("copy failed", copied, err)
	}
	if copied, err := migratePhotos(ctx, db, source, target); err != nil || copied != 0 {
		t.Fatal("retry failed", copied, err)
	}
	if raw, err := source.Get(ctx, key); err != nil || !bytes.Equal(raw, payload) {
		t.Fatal("source changed")
	}
	if err = target.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if err = target.Put(ctx, key, []byte("conflicting object")); err != nil {
		t.Fatal(err)
	}
	if _, err = migratePhotos(ctx, db, source, target); err == nil {
		t.Fatal("conflict overwritten")
	}
	if raw, err := target.Get(ctx, key); err != nil || string(raw) != "conflicting object" {
		t.Fatal("conflicting object changed")
	}
	var reference string
	if err = db.QueryRow(`SELECT foto_clave FROM usuario WHERE id=$1`, id).Scan(&reference); err != nil || reference != key {
		t.Fatal("DB reference changed")
	}
}
