package photoassets

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/cazocarma/rac-user-service/internal/photostore"
	_ "github.com/lib/pq"
)

func TestPhotoSourcePostgres(t *testing.T) {
	dsn := os.Getenv("RAC_PHOTO_ASSET_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable photo source database")
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Path != "/photo_sources" || (!strings.HasPrefix(u.Hostname(), "rac-migration-test-") && !strings.HasPrefix(u.Hostname(), "rac-photo-test-")) {
		t.Fatal("refusing non-disposable photo source database")
	}
	mode := "memory"
	if os.Getenv("RAC_PHOTO_CREATE_TEST_ENDPOINT") != "" {
		mode = "s3"
	}
	t.Run(mode, func(t *testing.T) { testPhotoSourcePostgres(t, u) })
}

func testPhotoSourcePostgres(t *testing.T, u *url.URL) {
	root, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	q := u.Query()
	q.Set("options", "-c role=rac_user")
	scoped := *u
	scoped.RawQuery = q.Encode()
	db, err := sql.Open("postgres", scoped.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var actor string
	if err := db.QueryRow(`SELECT current_user`).Scan(&actor); err != nil || actor != "rac_user" {
		t.Fatal("photo proof is not using its real owner role")
	}
	var subject string
	if err := db.QueryRow(`INSERT INTO usuario(id,nombre,correo,rol,keycloak_id) SELECT id,'Photo source fixture',id::text||'@example.test','cliente',id::text FROM (SELECT gen_random_uuid() AS id) f RETURNING keycloak_id`).Scan(&subject); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	reserve := func(upload Upload) Source {
		t.Helper()
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		source, err := Reserve(ctx, tx, subject, upload)
		if err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
		return source
	}
	upload := sourceFixture(t)
	source := reserve(upload)
	if retry := reserve(upload); retry != source {
		t.Fatal("reservation retry changed source")
	}
	// A DB rollback cannot leave a source that the upload path might expose.
	discarded := sourceFixture(t)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Reserve(ctx, tx, subject, discarded); err != nil {
		t.Fatal(err)
	}
	tx.Rollback()
	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Load(ctx, tx, subject, discarded.Source().ID()); !errors.Is(err, ErrNotFound) {
		t.Fatal("rolled-back source persisted", err)
	}
	tx.Rollback()
	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Load(ctx, tx, "other-owner", source.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatal("other owner can select private source", err)
	}
	tx.Rollback()
	reader := Reader(readerFunc(func(context.Context, string) ([]byte, error) { return upload.Bytes(), nil }))
	if endpoint := os.Getenv("RAC_PHOTO_CREATE_TEST_ENDPOINT"); endpoint != "" {
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed.Hostname() != "photo-storage-fixture" || parsed.Scheme != "http" || parsed.Port() != "9000" {
			t.Fatal("refusing non-disposable quarantine store")
		}
		quarantine, err := photostore.NewQuarantineS3(endpoint, "us-east-1", os.Getenv("PROFILE_S3_BUCKET"), os.Getenv("PROFILE_S3_ACCESS_KEY"), os.Getenv("PROFILE_S3_SECRET_KEY"))
		if err != nil {
			t.Fatal(err)
		}
		if err := quarantine.Put(ctx, source.ObjectKey(), upload.Bytes()); err != nil {
			t.Fatal(err)
		}
		if err := quarantine.Put(ctx, source.ObjectKey(), []byte("replacement")); !errors.Is(err, photostore.ErrExists) {
			t.Fatal("quarantine key overwritten", err)
		}
		if err := quarantine.Put(ctx, "../outside.raw", upload.Bytes()); err == nil {
			t.Fatal("unsafe quarantine key accepted")
		}
		reader = quarantine
	}
	verified, err := Verify(ctx, reader, source)
	if err != nil {
		t.Fatal(err)
	}
	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Confirm(ctx, tx, "other-owner", verified); !errors.Is(err, ErrNotFound) {
		t.Fatal("another owner confirmed source", err)
	}
	tx.Rollback()
	count := func(table, id string) int {
		t.Helper()
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM photo.`+table+` WHERE asset_id=$1`, id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Confirm(ctx, tx, subject, verified); err != nil {
		t.Fatal(err)
	}
	tx.Rollback()
	if count("upload_confirmations", source.ID()) != 0 || count("analysis_outbox", source.ID()) != 0 {
		t.Fatal("rollback left a confirmation or analysis intent")
	}
	// Two owner instances retry the same confirmed bytes: exactly one durable
	// confirmation and one analysis intent, even if both ACK successfully.
	outcomes := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tx, err := db.BeginTx(ctx, nil)
			if err == nil {
				defer tx.Rollback()
				err = Confirm(ctx, tx, subject, verified)
				if err == nil {
					err = tx.Commit()
				}
			}
			outcomes <- err
		}()
	}
	wg.Wait()
	close(outcomes)
	for err := range outcomes {
		if err != nil {
			t.Fatal(err)
		}
	}
	if count("upload_confirmations", source.ID()) != 1 || count("analysis_outbox", source.ID()) != 1 {
		t.Fatal("duplicate analysis work from concurrent retry")
	}
	var private bool
	if err := db.QueryRow(`SELECT foto_clave IS NULL AND NOT EXISTS(SELECT FROM compa_perfil WHERE usuario_id=u.id) FROM usuario u WHERE keycloak_id=$1`, subject).Scan(&private); err != nil || !private {
		t.Fatal("source confirmation published or replaced a personal photo", err)
	}
	for _, statement := range []string{
		`UPDATE photo.sources SET pipeline_version='changed'`,
		`DELETE FROM photo.sources`,
		`UPDATE photo.upload_confirmations SET verified_size=1`,
		`DELETE FROM photo.analysis_outbox`,
	} {
		if _, err := root.Exec(statement); err == nil {
			t.Fatal("owner could rewrite ordinary photo history")
		}
	}
	// The composite FK rejects a forged verification even through direct SQL.
	second := reserve(sourceFixture(t))
	if _, err := db.Exec(`INSERT INTO photo.upload_confirmations(asset_id,verified_sha256,verified_size) VALUES($1,decode(repeat('00',32),'hex'),$2)`, second.ID(), second.Size()); err == nil {
		t.Fatal("forged object digest accepted")
	}
	// Inject failure after verification INSERT: the entire confirmation must roll
	// back, not leave a source marked ready without an analysis intent.
	if _, err := root.Exec(`CREATE FUNCTION public.photo_source_outbox_fault() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN RAISE EXCEPTION 'synthetic outbox failure'; END $$;
 REVOKE ALL ON FUNCTION public.photo_source_outbox_fault() FROM PUBLIC;
 CREATE TRIGGER photo_source_outbox_fault BEFORE INSERT ON photo.analysis_outbox FOR EACH ROW EXECUTE FUNCTION public.photo_source_outbox_fault();`); err != nil {
		t.Fatal(err)
	}
	secondUpload := sourceFixture(t)
	second = reserve(secondUpload)
	secondVerified, err := Verify(ctx, readerFunc(func(context.Context, string) ([]byte, error) { return secondUpload.Bytes(), nil }), second)
	if err != nil {
		t.Fatal(err)
	}
	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Confirm(ctx, tx, subject, secondVerified); !errors.Is(err, ErrStorage) {
		t.Fatal("outbox fault accepted", err)
	}
	tx.Rollback()
	if count("upload_confirmations", second.ID()) != 0 || count("analysis_outbox", second.ID()) != 0 {
		t.Fatal("outbox failure retained partial confirmation")
	}
}
