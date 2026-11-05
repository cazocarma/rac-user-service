package photoassets

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/cazocarma/rac-user-service/internal/photostore"
)

func TestPhotoQueuePostgres(t *testing.T) {
	dsn := os.Getenv("RAC_PHOTO_QUEUE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable photo processing database")
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Path != "/photo_processing" || (!strings.HasPrefix(u.Hostname(), "rac-migration-test-") && !strings.HasPrefix(u.Hostname(), "rac-photo-test-")) {
		t.Fatal("refusing non-disposable queue database")
	}
	root, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	exec := func(s string, args ...any) {
		t.Helper()
		if _, err := root.Exec(s, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`CREATE ROLE rac_photo_worker_fixture LOGIN PASSWORD 'synthetic-photo-worker-only';
 GRANT USAGE ON SCHEMA photo TO rac_photo_worker_fixture;
 GRANT EXECUTE ON FUNCTION photo.claim_processing(text,text,text),photo.complete_processing(uuid,uuid,text,text,text,text,bytea,int,jsonb,text,int) TO rac_photo_worker_fixture;`)
	u.User = url.UserPassword("rac_photo_worker_fixture", "synthetic-photo-worker-only")
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	q, err := NewPostgresQueue(ctx, db)
	if err != nil {
		t.Fatal("isolated worker refused", err)
	}
	if _, err := NewPostgresQueue(ctx, root); err == nil {
		t.Fatal("superuser accepted as worker")
	}
	for _, s := range []string{"SELECT * FROM photo.sources", "SELECT * FROM photo.processing_results", "UPDATE photo.processing_jobs SET completed=true", "DELETE FROM photo.processing_attempts", "SELECT * FROM public.usuario"} {
		if _, err := db.Exec(s); err == nil {
			t.Fatal("raw access granted", s)
		}
	}
	var subject string
	if err := root.QueryRow(`INSERT INTO usuario(id,nombre,correo,rol,keycloak_id) SELECT id,'Queue fixture',id::text||'@example.test','cliente',id::text FROM (SELECT gen_random_uuid() id) f RETURNING keycloak_id`).Scan(&subject); err != nil {
		t.Fatal(err)
	}
	seed := func(pipeline string, lease, max int, images ...Upload) (Upload, Release) {
		t.Helper()
		base := sourceFixture(t)
		if len(images) > 0 {
			base = images[0]
		}
		upload, err := Prepare(ctx, base.Bytes(), "image/png", pipeline)
		if err != nil {
			t.Fatal(err)
		}
		release := Release{Pipeline: pipeline, Commit: strings.Repeat("a", 40), ImageDigest: "sha256:" + strings.Repeat("b", 64)}
		exec(`INSERT INTO photo.processing_policies VALUES($1,$2,0,$3)`, pipeline, lease, max)
		exec(`INSERT INTO photo.processing_releases VALUES($1,$2,$3)`, pipeline, release.Commit, release.ImageDigest)
		tx, err := root.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		source, err := Reserve(ctx, tx, subject, upload)
		if err != nil {
			t.Fatal(err)
		}
		verified, err := Verify(ctx, readerFunc(func(context.Context, string) ([]byte, error) { return upload.Bytes(), nil }), source)
		if err != nil {
			t.Fatal(err)
		}
		if err := Confirm(ctx, tx, subject, verified); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		return upload, release
	}
	artifact := func(a Attempt, upload Upload) Artifact {
		t.Helper()
		p, err := NewProcessor(upload.Source().PipelineVersion(), ocrFunc(func(context.Context, []byte) (OCRResult, error) { return ocrFixture("CINE"), nil }), engineFixture(t))
		if err != nil {
			t.Fatal(err)
		}
		result, err := p.Process(ctx, a.Source, readerFunc(func(context.Context, string) ([]byte, error) { return upload.Bytes(), nil }))
		if err != nil {
			t.Fatal(err)
		}
		return Artifact{key: a.ObjectKey(), size: len(result.image), digest: result.digest, assessment: result.Assessment(), disposition: result.disposition, risk: result.risk}
	}
	mustClaim := func(r Release) *Attempt {
		t.Helper()
		a, err := q.Claim(ctx, r)
		if err != nil || a == nil {
			t.Fatal("claim failed", err)
		}
		return a
	}
	count := func() int {
		t.Helper()
		var n int
		if err := root.QueryRow(`SELECT count(*) FROM photo.processing_results`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	t.Run("concurrent-claim-replay-and-rollback", func(t *testing.T) {
		upload, r := seed("queue-concurrent-1", 30, 3)
		var wg sync.WaitGroup
		attempts := make(chan *Attempt, 8)
		failures := make(chan error, 8)
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				a, err := q.Claim(ctx, r)
				if err != nil {
					failures <- err
				}
				if a != nil {
					attempts <- a
				}
			}()
		}
		wg.Wait()
		close(attempts)
		close(failures)
		for err := range failures {
			t.Fatal(err)
		}
		var a *Attempt
		for at := range attempts {
			if a != nil {
				t.Fatal("two workers own one live job")
			}
			a = at
		}
		if a == nil {
			t.Fatal("no winner")
		}
		receipt := artifact(*a, upload)
		wrong := r
		wrong.Commit = strings.Repeat("c", 40)
		if err := q.Complete(ctx, *a, wrong, receipt); !errors.Is(err, ErrClaimLost) {
			t.Fatal("release mismatch accepted", err)
		}
		bad := receipt
		bad.key = strings.Repeat("d", 32) + ".jpg"
		if err := q.Complete(ctx, *a, r, bad); !errors.Is(err, ErrInvalid) {
			t.Fatal("wrong key accepted", err)
		}
		exec(`CREATE FUNCTION photo.fixture_result_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic rollback'; END $$;
  REVOKE ALL ON FUNCTION photo.fixture_result_fault() FROM PUBLIC;
  CREATE TRIGGER fixture_result_fault AFTER INSERT ON photo.processing_results FOR EACH ROW EXECUTE FUNCTION photo.fixture_result_fault();`)
		before := count()
		if err := q.Complete(ctx, *a, r, receipt); !errors.Is(err, ErrStorage) || count() != before {
			t.Fatal("failure did not roll back", err)
		}
		exec(`DROP TRIGGER fixture_result_fault ON photo.processing_results; DROP FUNCTION photo.fixture_result_fault();`)
		if err := q.Complete(ctx, *a, r, receipt); err != nil {
			t.Fatal(err)
		}
		if err := q.Complete(ctx, *a, r, receipt); err != nil || count() != before+1 {
			t.Fatal("lost ACK replay duplicated result", err)
		}
		changed := receipt
		changed.size++
		if err := q.Complete(ctx, *a, r, changed); !errors.Is(err, ErrIntegrity) {
			t.Fatal("changed replay accepted", err)
		}
		if a, err := q.Claim(ctx, r); a != nil || err != nil {
			t.Fatal("completed work reclaimed", err)
		}
	})
	t.Run("expiry-fencing-and-exhaustion", func(t *testing.T) {
		upload, r := seed("queue-expiry-1", 1, 2)
		a := mustClaim(r)
		receipt := artifact(*a, upload)
		exec(`SELECT pg_sleep(1.1)`)
		if err := q.Complete(ctx, *a, r, receipt); !errors.Is(err, ErrClaimLost) {
			t.Fatal("expired attempt accepted", err)
		}
		b := mustClaim(r)
		if a.ObjectKey() == b.ObjectKey() {
			t.Fatal("attempts reuse an object key")
		}
		if err := q.Complete(ctx, *a, r, receipt); !errors.Is(err, ErrClaimLost) {
			t.Fatal("stale completion accepted", err)
		}
		exec(`SELECT pg_sleep(1.1)`)
		if a, err := q.Claim(ctx, r); a != nil || err != nil {
			t.Fatal("retry budget exceeded", err)
		}
	})
	t.Run("commit-time-expiry", func(t *testing.T) {
		upload, r := seed("queue-commit-1", 1, 2)
		a := mustClaim(r)
		receipt := artifact(*a, upload)
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		id := a.ID[:8] + "-" + a.ID[8:12] + "-" + a.ID[12:16] + "-" + a.ID[16:20] + "-" + a.ID[20:]
		var applied bool
		if err := tx.QueryRow(`SELECT photo.complete_processing($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11)`, id, a.Source.ID(), r.Pipeline, r.Commit, r.ImageDigest, receipt.key, receipt.digest[:], receipt.size, string(receipt.assessment), receipt.disposition, receipt.risk).Scan(&applied); err != nil || !applied {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`SELECT pg_sleep(1.1)`); err != nil {
			t.Fatal(err)
		}
		before := count()
		if err := tx.Commit(); err == nil {
			t.Fatal("held completion committed after expiry")
		}
		if count() != before {
			t.Fatal("expired commit left a result")
		}
	})
	t.Run("completed-replay-after-expiry", func(t *testing.T) {
		upload, r := seed("queue-replay-expired-1", 1, 2)
		a := mustClaim(r)
		receipt := artifact(*a, upload)
		if err := q.Complete(ctx, *a, r, receipt); err != nil {
			t.Fatal(err)
		}
		before := count()
		exec(`SELECT pg_sleep(1.1)`)
		if err := q.Complete(ctx, *a, r, receipt); err != nil || count() != before {
			t.Fatal("committed receipt cannot be recovered after lease expiry", err)
		}
	})
	t.Run("privilege-drift", func(t *testing.T) {
		exec(`GRANT SELECT ON photo.processing_results TO rac_photo_worker_fixture`)
		if _, err := q.Claim(ctx, Release{Pipeline: "queue-concurrent-1", Commit: strings.Repeat("a", 40), ImageDigest: "sha256:" + strings.Repeat("b", 64)}); err == nil {
			t.Fatal("privilege drift ignored")
		}
		exec(`REVOKE SELECT ON photo.processing_results FROM rac_photo_worker_fixture`)
	})
	t.Run("rustfs-worker", func(t *testing.T) {
		endpoint := os.Getenv("RAC_PHOTO_PIPELINE_TEST_ENDPOINT")
		if endpoint == "" {
			t.Skip("requires disposable pipeline IAM fixture")
		}
		upload, r := seed("queue-rustfs-1", 60, 3, imageFixture(t, "contact_border"))
		ingest, err := photostore.NewQuarantineS3(endpoint, "us-east-1", os.Getenv("PHOTO_QUARANTINE_BUCKET"), os.Getenv("PHOTO_INGEST_ACCESS_KEY"), os.Getenv("PHOTO_INGEST_SECRET_KEY"))
		if err != nil {
			t.Fatal(err)
		}
		reader, err := photostore.NewQuarantineS3(endpoint, "us-east-1", os.Getenv("PHOTO_QUARANTINE_BUCKET"), os.Getenv("PHOTO_READER_ACCESS_KEY"), os.Getenv("PHOTO_READER_SECRET_KEY"))
		if err != nil {
			t.Fatal(err)
		}
		staging, err := photostore.NewS3(endpoint, "us-east-1", os.Getenv("PHOTO_STAGING_BUCKET"), os.Getenv("PHOTO_STAGING_ACCESS_KEY"), os.Getenv("PHOTO_STAGING_SECRET_KEY"))
		if err != nil {
			t.Fatal(err)
		}
		if err := ingest.Put(ctx, upload.Source().ObjectKey(), upload.Bytes()); err != nil {
			t.Fatal(err)
		}
		ocr, err := NewTesseract(ctx, "/usr/bin/tesseract", "/usr/share/tesseract-ocr/5/tessdata")
		if err != nil {
			t.Fatal("native OCR required for pipeline transport proof", err)
		}
		processor, err := NewProcessor(r.Pipeline, ocr, engineFixture(t))
		if err != nil {
			t.Fatal(err)
		}
		worker, err := NewWorker(q, reader, staging, processor, r)
		if err != nil {
			t.Fatal(err)
		}
		if claimed, err := worker.RunOnce(ctx); !claimed || err != nil {
			t.Fatal("real S3/database worker failed", err)
		}
		var key, disposition string
		var digest []byte
		if err := root.QueryRow(`SELECT object_key,disposition,normalized_sha256 FROM photo.processing_results WHERE asset_id=$1`, upload.Source().ID()).Scan(&key, &disposition, &digest); err != nil {
			t.Fatal(err)
		}
		bytes, err := staging.Get(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		actual := sha256.Sum256(bytes)
		if disposition != ContactCorrection || !slices.Equal(actual[:], digest) {
			t.Fatal("worker lost contact correction or verified artifact digest")
		}
	})
}
