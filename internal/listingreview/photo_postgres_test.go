package listingreview

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"image"
	"image/jpeg"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cazocarma/rac-user-service/internal/photostore"
)

type previewFixtureStore struct {
	get func(context.Context, string) ([]byte, error)
}

func (s previewFixtureStore) Get(ctx context.Context, key string) ([]byte, error) {
	return s.get(ctx, key)
}

// SQL setup proves the preview boundary, not OCR execution (the pipeline lab
// covers real native OCR and S3). No history trigger is disabled here.
func testPhotoPreviewPostgres(t *testing.T, root *sql.DB, s *Server, request func(string) *httptest.ResponseRecorder) {
	t.Helper()
	exec := func(statement string, args ...any) {
		t.Helper()
		if _, err := root.Exec(statement, args...); err != nil {
			t.Fatal(err)
		}
	}
	var encoded bytes.Buffer
	if err := jpeg.Encode(&encoded, image.NewRGBA(image.Rect(0, 0, 64, 48)), nil); err != nil {
		t.Fatal(err)
	}
	data := encoded.Bytes()
	digest := sha256.Sum256(data)
	const asset = "bbbbbbbb-0000-4000-8000-000000000001"
	const attempt = "cccccccc-0000-4000-8000-000000000001"
	const revision = "aaaaaaaa-0000-4000-8000-000000000001"
	const key = "cccccccc000040008000000000000001.jpg"
	const path = "/internal/listings/revisions/" + revision + "/photo"
	exec(`INSERT INTO photo.processing_policies VALUES('preview-fixture-1',600,0,3);
 INSERT INTO photo.processing_releases VALUES('preview-fixture-1',repeat('c',40),'sha256:'||repeat('d',64));
 INSERT INTO photo.sources(id,owner_user_id,object_key,source_sha256,source_size,declared_media_type,source_width,source_height,pipeline_version)
 VALUES('` + asset + `','22222222-2222-4222-8222-222222222222',replace('` + asset + `','-','')||'.raw',decode(repeat('00',32),'hex'),1,'image/png',64,48,'preview-fixture-1');
 INSERT INTO photo.upload_confirmations(asset_id,verified_sha256,verified_size) VALUES('` + asset + `',decode(repeat('00',32),'hex'),1);
 INSERT INTO photo.analysis_outbox(asset_id) VALUES('` + asset + `');
 INSERT INTO photo.processing_attempts(id,asset_id,attempt_no,pipeline_version,commit_sha,image_digest,created_at,expires_at)
 VALUES('` + attempt + `','` + asset + `',1,'preview-fixture-1',repeat('c',40),'sha256:'||repeat('d',64),clock_timestamp(),clock_timestamp()+interval '10 minutes');`)
	exec(`INSERT INTO photo.processing_results(asset_id,attempt_id,object_key,normalized_sha256,normalized_size,assessment,disposition,risk_score)
 VALUES('`+asset+`','`+attempt+`','`+key+`',decode($1,'hex'),$2,'{}','needs_review',0)`, hex.EncodeToString(digest[:]), len(data))
	exec(`UPDATE photo.processing_jobs SET attempts=1,active_attempt='` + attempt + `',completed=true WHERE asset_id='` + asset + `';
 INSERT INTO listing_revisions(id,listing_id,revision_no,payload_canonical,assessment,risk_score,policy_version)
 VALUES('` + revision + `','44444444-4444-4444-8444-444444444444',2,'{"photo_version":"` + asset + `"}','{}',0,'fixture-1');
 UPDATE listings SET pending_revision_id='` + revision + `',version=version+1 WHERE id='44444444-4444-4444-8444-444444444444';`)
	count := func() int {
		var n int
		if err := root.QueryRow(`SELECT count(*) FROM listing_review.access_events WHERE kind='photo'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	gets := 0
	reset := func() {
		s.now = time.Now
		s.SetPhotoPreview(previewFixtureStore{get: func(ctx context.Context, requested string) ([]byte, error) {
			gets++
			if requested != key {
				t.Fatalf("unbound object requested: %s", requested)
			}
			return bytes.Clone(data), nil
		}})
	}
	w := request(path)
	if w.Code != 503 || count() != 0 {
		t.Fatal("missing store fell back to another source", w.Code)
	}
	reset()
	w = request(path)
	if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), data) || w.Header().Get("Content-Type") != "image/jpeg" ||
		w.Header().Get("Cache-Control") != "no-store" || count() != 2 || gets != 1 {
		t.Fatal("preview missing exact bytes or two committed audit boundaries", w.Code, count(), gets)
	}
	for _, statement := range []string{`SELECT * FROM photo.processing_results`, `SELECT * FROM photo.listing_references`, `SELECT * FROM listing_review.access_events`} {
		if _, err := s.db.Exec(statement); err == nil {
			t.Fatal("reader obtained raw photo/audit access", statement)
		}
	}
	before := count()
	w = request("/internal/listings/revisions/55555555-5555-4555-8555-555555555555/photo")
	if w.Code != 404 || count() != before+1 || gets != 1 {
		t.Fatal("superseded or unbound photo resolved", w.Code)
	}
	before = count()
	s.SetPhotoPreview(previewFixtureStore{get: func(context.Context, string) ([]byte, error) { return append(bytes.Clone(data), 0), nil }})
	w = request(path)
	if w.Code != 503 || count() != before+1 || strings.Contains(w.Body.String(), key) {
		t.Fatal("corrupt object escaped", w.Code)
	}
	s.SetPhotoPreview(previewFixtureStore{get: func(context.Context, string) ([]byte, error) { return nil, errors.New("private driver diagnostic") }})
	w = request(path)
	if w.Code != 503 || strings.Contains(w.Body.String(), "diagnostic") {
		t.Fatal("storage error leaked", w.Code)
	}
	// Expiry while storage is being read must prevent the second audit/response.
	s.SetPhotoPreview(previewFixtureStore{get: func(context.Context, string) ([]byte, error) {
		s.now = func() time.Time { return time.Now().Add(24 * time.Hour) }
		return bytes.Clone(data), nil
	}})
	before = count()
	w = request(path)
	if w.Code < 400 || count() != before+1 || bytes.Contains(w.Body.Bytes(), data) {
		t.Fatal("expired staff session received photo", w.Code)
	}
	reset()
	s.SetPhotoPreview(previewFixtureStore{get: func(context.Context, string) ([]byte, error) {
		exec(`UPDATE listings SET pending_revision_id=NULL,version=version+1 WHERE id='44444444-4444-4444-8444-444444444444'`)
		return bytes.Clone(data), nil
	}})
	before = count()
	w = request(path)
	if w.Code != 404 || count() != before+2 {
		t.Fatal("revision changed during I/O but photo escaped", w.Code)
	}
	exec(`UPDATE listings SET pending_revision_id='` + revision + `',version=version+1 WHERE id='44444444-4444-4444-8444-444444444444'`)
	reset()
	// Inject an audit failure after storage I/O: no bytes may cross the boundary.
	s.SetPhotoPreview(previewFixtureStore{get: func(context.Context, string) ([]byte, error) {
		exec(`CREATE FUNCTION listing_review.preview_fixture_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic audit unavailable'; END $$;
 CREATE TRIGGER preview_fixture_failure BEFORE INSERT ON listing_review.access_events FOR EACH ROW EXECUTE FUNCTION listing_review.preview_fixture_failure();`)
		return bytes.Clone(data), nil
	}})
	before = count()
	w = request(path)
	if w.Code != 503 || count() != before+1 {
		t.Fatal("failed final audit released photo", w.Code)
	}
	exec(`DROP TRIGGER preview_fixture_failure ON listing_review.access_events; DROP FUNCTION listing_review.preview_fixture_failure();`)
	reset()
	// Bound simultaneous image buffers independently of the short SQL pool.
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	responses := make(chan *httptest.ResponseRecorder, 2)
	s.SetPhotoPreview(previewFixtureStore{get: func(ctx context.Context, requested string) ([]byte, error) {
		entered <- struct{}{}
		select {
		case <-release:
			return bytes.Clone(data), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}})
	for range 2 {
		go func() { responses <- request(path) }()
	}
	for range 2 {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent previews did not enter storage")
		}
	}
	w = request(path)
	if w.Code != 503 {
		t.Fatal("unbounded private photo reads", w.Code)
	}
	close(release)
	for range 2 {
		select {
		case response := <-responses:
			if response.Code != 200 || !bytes.Equal(response.Body.Bytes(), data) {
				t.Fatal("bounded preview failed", response.Code)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("preview slots not released")
		}
	}
	reset()
	if endpoint := os.Getenv("RAC_PHOTO_PIPELINE_TEST_ENDPOINT"); endpoint != "" {
		t.Run("rustfs-read-only", func(t *testing.T) {
			writer, err := photostore.NewS3(endpoint, "us-east-1", os.Getenv("PHOTO_STAGING_BUCKET"), os.Getenv("PHOTO_STAGING_ACCESS_KEY"), os.Getenv("PHOTO_STAGING_SECRET_KEY"))
			if err != nil {
				t.Fatal(err)
			}
			if err := writer.Put(context.Background(), key, data); err != nil {
				t.Fatal(err)
			}
			t.Setenv("RAC_ENV", "dev")
			t.Setenv("RAC_PHOTO_PREVIEW_ENABLED", "true")
			t.Setenv("RAC_PHOTO_S3_ENDPOINT", endpoint)
			t.Setenv("RAC_PHOTO_S3_REGION", "us-east-1")
			t.Setenv("RAC_PHOTO_STAGING_BUCKET", os.Getenv("PHOTO_STAGING_BUCKET"))
			t.Setenv("RAC_PHOTO_QUARANTINE_BUCKET", os.Getenv("PHOTO_QUARANTINE_BUCKET"))
			for _, part := range []string{"ACCESS_KEY", "SECRET_KEY"} {
				path := filepath.Join(t.TempDir(), "synthetic-secret")
				if err := os.WriteFile(path, []byte(os.Getenv("PHOTO_PREVIEW_"+part)+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("RAC_PHOTO_PREVIEW_"+part+"_FILE", path)
			}
			store, err := photoPreviewFromEnvironment()
			if err != nil || store == nil {
				t.Fatal("configured preview missing", err)
			}
			s.SetPhotoPreview(store)
			before := count()
			w := request(path)
			if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), data) || count() != before+2 {
				t.Fatal("real RustFS preview failed", w.Code, w.Body.String())
			}
		})
		reset()
	}
	var access, audit int
	if err := root.QueryRow(`SELECT (SELECT count(*) FROM listing_review.access_events),(SELECT count(*) FROM audit.log WHERE chain_id='88888888-8888-4888-8888-888888888888')`).Scan(&access, &audit); err != nil || access != audit {
		t.Fatal("preview access and chain diverged", access, audit, err)
	}
}
