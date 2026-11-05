package httpapi

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/png"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cazocarma/rac-platform/contentsignals"
	"github.com/cazocarma/rac-platform/standing"
	"github.com/cazocarma/rac-user-service/internal/config"
	"github.com/cazocarma/rac-user-service/internal/photoassets"
	"github.com/cazocarma/rac-user-service/internal/photostore"
	"github.com/cazocarma/rac-user-service/internal/platform"
	"github.com/gin-gonic/gin"
)

type privateSourceMemory struct {
	mu       sync.Mutex
	objects  map[string][]byte
	puts     int
	afterPut func() error
}

func (m *privateSourceMemory) Put(ctx context.Context, key string, raw []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	m.puts++
	if _, ok := m.objects[key]; ok {
		m.mu.Unlock()
		return photostore.ErrExists
	}
	m.objects[key] = slices.Clone(raw)
	hook := m.afterPut
	m.mu.Unlock()
	if hook != nil {
		return hook()
	}
	return nil
}
func (m *privateSourceMemory) Get(ctx context.Context, key string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	raw, ok := m.objects[key]
	if !ok {
		return nil, photostore.ErrNotFound
	}
	return slices.Clone(raw), nil
}

type photoStandingSource struct{ version atomic.Uint64 }

func (p *photoStandingSource) Load(context.Context, string) (standing.Snapshot, error) {
	version := p.version.Load()
	status := standing.Active
	if version > 1 {
		status = standing.Suspended
	}
	return standing.Snapshot{Version: version, Status: status, ObservedAt: time.Now()}, nil
}
func (p *photoStandingSource) LatestVersion(context.Context, string) (uint64, error) {
	return p.version.Load(), nil
}

func TestPrivatePhotoUploadsPostgresHTTP(t *testing.T) {
	dsn := os.Getenv("RAC_PHOTO_UPLOAD_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable private upload database")
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Path != "/photo_uploads" || (!strings.HasPrefix(u.Hostname(), "rac-migration-test-") && !strings.HasPrefix(u.Hostname(), "rac-photo-test-")) {
		t.Fatal("refusing non-disposable private upload database")
	}
	root, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	options := u.Query()
	options.Set("options", "-c role=rac_user")
	u.RawQuery = options.Encode()
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	t.Setenv("STANDING_ENFORCEMENT_ENABLED", "false")
	t.Setenv("DOCUMENTS_ENFORCEMENT_ENABLED", "false")
	picture := func(red uint8) []byte {
		t.Helper()
		var b bytes.Buffer
		im := image.NewRGBA(image.Rect(0, 0, 64, 48))
		im.Set(0, 0, color.RGBA{R: red, A: 255})
		if err := png.Encode(&b, im); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	raw, changed := picture(10), picture(20)
	uuid := func() string {
		t.Helper()
		var id string
		if err := root.QueryRow(`SELECT gen_random_uuid()::text`).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	type fixture struct {
		s            *Server
		r            *gin.Engine
		owner, other string
		store        *privateSourceMemory
	}
	fresh := func(max int) fixture {
		t.Helper()
		owner, other := uuid(), uuid()
		for _, subject := range []string{owner, other} {
			if _, err := db.Exec(`INSERT INTO usuario(id,nombre,correo,rol,keycloak_id) VALUES(gen_random_uuid(),'Upload fixture',$1,'cliente',$2)`, subject+"@example.test", subject); err != nil {
				t.Fatal(err)
			}
		}
		store := &privateSourceMemory{objects: map[string][]byte{}}
		s := New(db, config.Config{})
		s.security = &platform.Security{VerifyToken: func(_ context.Context, token string) (*platform.Claims, error) {
			subject := owner
			if token == "other" {
				subject = other
			}
			p := &platform.Claims{Subject: subject}
			p.RealmAccess.Roles = []string{"cliente"}
			return p, nil
		}}
		if err := s.SetPrivatePhotoUploads(store, photoassets.UploadPolicy{Pipeline: "owner-api-fixture-1", MaxPerDay: max}); err != nil {
			t.Fatal(err)
		}
		return fixture{s: s, r: s.Router(), owner: owner, other: other, store: store}
	}
	send := func(f fixture, method, path, token, key, media string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		if media != "" {
			req.Header.Set("Content-Type", media)
		}
		w := httptest.NewRecorder()
		f.r.ServeHTTP(w, req)
		return w
	}
	decode := func(w *httptest.ResponseRecorder, status int) map[string]any {
		t.Helper()
		if w.Code != status {
			t.Fatalf("expected %d got %d %s", status, w.Code, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("private source response cacheable")
		}
		var result map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	count := func(table, subject string) int {
		t.Helper()
		var n int
		query := `SELECT count(*) FROM photo.` + table + ` x JOIN photo.sources s ON s.id=x.asset_id JOIN usuario u ON u.id=s.owner_user_id WHERE u.keycloak_id=$1`
		if table == "sources" {
			query = `SELECT count(*) FROM photo.sources s JOIN usuario u ON u.id=s.owner_user_id WHERE u.keycloak_id=$1`
		}
		if err := root.QueryRow(query, subject).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	t.Run("ownership-idempotency-redaction", func(t *testing.T) {
		f := fresh(3)
		capabilities := decode(send(f, "GET", "/api/user/me/photo-upload-config", "own", "", "", nil), 200)
		if capabilities["enabled"] != true || capabilities["max_bytes"] != float64(5*1024*1024) {
			t.Fatal("upload capabilities mismatch", capabilities)
		}
		key := uuid()
		if w := send(f, "POST", "/api/user/me/photo-sources", "", key, "image/png", raw); w.Code != 401 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("anonymous upload accepted or authentication response cacheable")
		}
		first := decode(send(f, "POST", "/api/user/me/photo-sources", "own", key, "image/png", raw), 202)
		id := first["asset_id"].(string)
		if first["status"] != "queued" || len(first) != 2 {
			t.Fatal("invalid/private upload receipt", first)
		}
		second := decode(send(f, "POST", "/api/user/me/photo-sources", "own", key, "image/png", raw), 202)
		if second["asset_id"] != id || count("sources", f.owner) != 1 || count("analysis_outbox", f.owner) != 1 {
			t.Fatal("retry duplicated upload or work")
		}
		decode(send(f, "POST", "/api/user/me/photo-sources", "own", key, "image/png", changed), 409)
		// Request IDs are scoped to the owner; another account cannot probe reuse.
		other := decode(send(f, "POST", "/api/user/me/photo-sources", "other", key, "image/png", raw), 202)
		if other["asset_id"] == id {
			t.Fatal("request id crossed owners")
		}
		decode(send(f, "GET", "/api/user/me/photo-sources/"+id, "other", "", "", nil), 404)
		decode(send(f, "POST", "/api/user/me/photo-sources/"+id+"/confirm", "other", "", "", nil), 404)
		status := decode(send(f, "GET", "/api/user/me/photo-sources/"+id, "own", "", "", nil), 200)
		if len(status) != 2 || status["status"] != "queued" {
			t.Fatal("private processing metadata leaked", status)
		}
		for _, forbidden := range []string{"object_key", "sha256", "assessment", "risk", "signals", "reviewer"} {
			if strings.Contains(privatePhotoJSON(status), forbidden) {
				t.Fatal("private status leaked", forbidden)
			}
		}
		if w := send(f, "GET", "/api/user/media/profile/"+strings.ReplaceAll(id, "-", "")+".raw", "", "", "", nil); w.Code != 404 {
			t.Fatal("quarantine served as public avatar")
		}
		decode(send(f, "POST", "/api/user/me/photo-sources/"+id+"/confirm", "own", "", "", []byte("{}")), 400)
		decode(send(f, "GET", "/api/user/me/photo-sources/not-a-uuid", "own", "", "", nil), 400)
		var exposed bool
		if err := db.QueryRow(`SELECT foto_clave IS NOT NULL FROM usuario WHERE keycloak_id=$1`, f.owner).Scan(&exposed); err != nil || exposed {
			t.Fatal("private upload changed public photo", err)
		}
	})
	t.Run("lost-object-ack-and-recovery", func(t *testing.T) {
		f := fresh(1)
		key := uuid()
		f.store.afterPut = func() error { return errors.New("synthetic lost storage ACK") }
		receipt := decode(send(f, "POST", "/api/user/me/photo-sources", "own", key, "image/png", raw), 503)
		id := receipt["asset_id"].(string)
		byRequest := decode(send(f, "GET", "/api/user/me/photo-upload-requests/"+key, "own", "", "", nil), 200)
		if byRequest["asset_id"] != id {
			t.Fatal("lost HTTP response cannot recover request")
		}
		if count("analysis_outbox", f.owner) != 0 {
			t.Fatal("unverified write queued analysis")
		}
		decode(send(f, "GET", "/api/user/me/photo-sources/"+id, "own", "", "", nil), 200)
		// Same request succeeds despite the full quota and uncertain original Put.
		retried := decode(send(f, "POST", "/api/user/me/photo-sources", "own", key, "image/png", raw), 202)
		if retried["asset_id"] != id || count("sources", f.owner) != 1 || count("analysis_outbox", f.owner) != 1 {
			t.Fatal("lost ACK recovery was not idempotent")
		}
		decode(send(f, "POST", "/api/user/me/photo-sources/"+id+"/confirm", "own", "", "", nil), 202)
	})
	t.Run("quota-across-instances", func(t *testing.T) {
		f := fresh(1)
		second := New(db, config.Config{})
		second.security = f.s.security
		if err := second.SetPrivatePhotoUploads(f.store, photoassets.UploadPolicy{Pipeline: "owner-api-fixture-1", MaxPerDay: 1}); err != nil {
			t.Fatal(err)
		}
		other := f
		other.r = second.Router()
		keys := []string{uuid(), uuid()}
		var wg sync.WaitGroup
		codes := make(chan int, 2)
		for i, g := range []fixture{f, other} {
			wg.Add(1)
			go func(f fixture, key string) {
				defer wg.Done()
				codes <- send(f, "POST", "/api/user/me/photo-sources", "own", key, "image/png", raw).Code
			}(g, keys[i])
		}
		wg.Wait()
		close(codes)
		accepted, denied := 0, 0
		for c := range codes {
			if c == 202 {
				accepted++
			} else if c == 429 {
				denied++
			} else {
				t.Fatal("unexpected concurrent status", c)
			}
		}
		if accepted != 1 || denied != 1 || count("sources", f.owner) != 1 {
			t.Fatal("concurrent upload quota bypassed", accepted, denied)
		}
	})
	t.Run("confirmation-fault-and-retry", func(t *testing.T) {
		f := fresh(2)
		if _, err := root.Exec(`CREATE FUNCTION photo.confirm_fixture_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic confirmation fault'; END $$;
   REVOKE ALL ON FUNCTION photo.confirm_fixture_fault() FROM PUBLIC;
   CREATE TRIGGER confirm_fixture_fault AFTER INSERT ON photo.analysis_outbox FOR EACH ROW EXECUTE FUNCTION photo.confirm_fixture_fault();`); err != nil {
			t.Fatal(err)
		}
		defer root.Exec(`DROP TRIGGER IF EXISTS confirm_fixture_fault ON photo.analysis_outbox; DROP FUNCTION IF EXISTS photo.confirm_fixture_fault();`)
		receipt := decode(send(f, "POST", "/api/user/me/photo-sources", "own", uuid(), "image/png", raw), 503)
		id := receipt["asset_id"].(string)
		if count("sources", f.owner) != 1 || count("analysis_outbox", f.owner) != 0 || count("upload_confirmations", f.owner) != 0 {
			t.Fatal("partial confirmation escaped rollback")
		}
		if _, err := root.Exec(`DROP TRIGGER confirm_fixture_fault ON photo.analysis_outbox; DROP FUNCTION photo.confirm_fixture_fault();`); err != nil {
			t.Fatal(err)
		}
		decode(send(f, "POST", "/api/user/me/photo-sources/"+id+"/confirm", "own", "", "", nil), 202)
		if count("analysis_outbox", f.owner) != 1 || count("upload_confirmations", f.owner) != 1 {
			t.Fatal("confirmation recovery failed")
		}
	})
	t.Run("readback-integrity-cannot-confirm", func(t *testing.T) {
		f := fresh(2)
		f.store.afterPut = func() error { return errors.New("synthetic lost ACK") }
		receipt := decode(send(f, "POST", "/api/user/me/photo-sources", "own", uuid(), "image/png", raw), 503)
		id := receipt["asset_id"].(string)
		f.store.mu.Lock()
		f.store.objects[strings.ReplaceAll(id, "-", "")+".raw"] = []byte("synthetic corrupted object")
		f.store.mu.Unlock()
		conflict := decode(send(f, "POST", "/api/user/me/photo-sources/"+id+"/confirm", "own", "", "", nil), 409)
		if conflict["resumable"] != false || count("analysis_outbox", f.owner) != 0 {
			t.Fatal("corrupted source confirmed or advertised as recoverable")
		}
	})
	t.Run("reservation-fault-has-no-object", func(t *testing.T) {
		f := fresh(2)
		if _, err := root.Exec(`CREATE FUNCTION photo.upload_fixture_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic fault'; END $$;
   REVOKE ALL ON FUNCTION photo.upload_fixture_fault() FROM PUBLIC;
   CREATE TRIGGER upload_fixture_fault AFTER INSERT ON photo.upload_requests FOR EACH ROW EXECUTE FUNCTION photo.upload_fixture_fault();`); err != nil {
			t.Fatal(err)
		}
		defer root.Exec(`DROP TRIGGER IF EXISTS upload_fixture_fault ON photo.upload_requests; DROP FUNCTION IF EXISTS photo.upload_fixture_fault();`)
		decode(send(f, "POST", "/api/user/me/photo-sources", "own", uuid(), "image/png", raw), 503)
		if count("sources", f.owner) != 0 || f.store.puts != 0 {
			t.Fatal("rollback left source or wrote unreserved object")
		}
	})
	t.Run("revocation-during-put-preserves-status-not-analysis", func(t *testing.T) {
		f := fresh(2)
		authority := &photoStandingSource{}
		authority.version.Store(1)
		f.s.standingCache = standing.NewLeaseCache(authority)
		f.store.afterPut = func() error { authority.version.Store(2); return nil }
		t.Setenv("STANDING_ENFORCEMENT_ENABLED", "true")
		key := uuid()
		w := send(f, "POST", "/api/user/me/photo-sources", "own", key, "image/png", raw)
		if w.Code != 403 {
			t.Fatal("revoked upload confirmed", w.Code, w.Body.String())
		}
		if count("sources", f.owner) != 1 || count("analysis_outbox", f.owner) != 0 {
			t.Fatal("revocation queued work or lost recovery record")
		}
		var id string
		if err := root.QueryRow(`SELECT s.id::text FROM photo.sources s JOIN usuario u ON u.id=s.owner_user_id WHERE u.keycloak_id=$1`, f.owner).Scan(&id); err != nil {
			t.Fatal(err)
		}
		result := decode(send(f, "GET", "/api/user/me/photo-sources/"+id, "own", "", "", nil), 200)
		if result["status"] != "awaiting_upload" {
			t.Fatal("revoked owner cannot recover status", result)
		}
		recovered := decode(send(f, "GET", "/api/user/me/photo-upload-requests/"+key, "own", "", "", nil), 200)
		if recovered["asset_id"] != id {
			t.Fatal("sanction blocked upload receipt recovery")
		}
		decode(send(f, "POST", "/api/user/me/photo-sources/"+id+"/confirm", "own", "", "", nil), 403)
	})
	t.Run("disabled-and-input-bounds", func(t *testing.T) {
		f := fresh(2)
		ambiguous := httptest.NewRequest("POST", "/api/user/me/photo-sources", bytes.NewReader(raw))
		ambiguous.Header.Set("Authorization", "Bearer own")
		ambiguous.Header.Set("Content-Type", "image/png")
		ambiguous.Header.Add("Idempotency-Key", uuid())
		ambiguous.Header.Add("Idempotency-Key", uuid())
		ambiguousResponse := httptest.NewRecorder()
		f.r.ServeHTTP(ambiguousResponse, ambiguous)
		decode(ambiguousResponse, 400)
		decode(send(f, "POST", "/api/user/me/photo-sources", "own", "", "image/png", raw), 400)
		decode(send(f, "POST", "/api/user/me/photo-sources", "own", uuid(), "image/svg+xml", raw), 415)
		decode(send(f, "POST", "/api/user/me/photo-sources", "own", uuid(), "image/png", []byte("invalid")), 400)
		decode(send(f, "POST", "/api/user/me/photo-sources", "own", uuid(), "image/png", make([]byte, 5*1024*1024+1)), 413)
		f.s.photoUploads = nil
		capabilities := decode(send(f, "GET", "/api/user/me/photo-upload-config", "own", "", "", nil), 200)
		if capabilities["enabled"] != false {
			t.Fatal("disabled upload advertised as enabled")
		}
		decode(send(f, "GET", "/api/user/me/photo-sources/"+uuid(), "own", "", "", nil), 503)
	})
	t.Run("s3-upload-worker-and-owner-status", func(t *testing.T) {
		endpoint := os.Getenv("RAC_PHOTO_PIPELINE_TEST_ENDPOINT")
		if endpoint == "" {
			t.Skip("requires isolated S3 pipeline IAM and native OCR")
		}
		f := fresh(2)
		ingress, err := photostore.NewQuarantineS3(endpoint, "us-east-1", os.Getenv("PHOTO_QUARANTINE_BUCKET"), os.Getenv("PHOTO_INGEST_ACCESS_KEY"), os.Getenv("PHOTO_INGEST_SECRET_KEY"))
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
		const pipeline = "owner-api-s3-fixture-1"
		if err := f.s.SetPrivatePhotoUploads(ingress, photoassets.UploadPolicy{Pipeline: pipeline, MaxPerDay: 2}); err != nil {
			t.Fatal(err)
		}
		f.r = f.s.Router()
		release := photoassets.Release{Pipeline: pipeline, Commit: strings.Repeat("a", 40), ImageDigest: "sha256:" + strings.Repeat("b", 64)}
		if _, err := root.Exec(`CREATE ROLE rac_photo_upload_worker_fixture LOGIN PASSWORD 'synthetic-photo-upload-worker-only';
	 GRANT USAGE ON SCHEMA photo TO rac_photo_upload_worker_fixture;
	 GRANT EXECUTE ON FUNCTION photo.claim_processing(text,text,text),photo.complete_processing(uuid,uuid,text,text,text,text,bytea,int,jsonb,text,int) TO rac_photo_upload_worker_fixture;`); err != nil {
			t.Fatal(err)
		}
		if _, err := root.Exec(`INSERT INTO photo.processing_policies VALUES($1,60,0,3);`, pipeline); err != nil {
			t.Fatal(err)
		}
		if _, err := root.Exec(`INSERT INTO photo.processing_releases VALUES($1,$2,$3)`, pipeline, release.Commit, release.ImageDigest); err != nil {
			t.Fatal(err)
		}
		workerURL, err := url.Parse(dsn)
		if err != nil {
			t.Fatal(err)
		}
		workerURL.User = url.UserPassword("rac_photo_upload_worker_fixture", "synthetic-photo-upload-worker-only")
		workerDB, err := sql.Open("postgres", workerURL.String())
		if err != nil {
			t.Fatal(err)
		}
		defer workerDB.Close()
		queue, err := photoassets.NewPostgresQueue(context.Background(), workerDB)
		if err != nil {
			t.Fatal(err)
		}
		ocr, err := photoassets.NewTesseract(context.Background(), "/usr/bin/tesseract", "/usr/share/tesseract-ocr/5/tessdata")
		if err != nil {
			t.Fatal(err)
		}
		analyzer, err := contentsignals.New(contentsignals.ProposedLexicon())
		if err != nil {
			t.Fatal(err)
		}
		processor, err := photoassets.NewProcessor(pipeline, ocr, analyzer)
		if err != nil {
			t.Fatal(err)
		}
		worker, err := photoassets.NewWorker(queue, reader, staging, processor, release)
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct{ name, state string }{{"contact_border", "correction_required"}, {"benign", "awaiting_review"}} {
			bytes, err := os.ReadFile("../photoassets/testdata/" + tc.name + ".png")
			if err != nil {
				t.Fatal(err)
			}
			key := uuid()
			receipt := decode(send(f, "POST", "/api/user/me/photo-sources", "own", key, "image/png", bytes), 202)
			id := receipt["asset_id"].(string)
			if receipt["status"] != "queued" {
				t.Fatal("upload did not enqueue analysis", receipt)
			}
			if claimed, err := worker.RunOnce(context.Background()); !claimed || err != nil {
				t.Fatal("S3 owner upload not processed", err)
			}
			status := decode(send(f, "GET", "/api/user/me/photo-sources/"+id, "own", "", "", nil), 200)
			if status["status"] != tc.state || len(status) != 2 {
				t.Fatal("owner sees wrong state or private metadata", status)
			}
			decode(send(f, "GET", "/api/user/me/photo-sources/"+id, "other", "", "", nil), 404)
		}
		if _, err := db.Exec(`SELECT assessment FROM photo.processing_results`); err == nil {
			t.Fatal("public application can read private assessment tables")
		}
	})
}

func privatePhotoJSON(value any) string { raw, _ := json.Marshal(value); return string(raw) }

func TestPrivatePhotoUploadActivationGuards(t *testing.T) {
	for _, environment := range []string{"", "qa", "prd", "test"} {
		t.Setenv("RAC_PHOTO_UPLOADS_ENABLED", "true")
		t.Setenv("RAC_ENV", environment)
		if err := (&Server{}).ConfigurePrivatePhotoUploadsFromEnvironment(); !errors.Is(err, photoassets.ErrInvalid) {
			t.Fatal("private upload enabled outside explicit DEV", err)
		}
	}
	t.Setenv("RAC_PHOTO_UPLOADS_ENABLED", "false")
	if err := (&Server{}).ConfigurePrivatePhotoUploadsFromEnvironment(); err != nil {
		t.Fatal(err)
	}
}

var _ photoassets.UploadStore = (*privateSourceMemory)(nil)
