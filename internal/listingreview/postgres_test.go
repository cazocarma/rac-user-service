package listingreview

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cazocarma/rac-platform/staff"
	_ "github.com/lib/pq"
)

func TestReaderPostgresHTTP(t *testing.T) {
	dsn := os.Getenv("RAC_LISTING_REVIEW_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable migrated listing reader database")
	}
	u, err := url.Parse(dsn)
	if err != nil || !strings.HasPrefix(u.Hostname(), "rac-migration-test-") || u.Path != "/listing_review_http" {
		t.Fatal("refusing non-disposable reader database")
	}
	root, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	exec := func(statement string) {
		t.Helper()
		if _, err := root.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	exec(`CREATE ROLE rac_listing_reader_fixture LOGIN PASSWORD 'synthetic-reader-only-123456';
 GRANT USAGE ON SCHEMA listing_review,audit TO rac_listing_reader_fixture;
 GRANT EXECUTE ON FUNCTION ` + strings.Join(signatures, ",") + ` TO rac_listing_reader_fixture;
 INSERT INTO audit.chain_heads(chain_id) VALUES('88888888-8888-4888-8888-888888888888');
 INSERT INTO audit.writer_principals VALUES('rac_listing_reader_fixture','99999999-9999-4999-8999-999999999999','88888888-8888-4888-8888-888888888888');`)
	// The seed tests the reader contract; it does not replace submission-policy tests.
	exec(`INSERT INTO usuario(id,nombre,correo,rol,keycloak_id) VALUES('22222222-2222-4222-8222-222222222222','Reader fixture','reader@example.test','compa','` + fixtureID + `');
 INSERT INTO compa_perfil(id,usuario_id,descripcion,tarifa_hora) VALUES('33333333-3333-4333-8333-333333333333','22222222-2222-4222-8222-222222222222','Synthetic',12000);
 INSERT INTO listings(id,compa_id) VALUES('44444444-4444-4444-8444-444444444444','33333333-3333-4333-8333-333333333333');
 INSERT INTO listing_revisions(id,listing_id,revision_no,payload_canonical,assessment,risk_score,policy_version)
 VALUES('55555555-5555-4555-8555-555555555555','44444444-4444-4444-8444-444444444444',1,'{"display_name":"Synthetic reader payload"}','{"signals":["synthetic-private-signal"]}',10,'fixture-1');
 UPDATE listings SET pending_revision_id='55555555-5555-4555-8555-555555555555',version=version+1 WHERE id='44444444-4444-4444-8444-444444444444';`)
	u.User = url.UserPassword("rac_listing_reader_fixture", "synthetic-reader-only-123456")
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	access, token := readerAccess(t)
	s, err := New(context.Background(), db, access, fixtureID)
	if err != nil {
		t.Fatal("scoped reader rejected", err)
	}
	handler := s.Handler()
	credential := token("ts_agent", staff.ListingsAudience)
	request := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("Authorization", "Bearer "+credential)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	count := func() int {
		t.Helper()
		var n int
		if err := root.QueryRow(`SELECT count(*) FROM listing_review.access_events`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	w := request("/internal/listings/queue?limit=1")
	if w.Code != 200 || strings.Contains(w.Body.String(), "payload") || strings.Contains(w.Body.String(), "synthetic-private-signal") {
		t.Fatal("queue leaked content or failed", w.Code, w.Body.String())
	}
	if count() != 1 {
		t.Fatal("queue delivered without committed access")
	}
	w = request("/internal/listings/revisions/55555555-5555-4555-8555-555555555555")
	var body struct {
		IsSelf    bool           `json:"is_self"`
		IsPending bool           `json:"is_pending"`
		Payload   map[string]any `json:"payload"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &body) != nil || !body.IsSelf || !body.IsPending || body.Payload["display_name"] != "Synthetic reader payload" {
		t.Fatal("wrong snapshot", w.Code, w.Body.String())
	}
	if count() != 2 {
		t.Fatal("detail delivered without committed access")
	}
	w = request("/internal/listings/revisions/66666666-6666-4666-8666-666666666666")
	if w.Code != 404 || count() != 3 {
		t.Fatal("missing revision was not audited", w.Code)
	}
	// Expiry after the SQL read must roll back its access record and withhold bytes.
	calls := 0
	s.now = func() time.Time {
		calls++
		if calls == 1 {
			return time.Now()
		}
		return time.Now().Add(24 * time.Hour)
	}
	w = request("/internal/listings/revisions/55555555-5555-4555-8555-555555555555")
	if calls != 2 || w.Code < 400 || strings.Contains(w.Body.String(), "Synthetic reader payload") || count() != 3 {
		t.Fatal("expired session disclosed content or committed access", calls, w.Code)
	}
	s.now = time.Now
	exec(`GRANT SELECT(nombre) ON usuario TO rac_listing_reader_fixture`)
	w = request("/internal/listings/queue")
	if w.Code != 503 || count() != 3 {
		t.Fatal("privilege drift did not close reader", w.Code)
	}
	exec(`REVOKE SELECT(nombre) ON usuario FROM rac_listing_reader_fixture`)
	var auditCount int
	if err := root.QueryRow(`SELECT count(*) FROM audit.log WHERE chain_id='88888888-8888-4888-8888-888888888888'`).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 3 {
		t.Fatal("access and audit diverged", auditCount)
	}
	t.Run("private-photo-preview", func(t *testing.T) { testPhotoPreviewPostgres(t, root, s, request) })
}
