package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cazocarma/rac-platform/documents"
	documentsdb "github.com/cazocarma/rac-platform/documents/postgres"
	"github.com/cazocarma/rac-platform/policy"
	"github.com/cazocarma/rac-user-service/internal/config"
	"github.com/cazocarma/rac-user-service/internal/platform"
)

type documentSourceFunc func(context.Context, documents.Query) (documents.Observation, error)

func (f documentSourceFunc) ReadDocuments(ctx context.Context, q documents.Query) (documents.Observation, error) {
	return f(ctx, q)
}
func TestDocumentPreconditionsBeforeWrites(t *testing.T) {
	t.Setenv("DOCUMENTS_ENFORCEMENT_ENABLED", "true")
	s := New(nil, config.Config{})
	s.security = &platform.Security{VerifyToken: func(context.Context, string) (*platform.Claims, error) {
		p := &platform.Claims{Subject: "11111111-1111-4111-8111-111111111111"}
		p.RealmAccess.Roles = []string{"admin"}
		return p, nil
	}}
	calls := 0
	s.documentsSource = documentSourceFunc(func(_ context.Context, q documents.Query) (documents.Observation, error) {
		calls++
		now := time.Now()
		snapshot := documents.Snapshot{ObservedAt: now, Policy: policy.Version{ID: "fixture-policy", State: policy.Approved, ApprovedBy: "fixture-reviewer", EffectiveAt: now.Add(-time.Hour)}}
		for i, k := range []documents.Kind{documents.TermsClient, documents.TermsCompa, documents.CommunityRules, documents.Privacy, documents.SafetyRules} {
			id := fmt.Sprintf("11111111-1111-4111-8111-%012d", i+1)
			snapshot.Documents = append(snapshot.Documents, documents.Document{ID: id, Kind: k, MaterialVersion: id, SHA256: [32]byte{byte(i + 1)}, PublishedAt: now.Add(-time.Hour), Approved: true})
		}
		return documents.Observation{Query: q, Revision: 1, Snapshot: snapshot}, nil
	})
	router := s.Router()
	for _, tc := range []struct {
		method, path string
		count        int
	}{{"PUT", "/api/user/me/compa", 5}, {"POST", "/api/user/compas", 5}, {"POST", "/api/user/compas/fixture/skills", 5}, {"POST", "/api/user/bookings/fixture/review", 4}} {
		request := httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{}`))
		request.Header.Set("Authorization", "Bearer fixture")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, request)
		var body struct {
			Error     string                        `json:"error"`
			Documents []struct{ ID, SHA256 string } `json:"documents"`
		}
		if w.Code != 428 || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Error != "DOCUMENT_ACCEPTANCE_REQUIRED" || len(body.Documents) != tc.count {
			t.Fatal("admin bypass or wrong document persona", w.Code, w.Body.String())
		}
	}
	before := calls
	request := httptest.NewRequest("POST", "/api/user/me/documents/acceptances", strings.NewReader(`{}`))
	request.Header.Set("Authorization", "Bearer fixture")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, request)
	if w.Code != 400 || calls != before {
		t.Fatal("acceptance action blocked by document prerequisites", w.Code)
	}
	s.documentsSource = nil
	request = httptest.NewRequest("PUT", "/api/user/me/compa", strings.NewReader(`{}`))
	request.Header.Set("Authorization", "Bearer fixture")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, request)
	if w.Code != 503 {
		t.Fatal("unavailable authority treated as acceptance success", w.Code)
	}
}

func TestDocumentGuardPostgres(t *testing.T) {
	dsn := os.Getenv("RAC_DOCUMENT_WRITES_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires isolated migrated document-write database")
	}
	connection, err := url.Parse(dsn)
	if err != nil || !strings.HasPrefix(connection.Hostname(), "rac-migration-test-") || strings.TrimPrefix(connection.Path, "/") != "document_writes" {
		t.Fatal("isolated document-write fixture required")
	}
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := admin.Exec(query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO audit.chain_heads(chain_id) VALUES('11111111-1111-4111-8111-111111111111'); INSERT INTO audit.writer_principals VALUES('postgres','22222222-2222-4222-8222-222222222222','11111111-1111-4111-8111-111111111111');`)
	exec(`INSERT INTO legal_documents(kind,version,locale,content,material_change,legal_review,approved_by,reviewed_at,published_at)
 SELECT kind,'guard-1','es','Synthetic document guard fixture',true,'approved',gen_random_uuid(),now()-interval '2 days',now()-interval '1 day'
 FROM unnest(ARRAY['terms_client','terms_compa','community_rules','privacy','safety_rules']) kind;`)
	activate := func(expected int) {
		t.Helper()
		exec(`SELECT documents.activate(gen_random_uuid(),$1,'es',ARRAY(SELECT DISTINCT ON(kind) id FROM legal_documents WHERE locale='es' ORDER BY kind,published_at DESC,created_at DESC),gen_random_uuid(),gen_random_uuid());`, expected)
	}
	activate(0)
	var subject, user string
	if err = admin.QueryRow(`INSERT INTO usuario(id,nombre,correo,rol,keycloak_id) VALUES(gen_random_uuid(),'Fixture','document-guard@example.test','cliente',gen_random_uuid()::text) RETURNING keycloak_id,id::text`).Scan(&subject, &user); err != nil {
		t.Fatal(err)
	}
	options := connection.Query()
	options.Set("options", "-c role=rac_user")
	connection.RawQuery = options.Encode()
	db, err := sql.Open("postgres", connection.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	t.Setenv("DOCUMENTS_ENFORCEMENT_ENABLED", "true")
	t.Setenv("STANDING_ENFORCEMENT_ENABLED", "true")
	s := New(db, config.Config{})
	s.security = &platform.Security{VerifyToken: func(context.Context, string) (*platform.Claims, error) {
		p := &platform.Claims{Subject: subject}
		p.RealmAccess.Roles = []string{"cliente"}
		return p, nil
	}}
	grants := 0
	s.grantCompa = func(context.Context, string) error { grants++; return nil }
	router := s.Router()
	send := func(method, path, body string, want int) {
		t.Helper()
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer fixture")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, request)
		if w.Code != want {
			t.Fatal(method, path, w.Code, w.Body.String())
		}
	}
	profile := validCompaProfile()
	raw, _ := json.Marshal(profile)
	send("PUT", "/api/user/me/compa", string(raw), 428)
	if grants != 0 {
		t.Fatal("unaccepted documents assigned external role")
	}
	registry := func() registryReference {
		t.Helper()
		var ref registryReference
		ref.Locale = "es"
		if err := admin.QueryRow(`SELECT r.version,r.policy_version FROM documents.head h JOIN documents.registry r ON r.locale=h.locale AND r.version=h.version WHERE h.locale='es'`).Scan(&ref.Version, &ref.PolicyVersion); err != nil {
			t.Fatal(err)
		}
		return ref
	}
	initialRegistry := registry()
	for _, path := range []string{"/api/user/documents", "/api/user/me/documents"} {
		request := httptest.NewRequest("GET", path, nil)
		request.Header.Set("Authorization", "Bearer fixture")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, request)
		var page struct {
			Registry registryView   `json:"registry"`
			Items    []documentView `json:"items"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || page.Registry.Version != 1 || len(page.Items) != 5 {
			t.Fatal("active set unavailable", w.Code, w.Body.String())
		}
	}
	// Reviewed publication alone does not replace the operator-activated set.
	exec(`INSERT INTO legal_documents(kind,version,locale,content,material_change,legal_review,approved_by,reviewed_at,published_at) VALUES('community_rules','unselected','es','Synthetic unselected revision',false,'approved',gen_random_uuid(),now()-interval '2 days',clock_timestamp());`)
	request := httptest.NewRequest("GET", "/api/user/me/documents", nil)
	request.Header.Set("Authorization", "Bearer fixture")
	listed := httptest.NewRecorder()
	router.ServeHTTP(listed, request)
	if listed.Code != 200 || strings.Contains(listed.Body.String(), "unselected") {
		t.Fatal("unselected publication became current", listed.Code, listed.Body.String())
	}
	send("GET", "/api/user/me/documents?locale=en", "", 503)
	var itemID, itemHash string
	if err := admin.QueryRow(`SELECT d.id,encode(d.content_sha256,'hex') FROM documents.head h JOIN documents.requirement r ON r.locale=h.locale AND r.version=h.version JOIN legal_documents d ON d.id=r.document_id WHERE h.locale='es' AND d.kind='terms_client'`).Scan(&itemID, &itemHash); err != nil {
		t.Fatal(err)
	}
	withoutRef, _ := json.Marshal(map[string]any{"documents": []map[string]string{{"id": itemID, "sha256": itemHash}}, "context": "account"})
	send("POST", "/api/user/me/documents/acceptances", string(withoutRef), 409)
	var unpublishedID, unpublishedHash string
	if err := admin.QueryRow(`SELECT id,encode(content_sha256,'hex') FROM legal_documents WHERE version='unselected'`).Scan(&unpublishedID, &unpublishedHash); err != nil {
		t.Fatal(err)
	}
	wrongSet, _ := json.Marshal(map[string]any{"registry": initialRegistry, "documents": []map[string]string{{"id": unpublishedID, "sha256": unpublishedHash}}, "context": "account"})
	send("POST", "/api/user/me/documents/acceptances", string(wrongSet), 409)
	var consentCount int
	if err := admin.QueryRow(`SELECT count(*) FROM document_acceptances WHERE user_id=$1`, user).Scan(&consentCount); err != nil || consentCount != 0 {
		t.Fatal("invalid target recorded consent", consentCount, err)
	}
	accept := func() {
		t.Helper()
		rows, err := admin.Query(`SELECT d.id,encode(d.content_sha256,'hex') FROM documents.head h JOIN documents.requirement r ON r.locale=h.locale AND r.version=h.version JOIN legal_documents d ON d.id=r.document_id WHERE h.locale='es'`)
		if err != nil {
			t.Fatal(err)
		}
		items := []map[string]string{}
		for rows.Next() {
			var id, hash string
			if err := rows.Scan(&id, &hash); err != nil {
				t.Fatal(err)
			}
			items = append(items, map[string]string{"id": id, "sha256": hash})
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
		body, _ := json.Marshal(map[string]any{"registry": registry(), "documents": items, "context": "compa_onboarding"})
		send("POST", "/api/user/me/documents/acceptances", string(body), 200)
	}
	accept()
	send("PUT", "/api/user/me/compa", string(raw), 200)
	if grants != 1 {
		t.Fatal("accepted onboarding did not complete", grants)
	}
	publish := func(version string) {
		t.Helper()
		exec(`INSERT INTO legal_documents(kind,version,locale,content,material_change,legal_review,approved_by,reviewed_at,published_at) VALUES('privacy',$1,'es','Synthetic material change',true,'approved',gen_random_uuid(),now()-interval '2 days',clock_timestamp());`, version)
	}
	publish("guard-2")
	activate(1)
	stale, _ := json.Marshal(map[string]any{"registry": initialRegistry, "documents": []map[string]string{{"id": itemID, "sha256": itemHash}}, "context": "account"})
	send("POST", "/api/user/me/documents/acceptances", string(stale), 409)

	send("PUT", "/api/user/me/compa", string(raw), 428)
	send("GET", "/api/user/me/compa", "", 200)
	accept()
	actual := documentsdb.New(db)
	changed := false
	s.documentsSource = documentSourceFunc(func(ctx context.Context, q documents.Query) (documents.Observation, error) {
		snapshot, err := actual.ReadDocuments(ctx, q)
		if !changed {
			changed = true
			publish("guard-3")
			activate(2)
		}
		return snapshot, err
	})
	profile.Description = "This changed profile must roll back before publication."
	raw, _ = json.Marshal(profile)
	send("PUT", "/api/user/me/compa", string(raw), 428)
	if grants != 1 {
		t.Fatal("new material registry escaped final fence and assigned role")
	}
	var description string
	if err := admin.QueryRow(`SELECT descripcion FROM compa_perfil WHERE usuario_id=$1`, user).Scan(&description); err != nil || description != validCompaProfile().Description {
		t.Fatal("stale preflight committed profile", description, err)
	}
}
