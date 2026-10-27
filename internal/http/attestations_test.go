package httpapi

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cazocarma/rac-user-service/internal/attestations"
	"github.com/cazocarma/rac-user-service/internal/config"
	"github.com/cazocarma/rac-user-service/internal/platform"
)

func TestCompaAttestationsPostgres(t *testing.T) {
	dsn := os.Getenv("RAC_ATTESTATIONS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires isolated attestation database")
	}
	u, err := url.Parse(dsn)
	if err != nil || !strings.HasPrefix(u.Hostname(), "rac-migration-test-") || u.Path != "/attestations" {
		t.Fatal("isolated attestation fixture required")
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
	exec("ALTER ROLE rac_user LOGIN PASSWORD 'synthetic-attestation-role-only-123456'")
	u.User = url.UserPassword("rac_user", "synthetic-attestation-role-only-123456")
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const buyer = "11111111-1111-4111-8111-000000000101"
	const other = "11111111-1111-4111-8111-000000000102"
	s := New(db, config.Config{})
	s.security = &platform.Security{VerifyToken: func(_ context.Context, token string) (*platform.Claims, error) {
		subject := buyer
		if token == "other" {
			subject = other
		}
		claims := &platform.Claims{Subject: subject}
		claims.RealmAccess.Roles = []string{"admin"}
		return claims, nil
	}}
	router := s.Router()
	request := func(method, token string, body any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest(method, "/api/user/me/compa/attestation", bytes.NewReader(raw))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	if w := request("GET", "fixture", nil); w.Code != 503 {
		t.Fatal("missing reviewed definition", w.Code)
	}
	content := attestations.Content{}
	for _, id := range []string{"no_illicit_substances", "no_sexual_services", "catalog_only", "adults_only", "enforcement_and_appeal"} {
		content.Statements = append(content.Statements, attestations.Statement{ID: id, Text: "Declaración sintética para prueba; no texto definitivo"})
	}
	for _, id := range []string{"scenario_one", "scenario_two", "scenario_three"} {
		content.Questions = append(content.Questions, attestations.Question{ID: id, Text: "Escenario sintético", CorrectOption: "reject_report", Options: []attestations.Option{{ID: "reject_report", Text: "Rechazar y reportar"}, {ID: "proceed", Text: "Continuar"}}})
	}
	raw, _ := json.Marshal(content)
	var definitionID string
	err = admin.QueryRow(`INSERT INTO compa_attestation_versions(version,locale,content,legal_review,approved_by,reviewed_at,published_at)
 VALUES('synthetic-1','es',$1,'approved',gen_random_uuid(),now()-interval '1 hour',now()-interval '1 minute') RETURNING id`, string(raw)).Scan(&definitionID)
	if err != nil {
		t.Fatal(err)
	}
	exec("INSERT INTO compa_attestation_requirements(locale,registry_version,definition_id) VALUES('es',1,$1)", definitionID)
	w := request("GET", "fixture", nil)
	if w.Code != 200 || strings.Contains(w.Body.String(), "correct_option") {
		t.Fatal("private answer key or invalid public view", w.Code, w.Body.String())
	}
	var view struct {
		Version  string            `json:"version"`
		SHA256   string            `json:"sha256"`
		Registry registryReference `json:"registry"`
		Passed   *time.Time        `json:"quiz_passed_at"`
	}
	if json.Unmarshal(w.Body.Bytes(), &view) != nil || view.Passed != nil {
		t.Fatal("unexpected existing pass")
	}
	digest := content.Digest()
	if view.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("content digest changed")
	}
	input := assessmentRequest{Version: view.Version, SHA256: view.SHA256, Registry: view.Registry, Statements: map[string]bool{}, Answers: map[string]string{}}
	for _, statement := range content.Statements {
		input.Statements[statement.ID] = true
	}
	for _, q := range content.Questions {
		input.Answers[q.ID] = q.CorrectOption
	}
	input.Statements["adults_only"] = false
	if w = request("POST", "fixture", input); w.Code != 422 {
		t.Fatal("admin skipped declaration", w.Code, w.Body.String())
	}
	input.Statements["adults_only"] = true
	input.Answers["scenario_one"] = "proceed"
	if w = request("POST", "fixture", input); w.Code != 422 {
		t.Fatal("incorrect quiz accepted", w.Code, w.Body.String())
	}
	var count int
	if err = admin.QueryRow("SELECT count(*) FROM compa_attestations").Scan(&count); err != nil || count != 0 {
		t.Fatal("failed attempt persisted", count, err)
	}
	input.Answers["scenario_one"] = "reject_report"
	var group sync.WaitGroup
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			if w := request("POST", "fixture", input); w.Code != 200 {
				t.Error("concurrent idempotent pass", w.Code, w.Body.String())
			}
		}()
	}
	group.Wait()
	var first time.Time
	if err = admin.QueryRow("SELECT count(*),min(quiz_passed_at) FROM compa_attestations").Scan(&count, &first); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	if w = request("POST", "fixture", input); w.Code != 200 {
		t.Fatal(w.Code)
	}
	var second time.Time
	if err = admin.QueryRow("SELECT quiz_passed_at FROM compa_attestations").Scan(&second); err != nil || !first.Equal(second) {
		t.Fatal("retry changed first pass", err)
	}
	w = request("GET", "other", nil)
	view.Passed = nil
	if json.Unmarshal(w.Body.Bytes(), &view) != nil || w.Code != 200 || view.Passed != nil {
		t.Fatal("another subject saw acceptance")
	}
	if _, err = db.Exec("UPDATE compa_attestations SET answers='{}'"); err == nil {
		t.Fatal("runtime can rewrite pass")
	}
	if _, err = db.Exec("DELETE FROM compa_attestations"); err == nil {
		t.Fatal("runtime can delete pass")
	}
	if _, err = db.Exec("UPDATE compa_attestation_versions SET legal_review='approved'"); err == nil {
		t.Fatal("runtime can approve definition")
	}
	if _, err = admin.Exec("UPDATE compa_attestation_versions SET content='{}' WHERE id=$1", definitionID); err == nil {
		t.Fatal("published definition mutable")
	}
	// A concurrent activation cannot cross the head lease used for recording.
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = readAssessment(context.Background(), tx, "es"); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	activate := `SELECT documents.activate(gen_random_uuid(),1,'es',ARRAY(SELECT id FROM legal_documents ORDER BY kind),gen_random_uuid(),gen_random_uuid())`
	blocked, err := admin.Begin()
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	_, err = blocked.Exec("SET LOCAL lock_timeout='100ms'")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = blocked.Exec(activate); err == nil {
		t.Error("activation crossed attestation lease")
	}
	blocked.Rollback()
	tx.Rollback()
	exec(activate)
	exec("INSERT INTO compa_attestation_requirements(locale,registry_version,definition_id) VALUES('es',2,$1)", definitionID)
	if w = request("POST", "fixture", input); w.Code != 409 {
		t.Fatal("stale registry accepted", w.Code, w.Body.String())
	}
	w = request("GET", "fixture", nil)
	view.Passed = nil
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil || view.Passed == nil || !view.Passed.Equal(first) {
		t.Fatal("nonmaterial binding forgot prior pass", w.Code, w.Body.String())
	}
}

func TestAssessmentRejectsAmbiguousConsentBeforeDatabase(t *testing.T) {
	s := New(nil, config.Config{})
	s.security = &platform.Security{VerifyToken: func(context.Context, string) (*platform.Claims, error) {
		claims := &platform.Claims{Subject: "11111111-1111-4111-8111-111111111111"}
		claims.RealmAccess.Roles = []string{"cliente"}
		return claims, nil
	}}
	router := s.Router()
	valid := `{"version":"synthetic-1","sha256":"` + strings.Repeat("a", 64) + `","registry":{"locale":"es","version":1,"policy_version":"11111111-1111-4111-8111-111111111111"},"statements":{"no_illicit_substances":true,"no_sexual_services":true,"catalog_only":true,"adults_only":true,"enforcement_and_appeal":true},"answers":{"scenario_one":"reject_report","scenario_two":"reject_report","scenario_three":"reject_report"}}`
	for _, body := range []string{
		strings.Replace(valid, `"adults_only":true`, `"adults_only":false,"adults_only":true`, 1),
		strings.TrimSuffix(valid, "}") + `,"user_id":"other-subject"}`,

		`{} {}`,
		strings.Repeat("[", 20) + strings.Repeat("]", 20),
		strings.Repeat(" ", 8200),
	} {
		request := httptest.NewRequest("POST", "/api/user/me/compa/attestation", strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer fixture")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, request)
		if w.Code != 400 {
			t.Fatal("ambiguous or caller-owned consent accepted", w.Code)
		}
	}
}
