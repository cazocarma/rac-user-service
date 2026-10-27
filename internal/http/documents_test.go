package httpapi

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cazocarma/rac-user-service/internal/config"
	"github.com/cazocarma/rac-user-service/internal/platform"
)

func TestDocumentsRejectMalformedConsentBeforeDatabase(t *testing.T) {
	s := New(nil, config.Config{})
	s.security = &platform.Security{VerifyToken: func(context.Context, string) (*platform.Claims, error) {
		p := &platform.Claims{Subject: "fixture"}
		p.RealmAccess.Roles = []string{"cliente"}
		return p, nil
	}}
	r := s.Router()
	for _, body := range []string{`{}`, `{"documents":[],"context":"account"}`, `{"documents":[{"id":"invalid","sha256":"00"}],"context":"account"}`,
		`{"documents":[],"context":"account","user_id":"foreign"}`, `{} {}`, strings.Repeat(" ", 8193) + `{}`} {
		req := httptest.NewRequest("POST", "/api/user/me/documents/acceptances", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer fixture")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != 400 {
			t.Fatal("malformed consent reached persistence", w.Code)
		}
	}
	for _, path := range []string{"/api/user/me/documents", "/api/user/me/documents/acceptances"} {
		method := "GET"
		if strings.HasSuffix(path, "acceptances") {
			method = "POST"
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(`{}`)))
		if w.Code != 401 {
			t.Fatal("anonymous access accepted")
		}
	}
}

func TestVersionedDocumentsPostgres(t *testing.T) {
	dsn := os.Getenv("RAC_DOCUMENT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable migrated database")
	}
	u, err := url.Parse(dsn)
	if err != nil || !strings.HasPrefix(u.Hostname(), "rac-migration-test-") {
		t.Fatal("isolated fixture required")
	}
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	var subject, user, version string
	if admin.QueryRow(`SELECT gen_random_uuid()::text,gen_random_uuid()::text,gen_random_uuid()::text`).Scan(&subject, &user, &version) != nil {
		t.Fatal("fixture unavailable")
	}
	if _, err = admin.Exec(`INSERT INTO usuario(id,nombre,correo,rol,keycloak_id) VALUES($1,'Fixture',$2,'cliente',$3)`, user, subject+"@fixture.test", subject); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(`DELETE FROM usuario WHERE id=$1`, user)
	u.User = url.UserPassword("rac_user", "synthetic-documents-role-only-123456")
	if _, err = admin.Exec(`ALTER ROLE rac_user LOGIN PASSWORD 'synthetic-documents-role-only-123456'`); err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Del("options")
	u.RawQuery = q.Encode()
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(8)
	const content = "Documento sintetico para pruebas; no son terminos definitivos."
	hash := sha256.Sum256([]byte(content))
	digest := hex.EncodeToString(hash[:])
	insert := func(kind, state string, future bool) string {
		t.Helper()
		var id string
		var published any
		var reviewed any
		var approver any
		if state == "approved" {
			reviewed = time.Now().Add(-time.Hour)
			approver = user
			at := time.Now().Add(-time.Minute)
			if future {
				at = time.Now().Add(time.Hour)
			}
			published = at
		}
		if err := admin.QueryRow(`INSERT INTO legal_documents(kind,version,locale,content,material_change,legal_review,approved_by,reviewed_at,published_at)
 VALUES($1,$2,'es',$3,true,$4,$5,$6,$7) RETURNING id::text`, kind, version, content, state, approver, reviewed, published).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	current := insert("terms_client", "approved", false)
	draft := insert("privacy", "pending", false)
	future := insert("community_rules", "approved", true)
	s := New(db, config.Config{})
	s.security = &platform.Security{VerifyToken: func(context.Context, string) (*platform.Claims, error) {
		p := &platform.Claims{Subject: subject}
		p.RealmAccess.Roles = []string{"cliente"}
		return p, nil
	}}
	r := s.Router()
	send := func(method, path, body string, authenticated bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if authenticated {
			req.Header.Set("Authorization", "Bearer fixture")
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	for _, id := range []string{draft, future} {
		if w := send("GET", "/api/user/documents/"+id, "", false); w.Code != 404 {
			t.Fatal("unreviewed/future document exposed", w.Code)
		}
	}
	w := send("GET", "/api/user/documents/"+current, "", false)
	var view documentView
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil || view.Content != content || view.SHA256 != digest {
		t.Fatal("served content/hash mismatch")
	}
	request := func(id, hash string) string {
		return `{"documents":[{"id":"` + id + `","sha256":"` + hash + `"}],"context":"account"}`
	}
	if w = send("POST", "/api/user/me/documents/acceptances", request(current, strings.Repeat("0", 64)), true); w.Code != 409 {
		t.Fatal("wrong content hash accepted")
	}
	bulk := `{"documents":[{"id":"` + current + `","sha256":"` + digest + `"},{"id":"` + draft + `","sha256":"` + digest + `"}],"context":"account"}`
	if w = send("POST", "/api/user/me/documents/acceptances", bulk, true); w.Code != 409 {
		t.Fatal("unreviewed batch accepted")
	}
	var n int
	if admin.QueryRow(`SELECT count(*) FROM document_acceptances WHERE user_id=$1`, user).Scan(&n) != nil || n != 0 {
		t.Fatal("batch rollback failed")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if w := send("POST", "/api/user/me/documents/acceptances", request(current, digest), true); w.Code != 200 {
				t.Error("concurrent acceptance failed", w.Code)
			}
		}()
	}
	wg.Wait()
	var first time.Time
	if admin.QueryRow(`SELECT accepted_at FROM document_acceptances WHERE user_id=$1 AND document_id=$2`, user, current).Scan(&first) != nil {
		t.Fatal("consent missing")
	}
	if w = send("POST", "/api/user/me/documents/acceptances", request(current, digest), true); w.Code != 200 {
		t.Fatal("retry failed")
	}
	var after time.Time
	if admin.QueryRow(`SELECT accepted_at FROM document_acceptances WHERE user_id=$1 AND document_id=$2`, user, current).Scan(&after) != nil || !first.Equal(after) {
		t.Fatal("retry rewrote consent time")
	}
	if w = send("GET", "/api/user/me/documents", "", true); w.Code != 200 || !strings.Contains(w.Body.String(), `"accepted_at"`) {
		t.Fatal("own acceptance missing")
	}
	if w = send("GET", "/api/user/documents", "", false); w.Code != 200 || strings.Contains(w.Body.String(), `"accepted_at"`) {
		t.Fatal("public endpoint disclosed private consent")
	}
	// Historical versions must remain visible even when they are not current.
	for i := 0; i < 2; i++ {
		var old string
		if err := admin.QueryRow(`INSERT INTO legal_documents(kind,version,locale,content,material_change,legal_review,approved_by,reviewed_at,published_at)
 VALUES('terms_client',$1,'es',$2,false,'approved',$3,$4,$5) RETURNING id`, version+"-history-"+strconv.Itoa(i), content, user, first.Add(-2*time.Hour), first.Add(-time.Hour)).Scan(&old); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(`INSERT INTO document_acceptances(user_id,document_id,accepted_at,context) VALUES($1,$2,$3,'booking')`, user, old, first); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("DOCUMENTS_ENFORCEMENT_ENABLED", "true") // No active registry exists in this fixture.
	t.Setenv("STANDING_ENFORCEMENT_ENABLED", "true")
	seen := map[string]bool{}
	cursor := ""
	for page := 0; page < 4; page++ {
		path := "/api/user/me/documents/history?limit=1"
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		w := send("GET", path, "", true)
		var result struct {
			Items []historyItem `json:"items"`
			Next  *string       `json:"next_cursor"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || len(result.Items) != 1 {
			t.Fatal("own history unavailable", w.Code, w.Body.String())
		}
		item := result.Items[0]
		if seen[item.ID] || item.AcceptedAt == nil || item.SHA256 != digest || item.Content != "" {
			t.Fatal("duplicate or inexact history", item)
		}
		seen[item.ID] = true
		if result.Next == nil {
			break
		}
		cursor = *result.Next
	}
	if len(seen) != 3 {
		t.Fatal("timestamp ties lost historical versions", len(seen))
	}
	for _, query := range []string{"limit=0", "limit=51", "limit=no", "cursor=invalid", "cursor=", "limit=1&limit=2"} {
		if w := send("GET", "/api/user/me/documents/history?"+query, "", true); w.Code != 400 {
			t.Fatal("unbounded history query accepted", query, w.Code)
		}
	}
	if w := send("GET", "/api/user/me/documents/history", "", false); w.Code != 401 {
		t.Fatal("history did not require authentication", w.Code)
	}
	originalSubject := subject
	var otherUser string
	if err := admin.QueryRow(`INSERT INTO usuario(id,nombre,correo,rol,keycloak_id) VALUES(gen_random_uuid(),'Other fixture',gen_random_uuid()::text||'@history.test','cliente',gen_random_uuid()::text) RETURNING id,keycloak_id`).Scan(&otherUser, &subject); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec("DELETE FROM usuario WHERE id=$1", otherUser)
	w = send("GET", "/api/user/me/documents/history?user_id="+user+"&cursor="+url.QueryEscape(cursor), "", true)
	var isolated struct {
		Items []historyItem `json:"items"`
		Next  *string       `json:"next_cursor"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &isolated) != nil || len(isolated.Items) != 0 || isolated.Next != nil {
		t.Fatal("history crossed authenticated subject", w.Code, w.Body.String())
	}
	subject = originalSubject
	for _, query := range []string{`UPDATE legal_documents SET content='changed'`, `DELETE FROM legal_documents`, `UPDATE document_acceptances SET context='booking'`, `DELETE FROM document_acceptances`} {
		if _, err = db.Exec(query); err == nil {
			t.Fatal("unexpected runtime document privilege")
		}
	}
	if _, err = admin.Exec(`UPDATE legal_documents SET content='changed' WHERE id=$1`, current); err == nil {
		t.Fatal("published content mutated")
	}
	if _, err = admin.Exec(`DELETE FROM legal_documents WHERE id=$1`, current); err == nil {
		t.Fatal("published version removed")
	}
}
