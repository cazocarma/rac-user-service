package editorial

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cazocarma/rac-platform/staff"
	"github.com/cazocarma/rac-user-service/internal/config"
	httpapi "github.com/cazocarma/rac-user-service/internal/http"
	"github.com/cazocarma/rac-user-service/internal/strictjson"
	"github.com/golang-jwt/jwt/v5"
)

const author = "11111111-1111-4111-8111-111111111111"
const reviewer = "22222222-2222-4222-8222-222222222222"
const policy = "33333333-3333-4333-8333-333333333333"
const docID = "44444444-4444-4444-8444-444444444444"
const draftEvent = "55555555-5555-4555-8555-555555555555"
const reviewEvent = "66666666-6666-4666-8666-666666666666"
const publishEvent = "77777777-7777-4777-8777-777777777777"
const text = "Documento sintético; no son términos definitivos."

func fixtureAccess(t *testing.T) (*staff.Access, func(string, string, string) string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keys := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "fixture", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	}))
	t.Cleanup(keys.Close)
	access, err := staff.New("https://fixture.example/realms/rac", keys.URL, staff.DocumentsAudience)
	if err != nil {
		t.Fatal(err)
	}
	token := func(subject, role, audience string) string {
		now := time.Now().Unix()
		claims := jwt.MapClaims{"iss": "https://fixture.example/realms/rac", "aud": audience, "sub": subject, "typ": "Bearer", "azp": staff.ClientID, "iat": now, "exp": now + 120, "auth_time": now - 30, "amr": []string{"pwd", "otp"}, "resource_access": map[string]any{staff.ClientID: map[string]any{"roles": []string{role}}}, "realm_access": map[string]any{"roles": []string{"admin"}}}
		signed := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		signed.Header["kid"] = "fixture"
		raw, err := signed.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	return access, token
}
func bodyDraft() map[string]any {
	digest := sha256.Sum256([]byte(text))
	return map[string]any{"event_id": draftEvent, "document_id": docID, "sha256": hex.EncodeToString(digest[:]), "kind": "privacy", "version": "fixture-1", "locale": "es", "content": text, "material_change": true}
}
func request(t *testing.T, handler http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}
func TestEditorialInputAndRouterIsolation(t *testing.T) {
	access, token := fixtureAccess(t)
	s := &Server{access: access, policy: policy, now: time.Now}
	handler := s.Handler()
	for _, tc := range []struct {
		role, audience string
		want           int
	}{{"legal", staff.AdminAudience, 401}, {"admin", staff.DocumentsAudience, 403}, {"support", staff.DocumentsAudience, 403}} {
		if w := request(t, handler, "POST", "/internal/documents/drafts", token(author, tc.role, tc.audience), bodyDraft()); w.Code != tc.want {
			t.Fatal("wrong persona/audience reached persistence", w.Code)
		}
	}
	if w := request(t, handler, "POST", "/internal/documents/drafts", "", bodyDraft()); w.Code != 401 {
		t.Fatal("anonymous command")
	}
	for _, field := range []string{"actor", "approved_by", "human_actor", "policy_version", "published_at"} {
		body := bodyDraft()
		body[field] = reviewer
		if w := request(t, handler, "POST", "/internal/documents/drafts", token(author, "legal", staff.DocumentsAudience), body); w.Code != 400 {
			t.Fatal("asserted authority accepted", field, w.Code)
		}
	}
	for _, content := range []string{"\x00", "   ", strings.Repeat("á", 65537)} {
		body := bodyDraft()
		body["content"] = content
		digest := sha256.Sum256([]byte(content))
		body["sha256"] = hex.EncodeToString(digest[:])
		if w := request(t, handler, "POST", "/internal/documents/drafts", token(author, "legal", staff.DocumentsAudience), body); w.Code != 400 {
			t.Fatal("invalid exact-hash content reached persistence", w.Code)
		}
	}
	// Otherwise valid body and matching hash for the replacement character:
	// encoding/json's default replacement must not silently repair bad UTF-8.
	utfBody := bodyDraft()
	utfBody["content"] = "\uFFFD"
	utfDigest := sha256.Sum256([]byte("\uFFFD"))
	utfBody["sha256"] = hex.EncodeToString(utfDigest[:])
	utfEncoded, _ := json.Marshal(utfBody)
	invalidUTF8 := bytes.Replace(utfEncoded, []byte("\uFFFD"), []byte{255}, 1)
	raw, _ := json.Marshal(bodyDraft())
	var control draftRequest
	if strictjson.Decode(bytes.NewReader(raw), &control) != nil || !valid(control.command) {
		t.Fatal("valid control malformed")
	}
	for name, raw := range map[string][]byte{
		"case alias":      []byte(strings.Replace(string(raw), `"content":`, `"Content":"ambiguous","content":`, 1)),
		"duplicate event": []byte(strings.Replace(string(raw), `"event_id":`, `"event_id":"`+draftEvent+`","event_id":`, 1)),
		"invalid UTF8":    invalidUTF8,
		"oversized":       []byte(strings.Repeat(" ", 1048577) + "{}"),
	} {
		req := httptest.NewRequest("POST", "/internal/documents/drafts", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token(author, "legal", staff.DocumentsAudience))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != 400 {
			t.Fatal("ambiguous input reached database", name, w.Code)
		}
	}
	public := httpapi.New(nil, config.Config{}).Router()
	for _, path := range []string{"/internal/documents/drafts", "/internal/documents/reviews", "/internal/documents/publications"} {
		w := request(t, public, "POST", path, token(author, "legal", staff.DocumentsAudience), bodyDraft())
		if w.Code != 404 {
			t.Fatal("private ingress registered publicly", path, w.Code)
		}
	}
}
func TestEditorialConfigurationDisabled(t *testing.T) {
	t.Setenv("DOCUMENT_EDITORIAL_ENABLED", "")
	if server, err := FromEnvironment(); server != nil || err != nil {
		t.Fatal("unexpected activation")
	}
	t.Setenv("DOCUMENT_EDITORIAL_ENABLED", "TRUE")
	if _, err := FromEnvironment(); err == nil {
		t.Fatal("ambiguous activation accepted")
	}
	t.Setenv("DOCUMENT_EDITORIAL_ENABLED", "true")
	t.Setenv("DOCUMENT_EDITORIAL_DATABASE_URL", "")
	if _, err := FromEnvironment(); err == nil {
		t.Fatal("missing isolated credential accepted")
	}
}
func TestEditorialPostgresHTTP(t *testing.T) {
	dsn := os.Getenv("RAC_EDITORIAL_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable migrated editorial database")
	}
	location, err := url.Parse(dsn)
	if err != nil || !strings.HasPrefix(location.Hostname(), "rac-migration-test-") || location.Path != "/editorial_http" {
		t.Fatal("isolated editorial fixture required")
	}
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal("fixture unavailable")
	}
	defer admin.Close()
	exec := func(query string) {
		t.Helper()
		if _, err := admin.Exec(query); err != nil {
			t.Fatal("editorial fixture setup failed", err)
		}
	}
	exec(`CREATE ROLE rac_editorial_fixture LOGIN PASSWORD 'synthetic-editorial-only-123456';
 GRANT USAGE ON SCHEMA public,documents,audit TO rac_editorial_fixture;
 GRANT EXECUTE ON FUNCTION ` + strings.Join(requiredSignatures, ",") + ` TO rac_editorial_fixture;
 INSERT INTO audit.chain_heads(chain_id) VALUES('88888888-8888-4888-8888-888888888888');
 INSERT INTO audit.writer_principals VALUES('rac_editorial_fixture','99999999-9999-4999-8999-999999999999','88888888-8888-4888-8888-888888888888');
 CREATE SEQUENCE public.editorial_fixture_probes;
 CREATE FUNCTION public.editorial_fixture_probe() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('public.editorial_fixture_probes'); RETURN NEW; END $$;
 CREATE TRIGGER editorial_fixture_probe AFTER INSERT ON audit.log FOR EACH ROW EXECUTE FUNCTION public.editorial_fixture_probe();`)
	location.User = url.UserPassword("rac_editorial_fixture", "synthetic-editorial-only-123456")
	db, err := sql.Open("postgres", location.String())
	if err != nil {
		t.Fatal("dedicated fixture unavailable")
	}
	defer db.Close()
	access, token := fixtureAccess(t)
	if _, err := New(context.Background(), admin, access, policy); err == nil {
		t.Fatal("superuser credential accepted")
	}
	exec("GRANT SELECT ON public.usuario TO rac_editorial_fixture;")
	if _, err := New(context.Background(), db, access, policy); err == nil {
		t.Fatal("unrelated private read permission accepted")
	}
	exec("REVOKE SELECT ON public.usuario FROM rac_editorial_fixture;")
	s, err := New(context.Background(), db, access, policy)
	if err != nil {
		t.Fatal("scoped editorial login rejected", err)
	}
	if _, err := db.Exec("UPDATE public.legal_documents SET legal_review='approved'"); err == nil {
		t.Fatal("editorial login has direct DML")
	}
	handler := s.Handler()
	send := func(method, path, subject string, body any, want int) *httptest.ResponseRecorder {
		t.Helper()
		w := request(t, handler, method, path, token(subject, "legal", staff.DocumentsAudience), body)
		if w.Code != want {
			t.Fatalf("editorial response %s %s: %d want %d", method, path, w.Code, want)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("editorial response cached")
		}
		return w
	}
	send("GET", "/ready", author, nil, 200)
	draft := bodyDraft()
	hash := draft["sha256"].(string)
	send("POST", "/internal/documents/drafts", author, draft, 200)
	send("POST", "/internal/documents/drafts", author, draft, 200)
	publication := map[string]any{"event_id": publishEvent, "document_id": docID, "sha256": hash}
	review := map[string]any{"event_id": reviewEvent, "document_id": docID, "sha256": hash, "decision": "approved"}
	send("POST", "/internal/documents/publications", reviewer, publication, 409)
	send("POST", "/internal/documents/reviews", author, review, 403)
	send("POST", "/internal/documents/reviews", reviewer, review, 200)
	send("POST", "/internal/documents/reviews", reviewer, review, 200)
	w := send("GET", "/internal/documents/"+docID, reviewer, nil, 200)
	var view map[string]any
	if json.Unmarshal(w.Body.Bytes(), &view) != nil || view["content"] != text || view["author_id"] != author || view["reviewer_id"] != reviewer || view["published_at"] != nil {
		t.Fatal("review does not expose exact unpublished text")
	}
	send("POST", "/internal/documents/publications", reviewer, publication, 200)
	send("POST", "/internal/documents/publications", reviewer, publication, 200)
	send("GET", "/internal/documents/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", reviewer, nil, 404)
	var audits int
	if err := admin.QueryRow("SELECT count(*) FROM audit.log").Scan(&audits); err != nil || audits != 3 {
		t.Fatal("non-idempotent editorial audit", audits, err)
	}
	// Advance the application clock only at the final commit fence. The actual
	// database function and audit append run, then the whole transaction rolls back.
	calls := 0
	s.now = func() time.Time {
		calls++
		if calls >= 3 {
			return time.Now().Add(6 * time.Minute)
		}
		return time.Now()
	}
	late := bodyDraft()
	late["event_id"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaab"
	late["document_id"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaac"
	late["version"] = "late"
	send("POST", "/internal/documents/drafts", author, late, 403)
	if err := admin.QueryRow("SELECT count(*) FROM audit.log").Scan(&audits); err != nil || audits != 3 {
		t.Fatal("expired session committed audit")
	}
	var count int
	if err := admin.QueryRow("SELECT count(*) FROM legal_documents WHERE version='late'").Scan(&count); err != nil || count != 0 {
		t.Fatal("expired session committed document")
	}
	var probe int
	if err := admin.QueryRow("SELECT last_value FROM public.editorial_fixture_probes").Scan(&probe); err != nil || probe != 4 {
		t.Fatal("expiry did not occur after a real audit insert", probe, err)
	}
	s.now = time.Now
	testAssessmentBundleHTTP(t, admin, s, token)
	exec("DELETE FROM audit.writer_principals WHERE database_role='rac_editorial_fixture'")
	send("GET", "/ready", author, nil, 503)
	late["version"] = "unavailable-audit"
	send("POST", "/internal/documents/drafts", author, late, 503)
	if err := admin.QueryRow("SELECT count(*) FROM legal_documents WHERE version='unavailable-audit'").Scan(&count); err != nil || count != 0 {
		t.Fatal("unaudited draft persisted")
	}
}
