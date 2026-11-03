package httpapi

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

	"github.com/cazocarma/rac-user-service/internal/config"
	"github.com/cazocarma/rac-user-service/internal/platform"
)

func TestListingOwnerPostgres(t *testing.T) {
	dsn := os.Getenv("RAC_LISTING_OWNER_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable migrated database")
	}
	u, err := url.Parse(dsn)
	if err != nil || !strings.HasPrefix(u.Hostname(), "rac-migration-test-") || u.Path != "/listing_owner_http" {
		t.Fatal("refusing non-disposable listing owner database")
	}
	query := u.Query()
	query.Set("options", "-c role=rac_user")
	u.RawQuery = query.Encode()
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	const owner, other = "5a0e7c64-61f4-4c6a-9b3e-0c1d2e3f4a5b", "6b1f8d75-72a5-4d7b-8c4f-1d2e3f4a5b6c"
	if _, err = db.ExecContext(ctx, `INSERT INTO usuario(id,nombre,correo,rol,keycloak_id) VALUES
 (gen_random_uuid(),'Owner fixture','listing-owner@example.test','compa',$1),
 (gen_random_uuid(),'Other fixture','listing-other@example.test','compa',$2)`, owner, other); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO compa_perfil(id,usuario_id,descripcion,tarifa_hora)
 SELECT gen_random_uuid(),id,'Mutable profile text',12000 FROM usuario WHERE keycloak_id=$1`, owner); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{"RAC_ENV": "test", "STANDING_ENFORCEMENT_ENABLED": "false", "DOCUMENTS_ENFORCEMENT_ENABLED": "false", "IDENTITY_ENFORCEMENT_ENABLED": "false", "LISTING_POLICY_VERSION": ""} {
		t.Setenv(key, value)
	}
	subject := owner
	s := New(db, config.Config{})
	s.security = &platform.Security{VerifyToken: func(context.Context, string) (*platform.Claims, error) {
		p := &platform.Claims{Subject: subject}
		p.RealmAccess.Roles = []string{"cliente", "compa"}
		return p, nil
	}}
	router := s.Router()
	send := func(method, path, body string) (int, map[string]any) {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body)).WithContext(ctx)
		req.Header.Set("Authorization", "Bearer fixture")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		var result map[string]any
		json.Unmarshal(w.Body.Bytes(), &result)
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("owner listing response cacheable", path)
		}
		return w.Code, result
	}
	draft := func(version, edit string) string {
		listing := map[string]any{"display_name": "Cris A", "biography": "", "interests": []string{"cine"},
			"description": "Compartamos una tarde de cine y conversación tranquila", "activities": []map[string]string{{"slug": "cine", "note": ""}},
			"price_clp_per_hour": 12000, "photo_version": "", "area_code": ""}
		switch edit {
		case "photo":
			listing["photo_version"] = "photo-1"
		case "contact":
			listing["description"] = "Escríbeme al +56 9 1234 5678 para coordinar el cine"
		case "activity":
			listing["activities"] = []map[string]string{{"slug": "masajes", "note": ""}}
		case "price":
			listing["price_clp_per_hour"] = 999999
		}
		encoded, _ := json.Marshal(map[string]any{"expected_version": version, "listing": listing})
		return string(encoded)
	}
	if status, body := send("GET", "/api/user/me/listing", ""); status != 200 || body["listing"] != nil {
		t.Fatal("listing shown before any submission", status, body)
	}
	if status, body := send("POST", "/api/user/me/listing/submissions", draft("0", "")); status != 503 || body["error"] != "listing_submission_unavailable" {
		t.Fatal("submission accepted without a configured policy", status, body)
	}
	for key, value := range map[string]string{"LISTING_POLICY_VERSION": "fixture-listing-1", "LISTING_MIN_PRICE_CLP": "5000", "LISTING_MAX_PRICE_CLP": "50000"} {
		t.Setenv(key, value)
	}
	for _, tc := range []struct {
		name, body string
		status     int
		code       string
	}{
		{"photo", draft("0", "photo"), 409, "listing_photo_unavailable"},
		{"contact", draft("0", "contact"), 400, "public_contact_not_allowed"},
		{"activity", draft("0", "activity"), 400, "invalid_listing"},
		{"price", draft("0", "price"), 400, "invalid_listing"},
		{"version", draft("00", ""), 400, "invalid_listing"},
		{"unknown field", strings.TrimSuffix(draft("0", ""), "}") + `,"state":"published"}`, 400, "invalid_listing"},
	} {
		if status, body := send("POST", "/api/user/me/listing/submissions", tc.body); status != tc.status || body["error"] != tc.code {
			t.Fatal(tc.name, status, body)
		}
	}
	var revisions int
	if db.QueryRowContext(ctx, `SELECT count(*) FROM listing_revisions`).Scan(&revisions); revisions != 0 {
		t.Fatal("rejected submission stored a revision")
	}
	status, body := send("POST", "/api/user/me/listing/submissions", draft("0", ""))
	if status != 202 || body["status"] != "submitted" || body["revision_no"] != "1" || body["listing_version"] != "1" {
		t.Fatal("valid submission failed", status, body)
	}
	if status, body := send("POST", "/api/user/me/listing/submissions", draft("0", "")); status != 409 || body["error"] != "listing_version_conflict" {
		t.Fatal("stale version accepted", status, body)
	}
	if status, body := send("POST", "/api/user/me/listing/submissions", draft("1", "")); status != 202 || body["revision_no"] != "2" || body["listing_version"] != "2" {
		t.Fatal("resubmission failed", status, body)
	}
	var unpublished bool
	if err := db.QueryRowContext(ctx, `SELECT state='unpublished' AND published_revision_id IS NULL AND pending_revision_id IS NOT NULL FROM listings`).Scan(&unpublished); err != nil || !unpublished {
		t.Fatal("submission published without review", err)
	}
	status, body = send("GET", "/api/user/me/listing", "")
	listing, _ := body["listing"].(map[string]any)
	pending, _ := listing["pending"].(map[string]any)
	if status != 200 || listing["state"] != "unpublished" || listing["version"] != "2" || listing["published"] != nil || listing["last_decision"] != nil || pending["revision_no"] != "2" {
		t.Fatal("owner status wrong", status, body)
	}
	if snapshot, _ := pending["listing"].(map[string]any); snapshot["display_name"] != "Cris A" {
		t.Fatal("owner cannot see submitted snapshot", pending)
	}
	raw, _ := json.Marshal(body)
	for _, private := range []string{"assessment", "risk", "signals", "reviewer"} {
		if strings.Contains(string(raw), private) {
			t.Fatal("owner status exposes review internals", private)
		}
	}
	subject = other
	if status, body := send("POST", "/api/user/me/listing/submissions", draft("0", "")); status != 404 || body["error"] != "compa_profile_required" {
		t.Fatal("submission without compa profile", status, body)
	}
	if status, body := send("GET", "/api/user/me/listing", ""); status != 200 || body["listing"] != nil {
		t.Fatal("other account sees a listing", status, body)
	}
}
