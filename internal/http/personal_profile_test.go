package httpapi

import (
	"context"
	"database/sql"
	"github.com/cazocarma/rac-user-service/internal/config"
	"github.com/cazocarma/rac-user-service/internal/platform"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestPersonalProfileValidation(t *testing.T) {
	p := personalProfile{Name: "  Cris Á  ", Interests: []string{" Cine ", "cine", "Running"}}
	if !p.valid() || p.Name != "Cris Á" || len(p.Interests) != 2 {
		t.Fatal("normalization failed", p)
	}
	for _, p := range []personalProfile{{Name: "a"}, {Name: strings.Repeat("á", 121)}, {Name: "Name\nOther"}, {Name: "Name", Phone: "javascript:alert"}, {Name: "Name", Interests: []string{strings.Repeat("á", 41)}}} {
		if p.valid() {
			t.Fatal("invalid profile accepted", p)
		}
	}
}

func TestPersonalProfileRejectsMassAssignment(t *testing.T) {
	s := New(nil, config.Config{})
	s.security = &platform.Security{VerifyToken: func(context.Context, string) (*platform.Claims, error) {
		p := &platform.Claims{Subject: "own"}
		p.RealmAccess.Roles = []string{"cliente"}
		return p, nil
	}}
	router := s.Router()
	for _, body := range []string{`{"nombre":"Cris","role":"admin"}`, `{"nombre":"Cris","correo":"foreign@test"}`, `{"nombre":"Cris","usuario_id":"foreign"}`, `{"nombre":"Cris"} {}`, strings.Repeat(" ", 8200) + `{}`} {
		req := httptest.NewRequest("PUT", "/api/user/me", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer fixture")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != 400 {
			t.Fatal("unsafe body accepted", w.Code)
		}
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("PUT", "/api/user/me", strings.NewReader(`{}`)))
	if w.Code != 401 {
		t.Fatal("anonymous edit accepted")
	}
}

func TestProfileStandingProvisioning(t *testing.T) {
	dsn := os.Getenv("RAC_ONBOARDING_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable migrated database")
	}
	t.Setenv("STANDING_ENFORCEMENT_ENABLED", "true")
	owner, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	var subject string
	if err = owner.QueryRow(`SELECT gen_random_uuid()::text`).Scan(&subject); err != nil {
		t.Fatal(err)
	}
	defer owner.Exec(`DELETE FROM usuario WHERE keycloak_id=$1`, subject)
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("options", "-c role=rac_user")
	u.RawQuery = q.Encode()
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := New(db, config.Config{})
	s.security = &platform.Security{VerifyToken: func(context.Context, string) (*platform.Claims, error) {
		p := &platform.Claims{Subject: subject, Email: subject + "@fixture.test"}
		p.RealmAccess.Roles = []string{"cliente"}
		return p, nil
	}}
	router := s.Router()
	call := func(method, path, body string, want int) {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer unchanged-fixture")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != want {
			t.Fatal(path, w.Code, w.Body.String())
		}
	}
	body := `{"nombre":"Initial profile","correo":"ignored@fixture.test","fecha_nacimiento":"1990-01-01","telefono":"123456789","pais":"Chile","region":"Region","ciudad":"Ciudad"}`
	call("POST", "/api/user/profile", body, 200)
	var status string
	if err = owner.QueryRow(`SELECT a.status FROM standing.account a JOIN usuario u ON u.id=a.subject_id WHERE u.keycloak_id=$1`, subject).Scan(&status); err != nil || status != "active" {
		t.Fatal("fresh profile missing authority", status, err)
	}
	call("PUT", "/api/user/me", `{"nombre":"Allowed name","biografia":"Allowed biography"}`, 200)
	if _, err = owner.Exec(`UPDATE standing.account SET status='suspended',version=version+1 WHERE subject_id=(SELECT id FROM usuario WHERE keycloak_id=$1)`, subject); err != nil {
		t.Fatal(err)
	}
	call("POST", "/api/user/profile", body, 403)
	call("PUT", "/api/user/me", `{"nombre":"Forbidden name","biografia":"Forbidden biography"}`, 403)
	call("GET", "/api/user/me", "", 200)
	var name, biography string
	if err = owner.QueryRow(`SELECT nombre,biografia FROM usuario WHERE keycloak_id=$1`, subject).Scan(&name, &biography); err != nil || name != "Allowed name" || biography != "Allowed biography" {
		t.Fatal("restricted profile write committed", name, biography, err)
	}
}
