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
	"github.com/gin-gonic/gin"
	"github.com/lib/pq"
)

func TestPublicContactRejectsBeforePersistence(t *testing.T) {
	s := New(nil, config.Config{}) // A forbidden edit must never reach the DB.
	s.security = &platform.Security{VerifyToken: func(context.Context, string) (*platform.Claims, error) {
		p := &platform.Claims{Subject: "own"}
		p.RealmAccess.Roles = []string{"cliente", "compa"}
		return p, nil
	}}
	t.Setenv("STANDING_ENFORCEMENT_ENABLED", "false")
	t.Setenv("DOCUMENTS_ENFORCEMENT_ENABLED", "false")
	t.Setenv("IDENTITY_ENFORCEMENT_ENABLED", "false")
	router := s.Router()
	for _, tc := range []struct{ method, path, body, field string }{
		{"PUT", "/api/user/me", `{"nombre":"Cris","biografia":"Escríbeme a hola@example.com"}`, "biografia"},
		{"PUT", "/api/user/me", `{"nombre":"@compa_test"}`, "nombre"},
		{"PUT", "/api/user/me", `{"nombre":"Cris","intereses":["https://example.com"]}`, "intereses"},
		{"PUT", "/api/user/me/compa", `{"descripcion":"Conversemos por WhatsApp antes de reservar","tarifa_hora":1000,"availability":{"lunes":["09:00-10:00"]}}`, "descripcion"},
		{"PUT", "/api/user/me/compa", `{"descripcion":"Compartamos una tarde de cine entretenida","tarifa_hora":1000,"actividades":[{"slug":"cine","nota":"hola arroba ejemplo punto com"}],"availability":{"lunes":["09:00-10:00"]}}`, "actividades.nota"},
		{"POST", "/api/user/compas", `{"descripcion":"https://example.com","tarifa_hora":1000}`, "descripcion"},
		{"POST", "/api/user/profile", `{"nombre":"@compa_test","correo":"ignored@example.test","fecha_nacimiento":"1990-01-01","telefono":"+56 9 1234 5678","pais":"Chile","region":"Fixture","ciudad":"Fixture"}`, "nombre"},
		{"POST", "/api/user/profile", `{"nombre":"Cris","correo":"ignored@example.test","fecha_nacimiento":"1990-01-01","telefono":"+56 9 1234 5678","pais":"Chile","region":"Fixture","ciudad":"Fixture","intereses":["https://example.com"]}`, "intereses"},
	} {
		t.Run(tc.path+"/"+tc.field, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Authorization", "Bearer fixture")
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			var result map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || w.Code != 400 || result["error"] != "public_contact_not_allowed" || result["field"] != tc.field || len(result) != 2 {
				t.Fatalf("unexpected public response: status=%d body=%s err=%v", w.Code, w.Body, err)
			}
		})
	}
}

func TestStoredPublicContactPostgres(t *testing.T) {
	dsn := os.Getenv("RAC_ONBOARDING_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable migrated database")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("invalid disposable DB configuration")
	}
	query := u.Query()
	query.Set("options", "-c role=rac_user")
	u.RawQuery = query.Encode()
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var subject string
	err = db.QueryRowContext(ctx, `INSERT INTO usuario(id,nombre,correo,rol,keycloak_id,telefono)
 SELECT id,'Fixture','stored-'||id::text||'@example.test','compa',id::text,'+56 9 1234 5678'
 FROM (SELECT gen_random_uuid() AS id) fixture RETURNING keycloak_id`).Scan(&subject)
	if err != nil {
		t.Fatal(err)
	}
	defer db.ExecContext(context.Background(), `DELETE FROM usuario WHERE keycloak_id=$1`, subject)
	for key, value := range map[string]string{"RAC_ENV": "test", "STANDING_ENFORCEMENT_ENABLED": "false", "DOCUMENTS_ENFORCEMENT_ENABLED": "false", "IDENTITY_ENFORCEMENT_ENABLED": "false"} {
		t.Setenv(key, value)
	}
	s := New(db, config.Config{})
	s.security = &platform.Security{VerifyToken: func(context.Context, string) (*platform.Claims, error) {
		p := &platform.Claims{Subject: subject}
		p.RealmAccess.Roles = []string{"cliente", "compa"}
		return p, nil
	}}
	router := s.Router()
	for _, tc := range []struct {
		field, name, bio string
		interests        []string
	}{
		{field: "nombre", name: "@compa_test"},
		{field: "biografia", name: "Cris", bio: "hola arroba ejemplo punto com"},
		{field: "intereses", name: "Cris", interests: []string{"https://example.com"}},
	} {
		_, err = db.ExecContext(ctx, `UPDATE usuario SET nombre=$2,biografia=$3,intereses=$4 WHERE keycloak_id=$1`, subject, tc.name, tc.bio, pq.Array(tc.interests))
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{"/api/user/compas", "/api/user/me/compa"} {
			method, body := "POST", `{"descripcion":"Compartamos una tarde entretenida de cine","tarifa_hora":12000}`
			if strings.HasSuffix(path, "/me/compa") {
				method = "PUT"
				body = `{"descripcion":"Compartamos una tarde entretenida de cine","tarifa_hora":12000,"actividades":[{"slug":"cine"}],"availability":{"lunes":["09:00-10:00"]}}`
			}
			req := httptest.NewRequest(method, path, strings.NewReader(body)).WithContext(ctx)
			req.Header.Set("Authorization", "Bearer fixture")
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			var result map[string]string
			if json.Unmarshal(w.Body.Bytes(), &result) != nil || w.Code != 400 || result["error"] != "public_contact_not_allowed" || result["field"] != tc.field {
				t.Fatal("stored contact bypassed publication guard", path, tc.field, w.Code, w.Body)
			}
		}
		var count int
		if err = db.QueryRowContext(ctx, `SELECT count(*) FROM compa_perfil cp JOIN usuario u ON u.id=cp.usuario_id WHERE u.keycloak_id=$1`, subject).Scan(&count); err != nil || count != 0 {
			t.Fatal("rejection persisted a profile", err, count)
		}
	}
	if _, err = db.ExecContext(ctx, `UPDATE usuario SET nombre='Cris',biografia='',intereses='{}' WHERE keycloak_id=$1`, subject); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/api/user/compas", strings.NewReader(`{"descripcion":"Compartamos una tarde entretenida de cine","tarifa_hora":12000}`)).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer fixture")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatal("corrected profile/private phone was rejected", w.Code, w.Body)
	}
}

func TestPublicContactDoesNotSanctionSuspicionOrReadPrivatePhone(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("PUT", "/", nil)
	p := personalProfile{Name: "Cris", Phone: "+56 9 1234 5678", Biography: "Me gusta el cine", Interests: []string{"Running"}}
	if !p.valid() || rejectPublicContact(c, publicText{"nombre", p.Name}, publicText{"biografia", p.Biography}, publicText{"intereses", strings.Join(p.Interests, " ")}) {
		t.Fatal("private phone must remain editable")
	}
	if rejectPublicContact(c, publicText{"descripcion", "vendo tusi"}) {
		t.Fatal("a private-lexicon signal is not a contact violation or a sanction")
	}
}

func TestPublicContactFailsClosedOnCanceledAnalysis(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.Request = httptest.NewRequest("PUT", "/", nil).WithContext(ctx)
	if !rejectPublicContact(c, publicText{"biografia", "ordinary text"}) || w.Code != 503 || strings.Contains(w.Body.String(), "ordinary text") {
		t.Fatal("analysis failure must not permit a write or disclose text", w.Code, w.Body)
	}
}
