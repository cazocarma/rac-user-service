package httpapi

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cazocarma/rac-user-service/internal/config"
	"github.com/cazocarma/rac-user-service/internal/platform"
	"github.com/gin-gonic/gin"
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
