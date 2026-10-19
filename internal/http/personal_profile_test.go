package httpapi

import (
	"context"
	"github.com/cazocarma/rac-user-service/internal/config"
	"github.com/cazocarma/rac-user-service/internal/platform"
	"net/http/httptest"
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
