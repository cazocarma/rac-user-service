package httpapi

import (
	"context"
	"github.com/cazocarma/rac-user-service/internal/config"
	"github.com/cazocarma/rac-user-service/internal/platform"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPrivateEndpointsRejectAnonymous(t *testing.T) {
	s := New(nil, config.Config{})
	r := s.Router()
	for method, path := range map[string]string{"GET": "/api/user/me", "PUT": "/api/user/me"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(method, path, nil))
		if w.Code != 401 {
			t.Fatalf("%s %s=%d", method, path, w.Code)
		}
	}
	for _, path := range []string{"/api/user/profile", "/api/user/compas/foreign/skills", "/api/user/compas"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("POST", path, strings.NewReader(`{}`)))
		if w.Code != 401 {
			t.Fatalf("%s=%d", path, w.Code)
		}
	}
}
func TestBaseCannotPublishOrEditSkills(t *testing.T) {
	s := New(nil, config.Config{})
	s.security = &platform.Security{VerifyToken: func(context.Context, string) (*platform.Claims, error) {
		p := &platform.Claims{Subject: "base"}
		p.RealmAccess.Roles = []string{"cliente"}
		return p, nil
	}}
	r := s.Router()
	for _, path := range []string{"/api/user/compas", "/api/user/compas/id/skills"} {
		req := httptest.NewRequest("POST", path, strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != 403 {
			t.Fatalf("%s=%d", path, w.Code)
		}
	}
}
