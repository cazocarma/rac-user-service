package httpapi

import (
	"bytes"
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	platformidentity "github.com/cazocarma/rac-platform/identity"
	"github.com/cazocarma/rac-user-service/internal/config"
	"github.com/cazocarma/rac-user-service/internal/identity"
	"github.com/cazocarma/rac-user-service/internal/identity/fake"
	"github.com/cazocarma/rac-user-service/internal/platform"
	"github.com/gin-gonic/gin"
)

func identityServer(t *testing.T, service *identity.Service) *Server {
	s := New(nil, config.Config{})
	s.security = &platform.Security{VerifyToken: func(context.Context, string) (*platform.Claims, error) {
		p := &platform.Claims{Subject: "person", EmailVerified: true}
		p.RealmAccess.Roles = []string{"cliente"}
		return p, nil
	}}
	s.SetIdentity(service)
	return s
}

func TestIdentityRoutesWithoutProviderAreUnavailable(t *testing.T) {
	r := identityServer(t, nil).Router()
	for _, test := range []struct{ method, path, body, token string }{
		{"GET", "/api/user/me/identity", "", "Bearer x"},
		{"POST", "/api/user/me/identity/sessions", `{"purpose":"client_booking"}`, "Bearer x"},
		{"POST", "/api/user/identity/webhook", `{}`, ""},
	} {
		req := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
		if test.token != "" {
			req.Header.Set("Authorization", test.token)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != 503 || !strings.Contains(w.Body.String(), "identity_unavailable") {
			t.Fatalf("%s %s=%d %s", test.method, test.path, w.Code, w.Body)
		}
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/user/me/identity", nil))
	if w.Code != 401 {
		t.Fatal("identity state readable without a token", w.Code)
	}
}

func TestIdentityRequestsAreValidatedBeforeStorage(t *testing.T) {
	provider, _ := fake.New("test", bytes.Repeat([]byte("w"), 32), "http://localhost")
	fingerprint, _ := identity.NewFingerprinter("test-key", bytes.Repeat([]byte("k"), 32))
	// The handle never connects: every case below must stop before storage.
	db, _ := sql.Open("postgres", "postgres://invalid.invalid/none")
	defer db.Close()
	service, err := identity.NewService(db, provider, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	r := identityServer(t, service).Router()
	body := fake.Body("evt_00000001", "fake_00000001", identity.Approved, nil, "CL", bytes.Repeat([]byte{1}, 16))
	for name, test := range map[string]struct {
		path, body, signature string
		token                 bool
		want                  int
	}{
		"unsigned webhook":      {"/api/user/identity/webhook", string(body), "", false, 401},
		"stale webhook":         {"/api/user/identity/webhook", string(body), provider.Sign(body, time.Now().Add(-time.Hour)), false, 401},
		"unknown purpose":       {"/api/user/me/identity/sessions", `{"purpose":"admin"}`, "", true, 400},
		"client-chosen subject": {"/api/user/me/identity/sessions", `{"purpose":"client_booking","user_id":"other"}`, "", true, 400},
		"duplicate key":         {"/api/user/me/identity/sessions", `{"purpose":"client_booking","purpose":"compa_onboarding"}`, "", true, 400},
	} {
		req := httptest.NewRequest("POST", test.path, strings.NewReader(test.body))
		if test.signature != "" {
			req.Header.Set(fake.SignatureHeader, test.signature)
		}
		if test.token {
			req.Header.Set("Authorization", "Bearer x")
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != test.want {
			t.Errorf("%s=%d %s", name, w.Code, w.Body)
		}
	}
}

type gateFunc func(platformidentity.Query) (platformidentity.Observation, error)

func (f gateFunc) ReadIdentity(_ context.Context, q platformidentity.Query) (platformidentity.Observation, error) {
	return f(q)
}

func TestPublicationRequiresApprovedIdentity(t *testing.T) {
	const subject = "6f1c3f6e-4a35-4c86-9c3b-0f6b0e1c2d3e"
	approved := false
	seen := []platformidentity.Query{}
	s := New(nil, config.Config{})
	s.security = &platform.Security{VerifyToken: func(context.Context, string) (*platform.Claims, error) {
		// A verified email and the compa role never stand in for identity.
		p := &platform.Claims{Subject: subject, EmailVerified: true}
		p.RealmAccess.Roles = []string{"cliente", "compa"}
		return p, nil
	}}
	s.identityGate = gateFunc(func(q platformidentity.Query) (platformidentity.Observation, error) {
		seen = append(seen, q)
		return platformidentity.Observation{Query: q, Approved: approved, ObservedAt: time.Now()}, nil
	})
	send := func(r http.Handler, method, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer x")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	// The gate alone, ending in a handler that needs no database.
	gate := gin.New()
	gate.POST("/gated", s.security.Require("cliente"), s.requireIdentity(platformidentity.CompaOnboarding), func(c *gin.Context) { c.Status(204) })
	if w := send(gate, "POST", "/gated"); w.Code != 204 || len(seen) != 0 {
		t.Fatal("gate active or identity read without rollout", w.Code, len(seen))
	}
	t.Setenv("IDENTITY_ENFORCEMENT_ENABLED", "true")
	// Every publication route stops at the gate before its handler runs.
	r := s.Router()
	for _, route := range []struct{ method, path string }{
		{"PUT", "/api/user/me/compa"}, {"POST", "/api/user/compas"}, {"POST", "/api/user/compas/" + subject + "/skills"},
	} {
		w := send(r, route.method, route.path)
		if w.Code != 428 || !strings.Contains(w.Body.String(), `"error":"IDENTITY_VERIFICATION_REQUIRED"`) ||
			!strings.Contains(w.Body.String(), `"flow":"/identity?purpose=compa_onboarding"`) || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("unverified publication", route.path, w.Code, w.Body)
		}
	}
	for _, q := range seen {
		if q.AccountID != subject || q.Purpose != platformidentity.CompaOnboarding {
			t.Fatal("identity query not bound to the authenticated subject", q)
		}
	}
	approved = true
	if w := send(gate, "POST", "/gated"); w.Code != 204 {
		t.Fatal("approved identity blocked", w.Code, w.Body)
	}
	s.SetIdentity(nil)
	if w := send(s.Router(), "POST", "/api/user/compas"); w.Code != 503 || !strings.Contains(w.Body.String(), "identity_unavailable") {
		t.Fatal("missing provider must fail closed", w.Code, w.Body)
	}
}
