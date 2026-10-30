package httpapi

import (
	"bytes"
	"context"
	"database/sql"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cazocarma/rac-user-service/internal/config"
	"github.com/cazocarma/rac-user-service/internal/identity"
	"github.com/cazocarma/rac-user-service/internal/identity/fake"
	"github.com/cazocarma/rac-user-service/internal/platform"
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
