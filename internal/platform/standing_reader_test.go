package platform

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	platformidentity "github.com/cazocarma/rac-platform/identity"
	"github.com/golang-jwt/jwt/v5"
)

func TestStandingReaderSignedTokens(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "reader",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	defer jwks.Close()
	const issuer = "https://issuer.example/realms/rac"
	cfg := StandingReaderConfig{Issuer: issuer, JWKS: jwks.URL, Audience: "rac-standing", Subjects: map[string]string{"rac-match-standing": "machine-subject"}, AllowDevelopmentHTTP: true}
	auth, err := NewStandingReader(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Changes to the caller's configuration must not change live authorization.
	cfg.Subjects["rac-web"] = "human-subject"
	for _, tc := range []struct {
		name           string
		change         func(jwt.MapClaims)
		badKey, wantOK bool
	}{
		{name: "provisioned reader", wantOK: true},
		{name: "wrong issuer", change: func(c jwt.MapClaims) { c["iss"] = "https://other.example" }},
		{name: "public audience", change: func(c jwt.MapClaims) { c["aud"] = "rac-api" }},
		{name: "human admin", change: func(c jwt.MapClaims) {
			c["azp"], c["sub"] = "rac-web", "human-subject"
			c["realm_access"] = map[string]any{"roles": []string{"admin"}}
		}},
		{name: "different service subject", change: func(c jwt.MapClaims) { c["sub"] = "other-machine" }},
		{name: "unknown client", change: func(c jwt.MapClaims) { c["azp"] = "other-client" }},
		{name: "missing client", change: func(c jwt.MapClaims) { delete(c, "azp") }},
		{name: "id token", change: func(c jwt.MapClaims) { c["typ"] = "ID" }},
		{name: "realm role insufficient", change: func(c jwt.MapClaims) {
			delete(c, "resource_access")
			c["realm_access"] = map[string]any{"roles": []string{"admin", "standing.read"}}
		}},
		{name: "wrong resource", change: func(c jwt.MapClaims) {
			c["resource_access"] = map[string]any{"rac-api": map[string]any{"roles": []string{"standing.read"}}}
		}},
		{name: "wrong permission", change: func(c jwt.MapClaims) {
			c["resource_access"] = map[string]any{"rac-standing": map[string]any{"roles": []string{"admin"}}}
		}},
		{name: "expired", change: func(c jwt.MapClaims) {
			c["iat"], c["exp"] = time.Now().Add(-200*time.Second).Unix(), time.Now().Add(-time.Second).Unix()
		}},
		{name: "missing expiry", change: func(c jwt.MapClaims) { delete(c, "exp") }},
		{name: "missing issued at", change: func(c jwt.MapClaims) { delete(c, "iat") }},
		{name: "future issued at", change: func(c jwt.MapClaims) { c["iat"] = time.Now().Add(time.Minute).Unix() }},
		{name: "long lifetime", change: func(c jwt.MapClaims) { c["exp"] = time.Now().Add(301 * time.Second).Unix() }},
		{name: "not yet valid", change: func(c jwt.MapClaims) { c["nbf"] = time.Now().Add(time.Minute).Unix() }},
		{name: "invalid signature", badKey: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := jwt.MapClaims{"iss": issuer, "aud": "rac-standing", "sub": "machine-subject", "azp": "rac-match-standing", "typ": "Bearer", "iat": time.Now().Unix(), "exp": time.Now().Add(300 * time.Second).Unix(), "resource_access": map[string]any{"rac-standing": map[string]any{"roles": []string{"standing.read"}}}}
			if tc.change != nil {
				tc.change(claims)
			}
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			token.Header["kid"] = "reader"
			signer := key
			if tc.badKey {
				signer = otherKey
			}
			raw, err := token.SignedString(signer)
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("POST", "/internal/standing", nil)
			r.Header.Set("Authorization", "Bearer "+raw)
			if err = auth(r); (err == nil) != tc.wantOK {
				t.Fatalf("authorized=%v want=%v", err == nil, tc.wantOK)
			}
			if tc.wantOK {
				r.Header.Add("Authorization", "Bearer "+raw)
				if auth(r) == nil {
					t.Fatal("duplicate authorization accepted")
				}
			}
		})
	}
	if auth(nil) == nil || auth(httptest.NewRequest("POST", "/", nil)) == nil {
		t.Fatal("missing request/token accepted")
	}

	documentConfig := StandingReaderConfig{Issuer: issuer, JWKS: jwks.URL, Audience: "rac-documents", Subjects: map[string]string{"rac-match-standing": "machine-subject"}, AllowDevelopmentHTTP: true}
	documentAuth, err := NewDocumentsReader(documentConfig)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"document reader", "standing audience", "standing role", "human admin"} {
		c := jwt.MapClaims{"iss": issuer, "aud": "rac-documents", "sub": "machine-subject", "azp": "rac-match-standing", "typ": "Bearer", "iat": time.Now().Unix(), "exp": time.Now().Add(300 * time.Second).Unix(), "resource_access": map[string]any{"rac-documents": map[string]any{"roles": []string{"documents.read"}}}}
		switch scenario {
		case "standing audience":
			c["aud"] = "rac-standing"
		case "standing role":
			c["resource_access"] = map[string]any{"rac-documents": map[string]any{"roles": []string{"standing.read"}}}
		case "human admin":
			c["azp"] = "rac-web"
			c["sub"] = "human-subject"
			c["realm_access"] = map[string]any{"roles": []string{"admin"}}
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
		token.Header["kid"] = "reader"
		raw, err := token.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest("GET", "/internal/documents", nil)
		request.Header.Set("Authorization", "Bearer "+raw)
		if (documentAuth(request) == nil) != (scenario == "document reader") {
			t.Fatal("document permission isolation", scenario)
		}
	}
	// A correctly signed, provisioned chat reader can check participants but
	// cannot use the separate history/recovery surface reserved for match.
	bindings := map[string]string{"rac-match-standing": "machine-subject", "rac-chat-standing": "chat-subject", "rac-alert-standing": "alert-subject"}
	general, err := NewStandingReader(StandingReaderConfig{Issuer: issuer, JWKS: jwks.URL, Audience: "rac-standing", Subjects: bindings, AllowDevelopmentHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.MapClaims{"iss": issuer, "aud": "rac-standing", "sub": "chat-subject", "azp": "rac-chat-standing", "typ": "Bearer", "iat": time.Now().Unix(), "exp": time.Now().Add(300 * time.Second).Unix(), "resource_access": map[string]any{"rac-standing": map[string]any{"roles": []string{"standing.read"}}}}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "reader"
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("POST", "/internal/standing", nil)
	request.Header.Set("Authorization", "Bearer "+raw)
	if err := general(request); err != nil {
		t.Fatal("valid chat reader rejected before purpose restriction", err)
	}
	file := filepath.Join(t.TempDir(), "subjects.json")
	data, _ := json.Marshal(bindings)
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STANDING_ENFORCEMENT_ENABLED", "true")
	t.Setenv("STANDING_SUBJECTS_FILE", file)
	t.Setenv("OIDC_ISSUER", issuer)
	t.Setenv("STANDING_JWKS_URL", jwks.URL)
	t.Setenv("RAC_ENV", "dev")
	server, err := StandingAuthorityFromEnvironment(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/internal/standing/replay", "/internal/standing/replay/events", "/internal/standing/replay/accounts"} {
		r := httptest.NewRequest("POST", path, strings.NewReader(`{"subject":"10000000-0000-4000-8000-000000000001","after":1}`))
		r.Header.Set("Authorization", "Bearer "+raw)
		w := httptest.NewRecorder()
		server.Handler.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatal("chat reader can crawl standing history", path, w.Code)
		}
	}

	t.Setenv("DOCUMENTS_ENFORCEMENT_ENABLED", "true")
	documentServer, err := StandingAuthorityFromEnvironment(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := jwt.MapClaims{"iss": issuer, "aud": "rac-documents", "sub": "machine-subject", "azp": "rac-match-standing", "typ": "Bearer", "iat": time.Now().Unix(), "exp": time.Now().Add(300 * time.Second).Unix(), "resource_access": map[string]any{"rac-documents": map[string]any{"roles": []string{"documents.read"}}}}
	documentToken := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	documentToken.Header["kid"] = "reader"
	documentRaw, err := documentToken.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		token string
		want  int
	}{{raw, 401}, {documentRaw, 405}} {
		r := httptest.NewRequest("GET", "/internal/documents", nil)
		r.Header.Set("Authorization", "Bearer "+tc.token)
		w := httptest.NewRecorder()
		documentServer.Handler.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatal("document listener scope", w.Code, tc.want)
		}
	}
	for _, client := range []struct {
		id, subject string
		paths       map[string]int
	}{
		{"rac-match-standing", "machine-subject", map[string]int{"/internal/standing": 405, "/internal/standing/replay/events": 405, "/internal/standing/replay/accounts": 401}},
		{"rac-alert-standing", "alert-subject", map[string]int{"/internal/standing": 401, "/internal/standing/replay/events": 405, "/internal/standing/replay/accounts": 405}},
	} {
		claims["azp"], claims["sub"] = client.id, client.subject
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "reader"
		raw, err := token.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		for path, want := range client.paths {
			r := httptest.NewRequest("GET", path, nil)
			r.Header.Set("Authorization", "Bearer "+raw)
			w := httptest.NewRecorder()
			server.Handler.ServeHTTP(w, r)
			if w.Code != want {
				t.Fatal("standing purpose isolation", client.id, path, w.Code, want)
			}
		}
	}

	// Identity has its own audience and only match may read it.
	t.Setenv("IDENTITY_ENFORCEMENT_ENABLED", "true")
	identityServer, err := StandingAuthorityFromEnvironment(nil, identitySourceFunc(nil))
	if err != nil {
		t.Fatal(err)
	}
	identityToken := func(azp, subject string) string {
		c := jwt.MapClaims{"iss": issuer, "aud": "rac-identity", "sub": subject, "azp": azp, "typ": "Bearer", "iat": time.Now().Unix(), "exp": time.Now().Add(300 * time.Second).Unix(), "resource_access": map[string]any{"rac-identity": map[string]any{"roles": []string{"identity.read"}}}}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
		token.Header["kid"] = "reader"
		signed, err := token.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	for name, tc := range map[string]struct {
		token string
		want  int
	}{
		"standing token":       {raw, 401},
		"document token":       {documentRaw, 401},
		"match identity":       {identityToken("rac-match-standing", "machine-subject"), 405},
		"chat identity":        {identityToken("rac-chat-standing", "chat-subject"), 401},
		"match wrong subject":  {identityToken("rac-match-standing", "chat-subject"), 401},
		"alert identity token": {identityToken("rac-alert-standing", "alert-subject"), 401},
	} {
		r := httptest.NewRequest("GET", "/internal/identity", nil)
		r.Header.Set("Authorization", "Bearer "+tc.token)
		w := httptest.NewRecorder()
		identityServer.Handler.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatal("identity listener scope", name, w.Code, tc.want)
		}
	}
	w := httptest.NewRecorder()
	documentServer.Handler.ServeHTTP(w, httptest.NewRequest("GET", "/internal/identity", nil))
	if w.Code != 404 {
		t.Fatal("identity authority mounted without rollout", w.Code)
	}
}

type identitySourceFunc func(platformidentity.Query) (platformidentity.Observation, error)

func (f identitySourceFunc) ReadIdentity(_ context.Context, q platformidentity.Query) (platformidentity.Observation, error) {
	return f(q)
}

func TestIdentityAuthorityRolloutConfiguration(t *testing.T) {
	for _, value := range []string{"yes", "TRUE", "1"} {
		t.Setenv("IDENTITY_ENFORCEMENT_ENABLED", value)
		if _, err := StandingAuthorityFromEnvironment(nil, identitySourceFunc(nil)); err == nil {
			t.Fatal("invalid identity rollout accepted", value)
		}
	}
	t.Setenv("IDENTITY_ENFORCEMENT_ENABLED", "true")
	t.Setenv("STANDING_ENFORCEMENT_ENABLED", "false")
	if _, err := StandingAuthorityFromEnvironment(nil, identitySourceFunc(nil)); err == nil {
		t.Fatal("identity authority without standing accepted")
	}
	t.Setenv("STANDING_ENFORCEMENT_ENABLED", "true")
	if _, err := StandingAuthorityFromEnvironment(nil, nil); err == nil {
		t.Fatal("identity authority without a provider accepted")
	}
	t.Setenv("IDENTITY_PROVIDER", "")
	if _, err := IdentityFromEnvironment(nil); err == nil {
		t.Fatal("identity enforcement without a provider accepted")
	}
	t.Setenv("IDENTITY_ENFORCEMENT_ENABLED", "false")
	t.Setenv("IDENTITY_PROVIDER", "real-vendor")
	if _, err := IdentityFromEnvironment(nil); err == nil {
		t.Fatal("unsupported provider accepted")
	}
	t.Setenv("IDENTITY_PROVIDER", "fake")
	t.Setenv("RAC_ENV", "prd")
	dir := t.TempDir()
	for name, value := range map[string]string{"webhook": strings.Repeat("w", 32), "fingerprint": strings.Repeat("k", 32)} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("IDENTITY_WEBHOOK_SECRET_FILE", filepath.Join(dir, "webhook"))
	t.Setenv("IDENTITY_FINGERPRINT_KEY_FILE", filepath.Join(dir, "fingerprint"))
	t.Setenv("IDENTITY_FINGERPRINT_KEY_ID", "k1")
	t.Setenv("IDENTITY_FAKE_BASE_URL", "http://localhost")
	if _, err := IdentityFromEnvironment(nil); err == nil {
		t.Fatal("fake provider accepted outside dev/test")
	}
}

func TestStandingReaderConfiguration(t *testing.T) {
	for _, cfg := range []StandingReaderConfig{
		{},
		{Issuer: "http://issuer", JWKS: "https://keys", Audience: "rac-standing", Subjects: map[string]string{"client": "subject"}},
		{Issuer: "https://issuer", JWKS: "https://user:password@keys", Audience: "rac-standing", Subjects: map[string]string{"client": "subject"}},
		{Issuer: "https://issuer", JWKS: "https://keys?secret=x", Audience: "rac-standing", Subjects: map[string]string{"client": "subject"}},
		{Issuer: "https://issuer", JWKS: "https://keys", Audience: "rac-standing", Subjects: map[string]string{"client": "subject", "other": "subject"}},
		{Issuer: "https://issuer", JWKS: "https://keys", Audience: "rac-standing", Subjects: map[string]string{"client": ""}},
	} {
		if auth, err := NewStandingReader(cfg); err == nil || auth != nil {
			t.Fatal("unsafe configuration accepted")
		}
	}
}

func TestDocumentAuthorityRolloutConfiguration(t *testing.T) {
	for _, value := range []string{"yes", "TRUE", "1"} {
		t.Setenv("DOCUMENTS_ENFORCEMENT_ENABLED", value)
		if _, err := StandingAuthorityFromEnvironment(nil, nil); err == nil {
			t.Fatal("invalid document rollout accepted")
		}
	}
	t.Setenv("DOCUMENTS_ENFORCEMENT_ENABLED", "true")
	t.Setenv("STANDING_ENFORCEMENT_ENABLED", "false")
	if _, err := StandingAuthorityFromEnvironment(nil, nil); err == nil {
		t.Fatal("document authority without standing accepted")
	}
}
