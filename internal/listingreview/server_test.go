package listingreview

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cazocarma/rac-platform/staff"
	"github.com/cazocarma/rac-user-service/internal/config"
	httpapi "github.com/cazocarma/rac-user-service/internal/http"
	"github.com/golang-jwt/jwt/v5"
)

const fixtureID = "11111111-1111-4111-8111-111111111111"

func TestReaderNotOnPublicRouter(t *testing.T) {
	public := httpapi.New(nil, config.Config{}).Router()
	for _, path := range []string{"/internal/listings/queue", "/internal/listings/revisions/" + fixtureID} {
		w := httptest.NewRecorder()
		public.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 404 {
			t.Fatal("private listing route exposed on public API", path, w.Code)
		}
	}
}

func readerAccess(t *testing.T) (*staff.Access, func(string, string, ...string) string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keys := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "reader-fixture", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	}))
	t.Cleanup(keys.Close)
	access, err := staff.New("https://fixture.example/realms/rac", keys.URL, staff.ListingsAudience)
	if err != nil {
		t.Fatal(err)
	}
	return access, func(role, audience string, subjects ...string) string {
		now := time.Now().Unix()
		claims := jwt.MapClaims{"iss": "https://fixture.example/realms/rac", "aud": audience, "sub": fixtureID, "typ": "Bearer", "azp": staff.ClientID, "iat": now, "exp": now + 120, "auth_time": now - 30, "amr": []string{"pwd", "otp"}, "resource_access": map[string]any{staff.ClientID: map[string]any{"roles": []string{role}}}, "realm_access": map[string]any{"roles": []string{"admin"}}}
		if len(subjects) > 0 {
			claims["sub"] = subjects[0]
		}
		signed := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		signed.Header["kid"] = "reader-fixture"
		value, err := signed.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
}

func TestReaderAuthorizationBeforePersistence(t *testing.T) {
	access, token := readerAccess(t)
	handler := (&Server{access: access, policy: fixtureID, now: time.Now}).Handler()
	for _, path := range []string{"/internal/listings/queue", "/internal/listings/revisions/" + fixtureID} {
		for _, tc := range []struct {
			role, audience string
			want           int
		}{
			{"", "", 401}, {"legal", staff.ListingsAudience, 403}, {"support", staff.ListingsAudience, 403},
			{"business_admin", staff.ListingsAudience, 403}, {"admin", staff.ListingsAudience, 403},
			{"ts_agent", staff.AdminAudience, 401}, {"ts_lead", staff.DocumentsAudience, 401},
		} {
			req := httptest.NewRequest("GET", path, nil)
			if tc.role != "" {
				req.Header.Set("Authorization", "Bearer "+token(tc.role, tc.audience))
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Fatalf("%s role=%s audience=%s: got %d want %d", path, tc.role, tc.audience, w.Code, tc.want)
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("private response cacheable")
			}
		}
	}
	// A valid staff session still cannot supply ambiguous parameters or asserted
	// authority. A nil DB makes any accidental persistence access fail the test.
	for _, role := range []string{"ts_agent", "ts_lead"} {
		credential := token(role, staff.ListingsAudience)
		for _, path := range []string{
			"/internal/listings/queue?limit=0", "/internal/listings/queue?limit=51",
			"/internal/listings/queue?limit=2&limit=3", "/internal/listings/queue?actor=" + fixtureID,
			"/internal/listings/queue?cursor=", "/internal/listings/queue?cursor=not-json",
			"/internal/listings/queue?", "/internal/listings/queue?limit=%ZZ",
			"/internal/listings/revisions/not-a-uuid", "/internal/listings/revisions/" + fixtureID + "?actor=" + fixtureID,
		} {
			req := httptest.NewRequest("GET", path, nil)
			req.Header.Set("Authorization", "Bearer "+credential)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != 400 {
				t.Fatalf("role=%s path=%s: got %d", role, path, w.Code)
			}
		}
		req := httptest.NewRequest("GET", "/internal/listings/queue", strings.NewReader(`{"actor":"forged"}`))
		req.Header.Set("Authorization", "Bearer "+credential)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != 400 {
			t.Fatal("GET body reached persistence", w.Code)
		}
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/ready", nil))
	if w.Code != 503 {
		t.Fatal("unconfigured DB reported ready")
	}
}

func TestReaderCursorRequiresCompleteUnambiguousPosition(t *testing.T) {
	encode := func(raw string) string { return base64.RawURLEncoding.EncodeToString([]byte(raw)) }
	valid := `{"risk":0,"at":"2026-11-02T12:00:00.123456Z","id":"` + fixtureID + `"}`
	value, stamp, err := decodeCursor(encode(valid))
	if err != nil || value.Risk != 0 || stamp.Nanosecond() != 123456000 {
		t.Fatal("valid zero risk cursor rejected", err)
	}
	for _, raw := range []string{
		`{"at":"2026-11-02T12:00:00Z","id":"` + fixtureID + `"}`,
		strings.Replace(valid, `"risk":0`, `"risk":null`, 1),
		strings.Replace(valid, `"risk":0`, `"risk":-1`, 1),
		strings.Replace(valid, `"risk":0`, `"risk":101`, 1),
		strings.Replace(valid, `"risk":0`, `"risk":0,"risk":1`, 1),
		strings.Replace(valid, `"risk":0`, `"risk":0,"actor":"forged"`, 1),
		strings.Replace(valid, fixtureID, "00000000-0000-0000-0000-000000000000", 1),
		strings.Replace(valid, "12:00:00.123456Z", "12:00:00.123456+03:00", 1),
		valid + `{}`,
	} {
		if _, _, err := decodeCursor(encode(raw)); err == nil {
			t.Fatal("ambiguous cursor accepted", raw)
		}
	}
	for _, raw := range []string{"!", strings.Repeat("a", 513), encode(valid) + "="} {
		if _, _, err := decodeCursor(raw); err == nil {
			t.Fatal("invalid encoding accepted")
		}
	}
}
