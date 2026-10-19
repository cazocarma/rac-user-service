package platform

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestJWTValidation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "test", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	}))
	defer server.Close()
	s := NewSecurity("https://issuer.example/realms/rac", server.URL, "rac-api")
	for _, tc := range []struct {
		name, issuer, audience, typ string
		expiry                      time.Time
		tamper, wantOK              bool
	}{
		{"valid", "https://issuer.example/realms/rac", "rac-api", "Bearer", time.Now().Add(time.Hour), false, true},
		{"wrong issuer", "https://attacker.example", "rac-api", "Bearer", time.Now().Add(time.Hour), false, false},
		{"wrong audience", "https://issuer.example/realms/rac", "another-api", "Bearer", time.Now().Add(time.Hour), false, false},
		{"expired", "https://issuer.example/realms/rac", "rac-api", "Bearer", time.Now().Add(-time.Hour), false, false},
		{"id token", "https://issuer.example/realms/rac", "rac-api", "ID", time.Now().Add(time.Hour), false, false},
		{"bad signature", "https://issuer.example/realms/rac", "rac-api", "Bearer", time.Now().Add(time.Hour), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": tc.issuer, "aud": tc.audience, "sub": "user-1", "exp": tc.expiry.Unix(), "iat": time.Now().Unix(), "typ": tc.typ, "realm_access": map[string]any{"roles": []string{"compa", "cliente"}}})
			token.Header["kid"] = "test"
			signingKey := key
			if tc.tamper {
				signingKey, _ = rsa.GenerateKey(rand.Reader, 2048)
			}
			raw, err := token.SignedString(signingKey)
			if err != nil {
				t.Fatal(err)
			}
			claims, err := s.VerifyToken(context.Background(), raw)
			if (err == nil) != tc.wantOK {
				t.Fatalf("valid=%v want=%v err=%v", err == nil, tc.wantOK, err)
			}
			if tc.wantOK && (claims.Subject != "user-1" || !claims.HasRole("cliente") || claims.HasRole("admin")) {
				t.Fatal("wrong principal")
			}
		})
	}
	if _, err := s.VerifyToken(context.Background(), "not-a-token"); err == nil {
		t.Fatal("malformed token accepted")
	}
}
func TestRoleInheritanceAndHTTP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		role, required string
		want           int
	}{{"compa", "cliente", 200}, {"cliente", "compa", 403}, {"compa", "admin", 403}, {"admin", "compa", 200}, {"unknown", "cliente", 403}} {
		t.Run(tc.role+tc.required, func(t *testing.T) {
			s := &Security{VerifyToken: func(context.Context, string) (*Claims, error) {
				p := &Claims{Subject: "subject"}
				p.RealmAccess.Roles = []string{tc.role}
				return p, nil
			}}
			r := gin.New()
			r.GET("/private", s.Require(tc.required), func(c *gin.Context) { c.String(200, Principal(c).Subject) })
			req := httptest.NewRequest("GET", "/private", nil)
			req.Header.Set("Authorization", "Bearer token")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d", w.Code, tc.want)
			}
			w = httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest("GET", "/private", nil))
			if w.Code != 401 {
				t.Fatal("anonymous request accepted")
			}
		})
	}
}
