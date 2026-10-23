package platform

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
