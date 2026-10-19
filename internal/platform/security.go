package platform

import (
	"context"
	"errors"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"net/http"
	"os"
	"strings"
	"time"
)

type Claims struct {
	Subject       string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Username      string `json:"preferred_username"`
	Type          string `json:"typ"`
	RealmAccess   struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
}

func (p *Claims) HasRole(role string) bool {
	for _, r := range p.RealmAccess.Roles {
		if r == "admin" || r == role || (r == "compa" && role == "cliente") {
			return true
		}
	}
	return false
}
func (p *Claims) Role() string {
	for _, role := range []string{"admin", "compa", "cliente"} {
		for _, r := range p.RealmAccess.Roles {
			if r == role {
				return role
			}
		}
	}
	return ""
}

type Security struct {
	VerifyToken func(context.Context, string) (*Claims, error)
}

func NewSecurity(issuer, jwks, audience string) *Security {
	client := &http.Client{Timeout: 5 * time.Second}
	ctx := oidc.ClientContext(context.Background(), client)
	keys := oidc.NewRemoteKeySet(ctx, jwks)
	verifier := oidc.NewVerifier(issuer, keys, &oidc.Config{ClientID: audience, SupportedSigningAlgs: []string{"RS256"}})
	return &Security{VerifyToken: func(ctx context.Context, raw string) (*Claims, error) {
		if issuer == "" || jwks == "" || audience == "" {
			return nil, errors.New("oidc_not_configured")
		}
		token, err := verifier.Verify(ctx, raw)
		if err != nil {
			return nil, err
		}
		var claims Claims
		if err = token.Claims(&claims); err != nil {
			return nil, err
		}
		if claims.Subject == "" || claims.Type != "Bearer" {
			return nil, errors.New("invalid_access_token")
		}
		return &claims, nil
	}}
}
func FromEnvironment() *Security {
	return NewSecurity(os.Getenv("OIDC_ISSUER"), os.Getenv("OIDC_JWKS_URL"), os.Getenv("OIDC_AUDIENCE"))
}
func Principal(c *gin.Context) *Claims { return c.MustGet("principal").(*Claims) }
func (s *Security) Require(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		parts := strings.Fields(c.GetHeader("Authorization"))
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			c.AbortWithStatusJSON(401, gin.H{"error": "authentication_required"})
			return
		}
		claims, err := s.VerifyToken(c.Request.Context(), parts[1])
		if err != nil {
			c.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
			c.AbortWithStatusJSON(401, gin.H{"error": "invalid_token"})
			return
		}
		if claims.Role() == "" {
			c.AbortWithStatusJSON(403, gin.H{"error": "role_required"})
			return
		}
		allowed := len(roles) == 0
		for _, role := range roles {
			if claims.HasRole(role) {
				allowed = true
			}
		}
		if !allowed {
			c.AbortWithStatusJSON(403, gin.H{"error": "forbidden"})
			return
		}
		c.Header("Cache-Control", "no-store")
		c.Set("principal", claims)
	}
}
