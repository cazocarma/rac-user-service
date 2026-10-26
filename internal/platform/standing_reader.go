package platform

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

var errStandingReader = errors.New("standing_reader_unauthorized")

// StandingReaderConfig binds each allowed OAuth client to its provisioned
// service-account subject. Realm roles and human users never grant this access.
type StandingReaderConfig struct {
	Issuer, JWKS, Audience string
	Subjects               map[string]string
	AllowDevelopmentHTTP   bool
}

// NewStandingReader returns the authenticator expected by the authority HTTP
// handler. It verifies JWTs independently of the public API's role inheritance.
// Construct it once, after provisioning service accounts; configuration errors
// must prevent the internal endpoint from starting.
func NewStandingReader(cfg StandingReaderConfig) (func(*http.Request) error, error) {
	return newServiceReader(cfg, "standing.read")
}

// NewDocumentsReader requires a distinct document audience and permission;
// a standing-reader token alone cannot read document acceptance state.
func NewDocumentsReader(cfg StandingReaderConfig) (func(*http.Request) error, error) {
	if cfg.Audience != "rac-documents" {
		return nil, errStandingReader
	}
	return newServiceReader(cfg, "documents.read")
}

func newServiceReader(cfg StandingReaderConfig, permission string) (func(*http.Request) error, error) {
	validURL := func(raw string) bool {
		u, err := url.Parse(raw)
		return err == nil && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" &&
			(u.Scheme == "https" || (cfg.AllowDevelopmentHTTP && u.Scheme == "http"))
	}
	if !validURL(cfg.Issuer) || !validURL(cfg.JWKS) || strings.TrimSpace(cfg.Audience) != cfg.Audience || cfg.Audience == "" || len(cfg.Subjects) == 0 {
		return nil, errStandingReader
	}
	subjects := make(map[string]string, len(cfg.Subjects))
	seen := make(map[string]bool, len(cfg.Subjects))
	for client, subject := range cfg.Subjects {
		if client == "" || subject == "" || strings.TrimSpace(client) != client || strings.TrimSpace(subject) != subject || seen[subject] {
			return nil, errStandingReader
		}
		subjects[client], seen[subject] = subject, true
	}
	client := &http.Client{Timeout: 1500 * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx := oidc.ClientContext(context.Background(), client)
	verifier := oidc.NewVerifier(cfg.Issuer, oidc.NewRemoteKeySet(ctx, cfg.JWKS), &oidc.Config{
		ClientID: cfg.Audience, SupportedSigningAlgs: []string{"RS256"},
	})
	return func(r *http.Request) error {
		if r == nil || len(r.Header.Values("Authorization")) != 1 {
			return errStandingReader
		}
		parts := strings.Fields(r.Header.Get("Authorization"))
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) > 16384 {
			return errStandingReader
		}
		ctx, cancel := context.WithTimeout(r.Context(), 1500*time.Millisecond)
		defer cancel()
		token, err := verifier.Verify(ctx, parts[1])
		if err != nil {
			return errStandingReader
		}
		var claims struct {
			Client    string `json:"azp"`
			Type      string `json:"typ"`
			NotBefore *int64 `json:"nbf"`
			Access    map[string]struct {
				Roles []string `json:"roles"`
			} `json:"resource_access"`
		}
		if token.Claims(&claims) != nil || claims.Type != "Bearer" || subjects[claims.Client] == "" || subjects[claims.Client] != token.Subject {
			return errStandingReader
		}
		// A missing issued-at or a long-lived token cannot bypass the intended
		// short client-credentials lifetime. Permit at most five seconds of skew.
		now := time.Now()
		if token.IssuedAt.IsZero() || token.IssuedAt.After(now.Add(5*time.Second)) || !token.Expiry.After(token.IssuedAt) || token.Expiry.Sub(token.IssuedAt) > 300*time.Second || (claims.NotBefore != nil && time.Unix(*claims.NotBefore, 0).After(now.Add(5*time.Second))) {
			return errStandingReader
		}
		for _, role := range claims.Access[cfg.Audience].Roles {
			if role == permission {
				return nil
			}
		}
		return errStandingReader
	}, nil
}
