// Package staff verifies dedicated console identities independently of public
// application roles. A realm administrator is not a delegated legal reviewer.
package staff

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

const ClientID = "rac-staff"
const AdminAudience = "rac-admin-staff"
const DocumentsAudience = "rac-user-documents"
const MaxAuthenticationAge = 5 * time.Minute

type Permission string

const (
	SessionRead       Permission = "staff.session.read"
	DocumentsRead     Permission = "documents.read"
	DocumentsDraft    Permission = "documents.draft"
	DocumentsApprove  Permission = "documents.approve"
	DocumentsActivate Permission = "documents.activate"
	DocumentsPublish  Permission = "documents.publish"
)

var (
	ErrUnauthorized = errors.New("invalid staff credential")
	ErrStepUp       = errors.New("fresh staff MFA required")
	ErrForbidden    = errors.New("staff permission denied")
)
var accountID = regexp.MustCompile(`^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$`)

type claims struct {
	Subject   string   `json:"sub"`
	Type      string   `json:"typ"`
	Client    string   `json:"azp"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
	AuthTime  int64    `json:"auth_time"`
	Methods   []string `json:"amr"`
	Resources map[string]struct {
		Roles []string `json:"roles"`
	} `json:"resource_access"`
}

type Session struct {
	Subject         string       `json:"subject"`
	Permissions     []Permission `json:"permissions"`
	AuthenticatedAt time.Time    `json:"authenticated_at"`
	ExpiresAt       time.Time    `json:"expires_at"`
}

func (s Session) Allows(permission Permission) bool {
	for _, p := range s.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

type Access struct {
	verify func(context.Context, string) (claims, error)
	now    func() time.Time
}

func configuredURL(value string) bool {
	u, err := url.Parse(value)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}
func New(issuer, jwks, audience string) (*Access, error) {
	if !configuredURL(issuer) || !configuredURL(jwks) || (audience != AdminAudience && audience != DocumentsAudience) {
		return nil, errors.New("invalid staff OIDC configuration")
	}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx := oidc.ClientContext(context.Background(), client)
	verifier := oidc.NewVerifier(issuer, oidc.NewRemoteKeySet(ctx, jwks), &oidc.Config{ClientID: audience, SupportedSigningAlgs: []string{"RS256"}})
	return &Access{now: time.Now, verify: func(ctx context.Context, raw string) (claims, error) {
		var c claims
		token, err := verifier.Verify(ctx, raw)
		if err != nil {
			return c, ErrUnauthorized
		}
		if err = token.Claims(&c); err != nil {
			return c, ErrUnauthorized
		}
		return c, nil
	}}, nil
}

func (a *Access) Authenticate(ctx context.Context, raw string) (Session, error) {
	if a == nil || a.verify == nil || a.now == nil || raw == "" || len(raw) > 16384 {
		return Session{}, ErrUnauthorized
	}
	c, err := a.verify(ctx, raw)
	if err != nil {
		return Session{}, ErrUnauthorized
	}
	return validate(c, a.now())
}
func validate(c claims, now time.Time) (Session, error) {
	timestamp := now.Unix()
	if !accountID.MatchString(c.Subject) || c.Subject == "00000000-0000-0000-0000-000000000000" || c.Type != "Bearer" || c.Client != ClientID ||
		c.IssuedAt <= 0 || c.IssuedAt > timestamp || c.ExpiresAt <= timestamp || c.ExpiresAt <= c.IssuedAt || c.ExpiresAt-c.IssuedAt > int64(MaxAuthenticationAge/time.Second) {
		return Session{}, ErrUnauthorized
	}
	known, legal := false, false
	for _, role := range c.Resources[ClientID].Roles {
		switch role {
		case "legal":
			legal = true
			known = true
		case "ts_agent", "ts_lead", "support", "business_admin":
			known = true
		}
	}
	if !known {
		return Session{}, ErrForbidden
	}
	methods := map[string]bool{}
	for _, m := range c.Methods {
		methods[m] = true
	}
	if !methods["pwd"] || !methods["otp"] || c.AuthTime <= 0 || c.AuthTime > c.IssuedAt || timestamp-c.AuthTime >= int64(MaxAuthenticationAge/time.Second) {
		return Session{}, ErrStepUp
	}
	permissions := []Permission{SessionRead}
	if legal {
		permissions = append(permissions, DocumentsRead, DocumentsDraft, DocumentsApprove, DocumentsPublish, DocumentsActivate)
	}
	expires := time.Unix(c.ExpiresAt, 0).UTC()
	stepUpExpiry := time.Unix(c.AuthTime, 0).Add(MaxAuthenticationAge).UTC()
	if stepUpExpiry.Before(expires) {
		expires = stepUpExpiry
	}
	return Session{Subject: c.Subject, Permissions: permissions, AuthenticatedAt: time.Unix(c.AuthTime, 0).UTC(), ExpiresAt: expires}, nil
}

// Check revalidates a previously verified session at the final commit boundary.
// The owner must obtain the session from Require, never decode it from a body.
func (s Session) Check(permission Permission, now time.Time) error {
	if !accountID.MatchString(s.Subject) || s.Subject == "00000000-0000-0000-0000-000000000000" ||
		s.AuthenticatedAt.IsZero() || s.AuthenticatedAt.After(now) || !s.ExpiresAt.After(now) ||
		!s.AuthenticatedAt.Add(MaxAuthenticationAge).After(now) {
		return ErrStepUp
	}
	if !s.Allows(permission) {
		return ErrForbidden
	}
	return nil
}

type sessionKey struct{}

func Principal(ctx context.Context) (Session, bool) {
	session, ok := ctx.Value(sessionKey{}).(Session)
	return session, ok
}
func Failure(err error) (int, string) {
	if errors.Is(err, ErrStepUp) {
		return 403, "staff_step_up_required"
	}
	if errors.Is(err, ErrForbidden) {
		return 403, "staff_permission_denied"
	}
	return 401, "invalid_staff_token"
}
func (a *Access) Require(permission Permission, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		fail := func(status int, code string) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"` + code + `"}`))
		}
		fields := strings.Fields(r.Header.Get("Authorization"))
		if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
			fail(401, "staff_authentication_required")
			return
		}
		session, err := a.Authenticate(r.Context(), fields[1])
		if err == nil {
			err = session.Check(permission, a.now())
		}
		if err != nil {
			status, code := Failure(err)
			fail(status, code)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, session)))
	})
}
