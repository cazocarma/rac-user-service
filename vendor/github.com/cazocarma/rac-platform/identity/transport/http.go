// Package transport exchanges identity observations over authenticated HTTP.
package transport

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/cazocarma/rac-platform/identity"
	"github.com/cazocarma/rac-platform/internal/authorityhttp"
	standingtransport "github.com/cazocarma/rac-platform/standing/transport"
)

const maxBody = 1024

type TokenProvider func(context.Context) (string, error)

type Client struct {
	endpoint string
	client   *http.Client
	token    TokenProvider
}

func NewClient(endpoint string, token TokenProvider, allowDEVHTTP bool) (*Client, error) {
	client, err := authorityhttp.New(endpoint, allowDEVHTTP)
	if err != nil || token == nil {
		return nil, identity.ErrUnavailable
	}
	return &Client{strings.TrimSuffix(endpoint, "/"), client, token}, nil
}

// NewServiceClient validates the mounted credential before startup and uses
// the bounded client-credentials flow shared with standing and documents.
func NewServiceClient(endpoint, tokenEndpoint, clientID, secretFile string, allowDEVHTTP bool) (*Client, error) {
	file, err := os.Open(secretFile)
	if err != nil {
		return nil, identity.ErrUnavailable
	}
	defer file.Close()
	secret, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(secret) > 4096 || len(strings.TrimSpace(string(secret))) < 32 {
		return nil, identity.ErrUnavailable
	}
	provider, err := standingtransport.CredentialsToken(tokenEndpoint, clientID, secretFile, allowDEVHTTP)
	if err != nil {
		return nil, identity.ErrUnavailable
	}
	return NewClient(endpoint, TokenProvider(provider), allowDEVHTTP)
}

func (c *Client) ReadIdentity(ctx context.Context, q identity.Query) (identity.Observation, error) {
	var o identity.Observation
	if c == nil || !q.Valid() || authorityhttp.Exchange(ctx, c.client, c.endpoint, c.token, q, maxBody, &o) != nil || o.Query != q {
		return identity.Observation{}, identity.ErrUnavailable
	}
	return o, nil
}

// Handler answers identity queries. authenticate must verify issuer,
// audience, expiry and the provisioned reader before the body is decoded.
// Mount only on an internal listener, never on the public API router.
func Handler(source identity.Source, authenticate func(*http.Request) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if authenticate == nil || authenticate(r) != nil {
			http.Error(w, "unauthorized", 401)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", 405)
			return
		}
		var q identity.Query
		if authorityhttp.Decode(http.MaxBytesReader(w, r.Body, maxBody), &q) != nil || !q.Valid() {
			http.Error(w, "invalid request", 400)
			return
		}
		if source == nil {
			http.Error(w, "unavailable", 503)
			return
		}
		o, err := source.ReadIdentity(r.Context(), q)
		if err != nil || o.Query != q {
			http.Error(w, "unavailable", 503)
			return
		}
		body, err := json.Marshal(o)
		if err != nil || len(body) > maxBody {
			http.Error(w, "unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
}

// Problem is the public precondition body shared by every gated writer.
type Problem struct {
	Error   string           `json:"error"`
	Purpose identity.Purpose `json:"purpose,omitempty"`
	Flow    string           `json:"flow,omitempty"`
}

// Failure maps a check error to the public response. The flow is the app's
// verification route for that purpose; no verification detail is disclosed.
func Failure(err error, purpose identity.Purpose) (int, Problem) {
	if err == identity.ErrRequired && purpose.Valid() {
		return 428, Problem{Error: "IDENTITY_VERIFICATION_REQUIRED", Purpose: purpose, Flow: "/identity?purpose=" + string(purpose)}
	}
	return 503, Problem{Error: "identity_unavailable"}
}
