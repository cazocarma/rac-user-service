// Package transport carries authority snapshots over authenticated HTTP. It has
// no permissive authentication default and never sends credentials on redirects.
package transport

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/cazocarma/rac-platform/internal/authorityhttp"
	"github.com/cazocarma/rac-platform/standing"
)

const maxBody = 32768

type TokenProvider func(context.Context) (string, error)
type Client struct {
	endpoint string
	client   *http.Client
	token    TokenProvider
}

// NewClient requires verified TLS except for explicitly enabled DEV fixtures.
// Tokens should be short-lived client credentials, scoped to standing reads.
func NewClient(endpoint string, token TokenProvider, allowDEVHTTP bool) (*Client, error) {
	client, err := authorityhttp.New(endpoint, allowDEVHTTP)
	if err != nil || token == nil {
		return nil, errors.New("invalid standing authority configuration")
	}
	return &Client{endpoint: strings.TrimSuffix(endpoint, "/"), token: token, client: client}, nil
}

type request struct {
	Subject string `json:"subject"`
}
type response struct {
	Subject  string            `json:"subject"`
	Snapshot standing.Snapshot `json:"snapshot"`
}

func decode(reader io.Reader, value any) error {
	return authorityhttp.Decode(reader, value)
}

func (c *Client) Load(ctx context.Context, subject string) (standing.Snapshot, error) {
	var result response
	if err := c.exchange(ctx, c.endpoint, subject, &result); err != nil || result.Subject != subject || result.Snapshot.Version == 0 || result.Snapshot.ObservedAt.IsZero() || len(result.Snapshot.Restrictions) > 50 {
		return standing.Snapshot{}, standing.ErrUnavailable
	}
	return result.Snapshot, nil
}

func (c *Client) exchange(ctx context.Context, endpoint, subject string, result any) error {
	if subject == "" || len(subject) > 64 {
		return standing.ErrUnavailable
	}
	return c.exchangePayload(ctx, endpoint, request{subject}, maxBody, result)
}

func (c *Client) exchangePayload(ctx context.Context, endpoint string, input any, limit int, result any) error {
	if authorityhttp.Exchange(ctx, c.client, endpoint, c.token, input, limit, result) != nil {
		return standing.ErrUnavailable
	}
	return nil
}

func (c *Client) LatestVersion(ctx context.Context, subject string) (uint64, error) {
	s, err := c.Load(ctx, subject)
	return s.Version, err
}

// Handler exposes the owner's source only after service authentication. The
// injected authenticator must verify issuer, audience, expiry and reader scope;
// checking only token presence or a commercial admin role is not sufficient.
func Handler(source standing.Source, authenticate func(*http.Request) error) http.Handler {
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
		var in request
		if decode(http.MaxBytesReader(w, r.Body, maxBody), &in) != nil || in.Subject == "" || len(in.Subject) > 64 {
			http.Error(w, "invalid request", 400)
			return
		}
		if source == nil {
			http.Error(w, "unavailable", 503)
			return
		}
		s, err := source.Load(r.Context(), in.Subject)
		if err != nil || s.Version == 0 || s.ObservedAt.IsZero() {
			http.Error(w, "unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response{in.Subject, s})
	})
}

var _ standing.Source = (*Client)(nil)
