// Package transport carries authority snapshots over authenticated HTTP. It has
// no permissive authentication default and never sends credentials on redirects.
package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

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
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Scheme != "https" && !(allowDEVHTTP && u.Scheme == "http")) || token == nil {
		return nil, errors.New("invalid standing authority configuration")
	}
	return &Client{endpoint: strings.TrimSuffix(endpoint, "/"), token: token, client: &http.Client{
		Timeout:       1500 * time.Millisecond,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

type request struct {
	Subject string `json:"subject"`
}
type response struct {
	Subject  string            `json:"subject"`
	Snapshot standing.Snapshot `json:"snapshot"`
}

func decode(reader io.Reader, value any) error {
	d := json.NewDecoder(reader)
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

func (c *Client) Load(ctx context.Context, subject string) (standing.Snapshot, error) {
	var result response
	if err := c.exchange(ctx, c.endpoint, subject, &result); err != nil || result.Subject != subject || result.Snapshot.Version == 0 || len(result.Snapshot.Restrictions) > 50 {
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
	ctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	token, err := c.token(ctx)
	if err != nil || token == "" {
		return standing.ErrUnavailable
	}
	body, err := json.Marshal(input)
	if err != nil {
		return standing.ErrUnavailable
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return standing.ErrUnavailable
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	reply, err := c.client.Do(r)
	if err != nil {
		return standing.ErrUnavailable
	}
	defer reply.Body.Close()
	if reply.StatusCode != http.StatusOK {
		return standing.ErrUnavailable
	}
	data, readErr := io.ReadAll(io.LimitReader(reply.Body, int64(limit)+1))
	if readErr != nil || len(data) > limit || decode(bytes.NewReader(data), result) != nil {
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
		if err != nil || s.Version == 0 {
			http.Error(w, "unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response{in.Subject, s})
	})
}

var _ standing.Source = (*Client)(nil)
