// Package transport exchanges document observations over authenticated HTTP.
package transport

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/cazocarma/rac-platform/documents"
	"github.com/cazocarma/rac-platform/internal/authorityhttp"
)

const maxBody = 16384

type TokenProvider func(context.Context) (string, error)
type Client struct {
	endpoint string
	client   *http.Client
	token    TokenProvider
}

func NewClient(endpoint string, token TokenProvider, allowDEVHTTP bool) (*Client, error) {
	client, err := authorityhttp.New(endpoint, allowDEVHTTP)
	if err != nil || token == nil {
		return nil, documents.ErrUnavailable
	}
	return &Client{strings.TrimSuffix(endpoint, "/"), client, token}, nil
}
func valid(o documents.Observation, q documents.Query) bool {
	if !q.Valid() || o.Query != q || o.Revision == 0 || len(o.Snapshot.Documents) > 5 || len(o.Snapshot.Acceptances) > 5 {
		return false
	}
	err := documents.RequireAcceptedDocuments(o.Snapshot, q.Role, q.Capability)
	return err == nil || errors.Is(err, documents.ErrRequired)
}
func (c *Client) ReadDocuments(ctx context.Context, q documents.Query) (documents.Observation, error) {
	var o documents.Observation
	if c == nil || !q.Valid() || authorityhttp.Exchange(ctx, c.client, c.endpoint, c.token, q, maxBody, &o) != nil || !valid(o, q) {
		return documents.Observation{}, documents.ErrUnavailable
	}
	return o, nil
}

// authenticate must verify issuer, audience, expiry and provisioned reader
// identity/scope. Authorization is mandatory and runs before decoding the body.
// Mount only on an internal listener, never on the public API router.
func Handler(source documents.Source, authenticate func(*http.Request) error) http.Handler {
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
		var q documents.Query
		if authorityhttp.Decode(http.MaxBytesReader(w, r.Body, maxBody), &q) != nil || !q.Valid() {
			http.Error(w, "invalid request", 400)
			return
		}
		if source == nil {
			http.Error(w, "unavailable", 503)
			return
		}
		o, err := source.ReadDocuments(r.Context(), q)
		if err != nil || !valid(o, q) {
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

var _ documents.Source = (*Client)(nil)
