package transport

import (
	"context"
	"encoding/json"
	"github.com/cazocarma/rac-platform/standing"
	"net/http"
)

type discoveryRequest struct {
	After string `json:"after"`
}

func (c *Client) Discover(ctx context.Context, after string) (standing.DiscoveryPage, error) {
	var page standing.DiscoveryPage
	if after != "" && !standing.ValidAccountID(after) {
		return page, standing.ErrUnavailable
	}
	if err := c.exchangePayload(ctx, c.endpoint+"/replay/accounts", discoveryRequest{after}, maxBody, &page); err != nil || page.After != after || !page.Valid() {
		return standing.DiscoveryPage{}, standing.ErrUnavailable
	}
	return page, nil
}

func DiscoveryHandler(source standing.DiscoverySource, authenticate func(*http.Request) error) http.Handler {
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
		var in discoveryRequest
		if decode(http.MaxBytesReader(w, r.Body, maxBody), &in) != nil || (in.After != "" && !standing.ValidAccountID(in.After)) {
			http.Error(w, "invalid request", 400)
			return
		}
		if source == nil {
			http.Error(w, "unavailable", 503)
			return
		}
		page, err := source.Discover(r.Context(), in.After)
		if err != nil || page.After != in.After || !page.Valid() {
			http.Error(w, "unavailable", 503)
			return
		}
		data, err := json.Marshal(page)
		if err != nil || len(data) > maxBody {
			http.Error(w, "unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	})
}
