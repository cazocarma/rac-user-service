package transport

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/cazocarma/rac-platform/standing"
)

// Head shares the authenticated authority client but never grants a lease.
func (c *Client) Head(ctx context.Context, subject string) (standing.ReplayHead, error) {
	var h standing.ReplayHead
	if !standing.ValidAccountID(subject) {
		return h, standing.ErrUnavailable
	}
	if err := c.exchange(ctx, c.endpoint+"/replay", subject, &h); err != nil || h.Subject != subject || !h.Valid() {
		return standing.ReplayHead{}, standing.ErrUnavailable
	}
	return h, nil
}

// ReplayHandler is an internal recovery surface. Its authenticator should
// restrict replay to the service that owns the corresponding projections.
func ReplayHandler(source standing.ReplaySource, authenticate func(*http.Request) error) http.Handler {
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
		if decode(http.MaxBytesReader(w, r.Body, maxBody), &in) != nil || !standing.ValidAccountID(in.Subject) {
			http.Error(w, "invalid request", 400)
			return
		}
		if source == nil {
			http.Error(w, "unavailable", 503)
			return
		}
		h, err := source.Head(r.Context(), in.Subject)
		if err != nil || h.Subject != in.Subject || !h.Valid() {
			http.Error(w, "unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(h)
	})
}
