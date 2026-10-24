package transport

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/cazocarma/rac-platform/standing"
)

// A page has at most 50 events of 8 KiB; this bound includes JSON metadata.
const maxReplayPage = 420000

type pageRequest struct {
	Subject string `json:"subject"`
	After   uint64 `json:"after"`
}

func (c *Client) Page(ctx context.Context, subject string, after uint64) (standing.ReplayPage, error) {
	var page standing.ReplayPage
	if !standing.ValidAccountID(subject) {
		return page, standing.ErrUnavailable
	}
	if err := c.exchangePayload(ctx, c.endpoint+"/replay/events", pageRequest{subject, after}, maxReplayPage, &page); err != nil || page.Subject != subject || page.After != after || !page.Valid() {
		return standing.ReplayPage{}, standing.ErrUnavailable
	}
	return page, nil
}

func ReplayPageHandler(source standing.ReplayPageSource, authenticate func(*http.Request) error) http.Handler {
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
		var in pageRequest
		if decode(http.MaxBytesReader(w, r.Body, maxBody), &in) != nil || !standing.ValidAccountID(in.Subject) {
			http.Error(w, "invalid request", 400)
			return
		}
		if source == nil {
			http.Error(w, "unavailable", 503)
			return
		}
		page, err := source.Page(r.Context(), in.Subject, in.After)
		if err != nil || page.Subject != in.Subject || page.After != in.After || !page.Valid() {
			http.Error(w, "unavailable", 503)
			return
		}
		data, err := json.Marshal(page)
		if err != nil || len(data) > maxReplayPage {
			http.Error(w, "unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	})
}
