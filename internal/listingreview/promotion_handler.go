package listingreview

import (
	"context"
	"net/http"
	"time"

	"github.com/cazocarma/rac-platform/staff"
)

func (a *photoApprover) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /internal/listings/revisions/{id}/photo-approval", a.owner.access.Require(staff.ListingsReview, http.HandlerFunc(a.serveApproval)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
}

func (a *photoApprover) serveApproval(w http.ResponseWriter, r *http.Request) {
	id, version, command, ok := readApprovalCommand(w, r)
	if !ok {
		return
	}
	session, ok := staff.Principal(r.Context())
	if !ok {
		problem(w, 401, "staff_authentication_required")
		return
	}
	select {
	case a.slots <- struct{}{}:
		defer func() { <-a.slots }()
	default:
		problem(w, 503, "listing_review_unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
	defer cancel()
	raw, err := a.approve(ctx, session, id, version, command)
	if err != nil {
		approvalFailure(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write(raw)
}
