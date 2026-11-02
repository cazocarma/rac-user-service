package listingreview

import (
	"context"
	"database/sql"
	"errors"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/cazocarma/rac-platform/audit"
	"github.com/cazocarma/rac-platform/staff"
	"github.com/cazocarma/rac-user-service/internal/strictjson"
	"github.com/lib/pq"
)

const correctionSignature = "listing_review.correct(audit.reference,audit.reference,audit.reference,audit.reference,bigint,audit.digest,text,text,text)"
const correctionReadySignature = "listing_review.correction_ready()"

var correctionSignatures = []string{readySignature, correctionSignature, correctionReadySignature}

var (
	errUnavailable = errors.New("listing_review_unavailable")
	reviewVersion  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	reviewReason   = regexp.MustCompile(`^[a-z][a-z0-9_]{1,63}$`)
	reviewDigest   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	decimalVersion = regexp.MustCompile(`^(0|[1-9][0-9]{0,18})$`)
)

// Corrector is separate from the reader: no raw tables, content-reading
// functions or publication approval are granted to its database login.
type Corrector struct{ owner *Server }

func NewCorrector(ctx context.Context, db *sql.DB, access *staff.Access, policy string) (*Corrector, error) {
	owner, err := newServer(ctx, db, access, policy, functionPolicy(correctionSignatures))
	if err != nil {
		return nil, err
	}
	owner.readiness = `SELECT listing_review.correction_ready()`
	return &Corrector{owner: owner}, nil
}

func (c *Corrector) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ready", c.owner.ready)
	mux.Handle("POST /internal/listings/revisions/{id}/decisions", c.owner.access.Require(staff.ListingsReview, http.HandlerFunc(c.owner.correct)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
}

type correctionCommand struct {
	EventID              string `json:"event_id"`
	ExpectedVersion      string `json:"expected_version"`
	SHA256               string `json:"sha256"`
	Decision             string `json:"decision"`
	ReasonCatalogVersion string `json:"reason_catalog_version"`
	ReasonCode           string `json:"reason_code"`
}

func (s *Server) correct(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	media, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || len(params) > 1 || (len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8")) || r.URL.RawQuery != "" || r.URL.ForceQuery || !audit.ValidID(id) {
		problem(w, 400, "invalid_listing_review_command")
		return
	}
	var command correctionCommand
	if strictjson.Decode(http.MaxBytesReader(w, r.Body, 4096), &command) != nil || !audit.ValidID(command.EventID) || !decimalVersion.MatchString(command.ExpectedVersion) || !reviewDigest.MatchString(command.SHA256) || !reviewVersion.MatchString(command.ReasonCatalogVersion) || !reviewReason.MatchString(command.ReasonCode) || (command.Decision != "rejected" && command.Decision != "changes_requested") {
		problem(w, 400, "invalid_listing_review_command")
		return
	}
	version, err := strconv.ParseInt(command.ExpectedVersion, 10, 64)
	if err != nil || version == 9223372036854775807 {
		problem(w, 400, "invalid_listing_review_command")
		return
	}
	session, ok := staff.Principal(r.Context())
	if !ok {
		problem(w, 401, "staff_authentication_required")
		return
	}
	raw, err := s.transaction(r.Context(), session, staff.ListingsReview,
		`SELECT listing_review.correct($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		command.EventID, session.Subject, s.policy, id, version, command.SHA256, command.Decision, command.ReasonCatalogVersion, command.ReasonCode)
	if err != nil {
		reviewFailure(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write(raw)
}

func reviewFailure(w http.ResponseWriter, err error) {
	if errors.Is(err, staff.ErrStepUp) || errors.Is(err, staff.ErrForbidden) || errors.Is(err, staff.ErrUnauthorized) {
		status, code := staff.Failure(err)
		problem(w, status, code)
		return
	}
	var pg *pq.Error
	if errors.As(err, &pg) {
		switch pg.Code {
		case "23505", "40001":
			problem(w, 409, "listing_review_conflict")
			return
		case "22023", "23514":
			problem(w, 400, "invalid_listing_review_command")
			return
		case "P0002":
			if pg.Message == "listing_revision_not_found" {
				problem(w, 404, "listing_revision_not_found")
				return
			}
		case "42501":
			if pg.Message == "listing_self_review" {
				problem(w, 403, "listing_self_review")
				return
			}
		}
	}
	problem(w, 503, "listing_review_unavailable")
}
