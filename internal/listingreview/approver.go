package listingreview

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cazocarma/rac-platform/audit"
	"github.com/cazocarma/rac-platform/staff"
	staffdb "github.com/cazocarma/rac-platform/staff/postgres"
	"github.com/cazocarma/rac-user-service/internal/listings"
	"github.com/cazocarma/rac-user-service/internal/strictjson"
	"github.com/lib/pq"
)

const approvalContextSignature = "listing_review.approval_context(audit.reference,audit.reference,bigint,audit.digest)"
const approvalSignature = "listing_review.approve(audit.reference,audit.reference,audit.reference,audit.reference,bigint,audit.digest,text,jsonb,boolean)"

var approvalSignatures = []string{readySignature, approvalContextSignature, approvalSignature}

// ApprovalPolicy comes from server configuration, never from the request.
type ApprovalPolicy struct {
	ListingPolicy           string
	AllowProposedActivities bool
}

// Approver uses a third function-only login: no content reads, no
// corrections. The owner database handle only evaluates prerequisites.
type Approver struct {
	owner         *Server
	ownerDB       *sql.DB
	prerequisites listings.Prerequisites
	approval      ApprovalPolicy
}

func NewApprover(ctx context.Context, db, ownerDB *sql.DB, access *staff.Access, policy string, approval ApprovalPolicy, prerequisites listings.Prerequisites) (*Approver, error) {
	if ownerDB == nil || prerequisites == nil || !reviewVersion.MatchString(approval.ListingPolicy) {
		return nil, errors.New("invalid listing approval configuration")
	}
	owner, err := newServer(ctx, db, access, policy, functionPolicy(approvalSignatures))
	if err != nil {
		return nil, err
	}
	return &Approver{owner: owner, ownerDB: ownerDB, prerequisites: prerequisites, approval: approval}, nil
}

func (a *Approver) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ready", a.owner.ready)
	mux.Handle("POST /internal/listings/revisions/{id}/approval", a.owner.access.Require(staff.ListingsReview, http.HandlerFunc(a.approve)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
}

type approvalCommand struct {
	EventID         string `json:"event_id"`
	ExpectedVersion string `json:"expected_version"`
	SHA256          string `json:"sha256"`
}

func readApprovalCommand(w http.ResponseWriter, r *http.Request) (string, int64, approvalCommand, bool) {
	id := r.PathValue("id")
	media, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || len(params) > 1 || (len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8")) || r.URL.RawQuery != "" || r.URL.ForceQuery || !audit.ValidID(id) {
		problem(w, 400, "invalid_listing_review_command")
		return "", 0, approvalCommand{}, false
	}
	var command approvalCommand
	if strictjson.Decode(http.MaxBytesReader(w, r.Body, 4096), &command) != nil || !audit.ValidID(command.EventID) || !decimalVersion.MatchString(command.ExpectedVersion) || !reviewDigest.MatchString(command.SHA256) {
		problem(w, 400, "invalid_listing_review_command")
		return "", 0, approvalCommand{}, false
	}
	version, err := strconv.ParseInt(command.ExpectedVersion, 10, 64)
	if err != nil || version == 9223372036854775807 {
		problem(w, 400, "invalid_listing_review_command")
		return "", 0, approvalCommand{}, false
	}
	return id, version, command, true
}

func (a *Approver) approve(w http.ResponseWriter, r *http.Request) {
	id, version, command, ok := readApprovalCommand(w, r)
	if !ok {
		return
	}
	session, ok := staff.Principal(r.Context())
	if !ok {
		problem(w, 401, "staff_authentication_required")
		return
	}
	raw, err := a.decide(r.Context(), session, id, version, command)
	if err != nil {
		approvalFailure(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write(raw)
}

// decide mirrors Server.transaction, with the owner-side evaluation between
// locking the listing and recording the decision. Both transactions end
// together: the evaluation's locks are released only after the commit.
func (a *Approver) decide(parent context.Context, session staff.Session, id string, version int64, command approvalCommand) ([]byte, error) {
	s := a.owner
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	if staffdb.CheckRole(ctx, s.db, s.authority) != nil {
		return nil, errUnavailable
	}
	if err := session.Check(staff.ListingsReview, s.now()); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, errUnavailable
	}
	defer tx.Rollback()
	var rawContext []byte
	if err = tx.QueryRowContext(ctx, `SELECT listing_review.approval_context($1,$2,$3,$4)`, command.EventID, id, version, command.SHA256).Scan(&rawContext); err != nil {
		return nil, err
	}
	requirements, ownerTx, err := checkedApprovalRequirements(ctx, a.ownerDB, a.prerequisites, a.approval.AllowProposedActivities, rawContext)
	if err != nil {
		return nil, err
	}
	if ownerTx != nil {
		defer ownerTx.Rollback()
	}
	var raw []byte
	if err = tx.QueryRowContext(ctx, `SELECT listing_review.approve($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		command.EventID, session.Subject, s.policy, id, version, command.SHA256,
		a.approval.ListingPolicy, string(requirements), a.approval.AllowProposedActivities).Scan(&raw); err != nil {
		return nil, err
	}
	if len(raw) > 128*1024 || !json.Valid(raw) {
		return nil, errUnavailable
	}
	if err = session.Check(staff.ListingsReview, s.now()); err != nil {
		return nil, err
	}
	if tx.Commit() != nil {
		return nil, errUnavailable
	}
	return raw, nil
}

// Publication-state failures name their cause so the console can explain why
// the approval did not happen; the owner must correct and resubmit.
var approvalStates = map[string]bool{
	"listing_not_publishable":      true,
	"listing_policy_changed":       true,
	"listing_owner_restricted":     true,
	"listing_activity_unavailable": true,
	"listing_photo_unapproved":     true,
}

func approvalFailure(w http.ResponseWriter, err error) {
	if errors.Is(err, listings.ErrPrerequisites) {
		problem(w, 409, listings.ErrPrerequisites.Error())
		return
	}
	var pg *pq.Error
	if errors.As(err, &pg) && pg.Code == "55000" && pg.Message == "listing_photo_authorization_expired" {
		problem(w, 403, "staff_step_up_required")
		return
	}
	if errors.As(err, &pg) && pg.Code == "55000" && approvalStates[pg.Message] {
		problem(w, 409, pg.Message)
		return
	}
	reviewFailure(w, err)
}
