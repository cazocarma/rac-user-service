package listingreview

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/cazocarma/rac-platform/staff"
	staffdb "github.com/cazocarma/rac-platform/staff/postgres"
	"github.com/cazocarma/rac-user-service/internal/listings"
	"github.com/cazocarma/rac-user-service/internal/photostore"
)

const promotionResultSignature = "listing_review.photo_promotion_result(audit.reference,audit.reference,audit.reference,audit.reference,bigint,audit.digest,text,text,audit.reference)"
const promotionFinalizeSignature = "listing_review.finalize_photo_promotion(audit.reference,audit.reference,audit.reference,audit.reference,bigint,audit.digest,text,jsonb,boolean,audit.reference,audit.reference,text,bytea,integer,timestamp with time zone)"

var photoApprovalSignatures = []string{readySignature, approvalContextSignature, promotionPrepareSignature, promotionResultSignature, promotionFinalizeSignature}

// Internal coordinator; not registered on an ingress until runtime/provisioning
// and the corresponding staff UI gates are integrated and tested.
type photoApprover struct {
	owner         *Server
	ownerDB       *sql.DB
	prerequisites listings.Prerequisites
	allowProposed bool
	preparer      *promotionPreparer
	source        PreviewStore
	destination   promotionDestination
}

func newPhotoApprover(ctx context.Context, db, ownerDB *sql.DB, access *staff.Access, reviewPolicy string, policy promotionPolicy, allowProposed bool, prerequisites listings.Prerequisites, source PreviewStore, destination promotionDestination) (*photoApprover, error) {
	if ownerDB == nil || prerequisites == nil || source == nil || destination == nil || !policy.valid() {
		return nil, errors.New("invalid photo approval configuration")
	}
	owner, err := newServer(ctx, db, access, reviewPolicy, functionPolicy(photoApprovalSignatures))
	if err != nil {
		return nil, err
	}
	return &photoApprover{owner: owner, ownerDB: ownerDB, prerequisites: prerequisites, allowProposed: allowProposed,
		preparer: &promotionPreparer{owner: owner, policy: policy}, source: source, destination: destination}, nil
}

func (a *photoApprover) result(ctx context.Context, session staff.Session, revision string, version int64, command approvalCommand) ([]byte, error) {
	if !validPromotionCommand(revision, version, command) {
		return nil, errUnavailable
	}
	p := a.preparer.policy
	raw, err := a.owner.transaction(ctx, session, staff.ListingsReview, `SELECT listing_review.photo_promotion_result($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		command.EventID, session.Subject, a.owner.policy, revision, version, command.SHA256, p.Listing, p.Pipeline, p.Target)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}
	if !validPhotoApprovalResult(raw, revision, command.EventID) {
		return nil, errUnavailable
	}
	return raw, nil
}

func validPhotoApprovalResult(raw []byte, revision, event string) bool {
	var result struct {
		Revision string `json:"revision_id"`
		Event    string `json:"event_id"`
		Decision string `json:"decision"`
	}
	return len(raw) <= 128*1024 && json.Unmarshal(raw, &result) == nil && result.Revision == revision && result.Event == event && result.Decision == "approved"
}

func (a *photoApprover) approve(ctx context.Context, session staff.Session, revision string, version int64, command approvalCommand) ([]byte, error) {
	prior, err := a.result(ctx, session, revision, version, command)
	if err != nil || prior != nil {
		return prior, err
	}
	intent, err := a.preparer.prepare(ctx, session, revision, version, command)
	if err != nil {
		return nil, err
	}
	receipt, err := copyPreparedPhoto(ctx, session, intent, a.source, a.destination, a.owner.now)
	if err != nil {
		return nil, err
	}
	return a.finalize(ctx, session, intent, receipt, command)
}

func (a *photoApprover) finalize(parent context.Context, session staff.Session, intent promotionIntent, receipt promotionCopyReceipt, command approvalCommand) ([]byte, error) {
	if !intent.committed || intent.Actor != session.Subject || intent.Event != command.EventID || intent.SHA256 != command.SHA256 ||
		intent.ExpectedVersion != command.ExpectedVersion || receipt.intent != intent.ID || receipt.attempt != intent.Attempt ||
		receipt.key != intent.DestinationKey || !photostore.ValidVersionID(receipt.version) || receipt.size != intent.NormalizedSize {
		return nil, errUnavailable
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	s := a.owner
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
	if err := tx.QueryRowContext(ctx, `SELECT listing_review.approval_context($1,$2,$3,$4)`, command.EventID, intent.Revision, intent.ExpectedVersion, intent.SHA256).Scan(&rawContext); err != nil {
		return nil, err
	}
	requirements, ownerTx, err := checkedApprovalRequirements(ctx, a.ownerDB, a.prerequisites, a.allowProposed, rawContext)
	if err != nil {
		return nil, err
	}
	if ownerTx != nil {
		defer ownerTx.Rollback()
	}
	until := session.ExpiresAt
	if mfa := session.AuthenticatedAt.Add(staff.MaxAuthenticationAge); mfa.Before(until) {
		until = mfa
	}
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT listing_review.finalize_photo_promotion($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		command.EventID, session.Subject, s.policy, intent.Revision, intent.ExpectedVersion, intent.SHA256, intent.ListingPolicy, string(requirements), a.allowProposed,
		intent.ID, intent.Attempt, receipt.version, receipt.digest[:], receipt.size, until.UTC()).Scan(&raw); err != nil {
		return nil, err
	}
	if !validPhotoApprovalResult(raw, intent.Revision, command.EventID) {
		return nil, errUnavailable
	}
	if err := session.Check(staff.ListingsReview, s.now()); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return raw, nil
}
