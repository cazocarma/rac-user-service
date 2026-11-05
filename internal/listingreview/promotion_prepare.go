package listingreview

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cazocarma/rac-platform/audit"
	"github.com/cazocarma/rac-platform/staff"
)

const promotionPrepareSignature = "listing_review.prepare_photo_promotion(audit.reference,audit.reference,audit.reference,audit.reference,bigint,audit.digest,text,text,audit.reference)"

// Internal preparation port, not a customer or staff HTTP command yet. The
// atomic finalization/promotion coordinator must exist before routing approval.
type promotionPolicy struct {
	Listing, Pipeline, Target, Bucket, Region, LocatorSHA256 string
}
type promotionPreparer struct {
	owner  *Server
	policy promotionPolicy
}
type promotionIntent struct {
	ID                string    `json:"intent_id"`
	Attempt           string    `json:"attempt_id"`
	Reused            *bool     `json:"intent_reused"`
	Event             string    `json:"event_id"`
	Revision          string    `json:"revision_id"`
	Listing           string    `json:"listing_id"`
	ExpectedVersion   string    `json:"expected_version"`
	SHA256            string    `json:"sha256"`
	Actor             string    `json:"human_actor"`
	ReviewPolicy      string    `json:"review_policy"`
	ListingPolicy     string    `json:"listing_policy"`
	Asset             string    `json:"asset_id"`
	ProcessingAttempt string    `json:"processing_attempt_id"`
	Pipeline          string    `json:"pipeline_version"`
	SourceKey         string    `json:"source_key"`
	NormalizedSHA256  string    `json:"normalized_sha256"`
	NormalizedSize    int       `json:"normalized_size"`
	Target            string    `json:"destination_id"`
	Bucket            string    `json:"destination_bucket"`
	Region            string    `json:"destination_region"`
	LocatorSHA256     string    `json:"destination_locator_sha256"`
	DestinationKey    string    `json:"destination_key"`
	ExpiresAt         time.Time `json:"attempt_expires_at"`
}

var promotionBucket = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
var promotionRegion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)

func newPromotionPreparer(ctx context.Context, db *sql.DB, access *staff.Access, reviewPolicy string, policy promotionPolicy) (*promotionPreparer, error) {
	if !reviewVersion.MatchString(policy.Listing) || !reviewVersion.MatchString(policy.Pipeline) || !audit.ValidID(policy.Target) ||
		!promotionBucket.MatchString(policy.Bucket) || !promotionRegion.MatchString(policy.Region) || !reviewDigest.MatchString(policy.LocatorSHA256) {
		return nil, errors.New("invalid photo promotion policy")
	}
	owner, err := newServer(ctx, db, access, reviewPolicy, functionPolicy([]string{readySignature, promotionPrepareSignature}))
	if err != nil {
		return nil, err
	}
	return &promotionPreparer{owner: owner, policy: policy}, nil
}

// The common transaction boundary verifies the function-only LOGIN and fresh
// MFA, commits the durable intent/attempt/audit, and releases every lock before
// returning any storage metadata. No source/destination port is invoked here.
func (p *promotionPreparer) prepare(ctx context.Context, session staff.Session, revision string, version int64, command approvalCommand) (promotionIntent, error) {
	var intent promotionIntent
	if !audit.ValidID(revision) || !audit.ValidID(command.EventID) || !reviewDigest.MatchString(command.SHA256) ||
		version < 0 || version == 9223372036854775807 || command.ExpectedVersion != strconv.FormatInt(version, 10) {
		return intent, errUnavailable
	}
	raw, err := p.owner.transaction(ctx, session, staff.ListingsReview,
		`SELECT listing_review.prepare_photo_promotion($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		command.EventID, session.Subject, p.owner.policy, revision, version, command.SHA256, p.policy.Listing, p.policy.Pipeline, p.policy.Target)
	if err != nil {
		return intent, err
	}
	if json.Unmarshal(raw, &intent) != nil || intent.Reused == nil || !audit.ValidID(intent.ID) || !audit.ValidID(intent.Attempt) ||
		intent.Event != command.EventID || intent.Revision != revision || !audit.ValidID(intent.Listing) ||
		intent.ExpectedVersion != command.ExpectedVersion || intent.SHA256 != command.SHA256 || intent.Actor != session.Subject ||
		intent.ReviewPolicy != p.owner.policy || intent.ListingPolicy != p.policy.Listing || intent.Pipeline != p.policy.Pipeline ||
		!audit.ValidID(intent.Asset) || !audit.ValidID(intent.ProcessingAttempt) ||
		intent.SourceKey != strings.ReplaceAll(intent.ProcessingAttempt, "-", "")+".jpg" ||
		intent.DestinationKey != strings.ReplaceAll(intent.ID, "-", "")+".jpg" || !reviewDigest.MatchString(intent.NormalizedSHA256) ||
		intent.NormalizedSize < 1 || intent.NormalizedSize > 5*1024*1024 || intent.Target != p.policy.Target ||
		intent.Bucket != p.policy.Bucket || intent.Region != p.policy.Region || intent.LocatorSHA256 != p.policy.LocatorSHA256 ||
		!intent.ExpiresAt.After(p.owner.now()) {
		return promotionIntent{}, errUnavailable
	}
	if err := session.Check(staff.ListingsReview, p.owner.now()); err != nil {
		return promotionIntent{}, err
	}
	return intent, nil
}
