package httpapi

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cazocarma/rac-platform/contentsignals"
	"github.com/cazocarma/rac-platform/documents"
	"github.com/cazocarma/rac-platform/standing"
	"github.com/cazocarma/rac-user-service/internal/listings"
	"github.com/cazocarma/rac-user-service/internal/platform"
	"github.com/gin-gonic/gin"
)

var errListingUnavailable = errors.New("listing_submission_unavailable")
var listingVersion = regexp.MustCompile(`^(0|[1-9][0-9]{0,18})$`)

// The proposed lexicon is usable for DEV and corpus runs only (D13). Outside
// dev/test no approved lexicon exists yet, so owner submissions stay closed.
var proposedAnalyzer = sync.OnceValues(func() (*contentsignals.Engine, error) {
	return contentsignals.New(contentsignals.ProposedLexicon())
})

// listingPolicyFromEnvironment has no defaults: D04 prices and areas are not
// decided, so an unset policy keeps submissions unavailable instead of
// inventing limits. The approval ingress must be configured with the same version.
func listingPolicyFromEnvironment() (listings.Policy, bool) {
	minimum, errMin := strconv.ParseInt(os.Getenv("LISTING_MIN_PRICE_CLP"), 10, 64)
	maximum, errMax := strconv.ParseInt(os.Getenv("LISTING_MAX_PRICE_CLP"), 10, 64)
	policy := listings.Policy{Version: os.Getenv("LISTING_POLICY_VERSION"), MinPriceCLP: minimum, MaxPriceCLP: maximum, RequireArea: os.Getenv("LISTING_REQUIRE_AREA") == "true"}
	if areas := os.Getenv("LISTING_AREAS"); areas != "" {
		policy.AllowedAreas = strings.Split(areas, ",")
	}
	return policy, policy.Version != "" && errMin == nil && errMax == nil
}

func (s *Server) listingPreparer(ctx context.Context) (*listings.Preparer, error) {
	policy, ok := listingPolicyFromEnvironment()
	if !ok || !s.catalog.AllowProposed {
		return nil, errListingUnavailable
	}
	categories, err := s.repo.ListCategories(ctx, s.catalog)
	if err != nil {
		return nil, errListingUnavailable
	}
	for _, category := range categories {
		policy.AllowedActivities = append(policy.AllowedActivities, category.Slug)
	}
	policy.MaxActivities = s.catalog.MaxPerCompa
	analyzer, err := proposedAnalyzer()
	if err != nil {
		return nil, errListingUnavailable
	}
	return listings.NewPreparer(policy, analyzer)
}

type listingSubmission struct {
	ExpectedVersion string         `json:"expected_version"`
	Listing         listings.Draft `json:"listing"`
}

// submitListing sends an immutable snapshot to review. It never publishes:
// the current public revision (if any) stays until a human approves this one.
func (s *Server) submitListing(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	principal := platform.Principal(c)
	var body listingSubmission
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 32768)
	if decodeUniqueJSON(c.Request.Body, &body) != nil || !listingVersion.MatchString(body.ExpectedVersion) {
		c.JSON(400, gin.H{"error": "invalid_listing"})
		return
	}
	expected, err := strconv.ParseInt(body.ExpectedVersion, 10, 64)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_listing"})
		return
	}
	// No reviewed photo can be referenced until P09 promotes approved media.
	if body.Listing.PhotoVersion != "" {
		c.JSON(409, gin.H{"error": "listing_photo_unavailable"})
		return
	}
	preparer, err := s.listingPreparer(c.Request.Context())
	if err != nil {
		c.JSON(503, gin.H{"error": errListingUnavailable.Error()})
		return
	}
	// Analysis runs before any row lock.
	submission, err := preparer.Prepare(c.Request.Context(), body.Listing)
	var contact listings.ContactError
	switch {
	case errors.As(err, &contact):
		c.JSON(400, gin.H{"error": "public_contact_not_allowed", "field": contact.Field})
		return
	case errors.Is(err, listings.ErrInvalidDraft):
		c.JSON(400, gin.H{"error": "invalid_listing"})
		return
	case err != nil:
		c.JSON(503, gin.H{"error": "content_check_unavailable"})
		return
	}
	ctx, permit, cancel, ok := s.userPermit(c, standing.Requirement{Subject: principal.Subject, Capability: standing.PublishListing})
	defer cancel()
	if !ok {
		return
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		c.JSON(503, gin.H{"error": errListingUnavailable.Error()})
		return
	}
	defer tx.Rollback()
	var profileID string
	err = tx.QueryRowContext(ctx, `SELECT cp.id::text FROM compa_perfil cp JOIN usuario u ON u.id=cp.usuario_id
 WHERE u.keycloak_id=$1 FOR KEY SHARE OF cp,u`, principal.Subject).Scan(&profileID)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(404, gin.H{"error": "compa_profile_required"})
		return
	}
	if err != nil {
		c.JSON(503, gin.H{"error": errListingUnavailable.Error()})
		return
	}
	receipt, err := listings.Submit(ctx, tx, principal.Subject, profileID, expected, submission)
	switch {
	case errors.Is(err, listings.ErrConflict):
		c.JSON(409, gin.H{"error": "listing_version_conflict"})
		return
	case errors.Is(err, listings.ErrNotFound):
		c.JSON(404, gin.H{"error": "compa_profile_required"})
		return
	case err != nil:
		c.JSON(503, gin.H{"error": errListingUnavailable.Error()})
		return
	}
	if !s.documentCommit(ctx, c, tx, documents.Compa, standing.PublishListing) {
		return
	}
	if permit != nil {
		if err = permit.Check(ctx); err != nil {
			reviewStandingFailure(c, err)
			return
		}
	}
	if tx.Commit() != nil {
		c.JSON(503, gin.H{"error": errListingUnavailable.Error()})
		return
	}
	c.JSON(202, gin.H{"listing_id": receipt.ListingID, "revision_id": receipt.RevisionID,
		"revision_no": strconv.FormatInt(receipt.RevisionNo, 10), "listing_version": strconv.FormatInt(receipt.Version, 10),
		"sha256": hex.EncodeToString(receipt.PayloadHash[:]), "status": "submitted"})
}

type ownRevision struct {
	ID          string          `json:"revision_id"`
	Number      string          `json:"revision_no"`
	SubmittedAt time.Time       `json:"submitted_at"`
	Listing     json.RawMessage `json:"listing"`
}

type ownDecision struct {
	Number     string    `json:"revision_no"`
	Decision   string    `json:"decision"`
	ReasonCode string    `json:"reason_code"`
	NoteKey    string    `json:"note_to_user_key"`
	DecidedAt  time.Time `json:"decided_at"`
}

// ownListing shows the owner their own snapshots and the latest decision.
// Review signals, risk and reviewer identity are never returned.
func (s *Server) ownListing(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	var id, state, version string
	var pendingID, pendingNo, pendingPayload, publishedID, publishedNo, publishedPayload sql.NullString
	var decisionNo, decision, reason, note sql.NullString
	var pendingAt, publishedAt, decidedAt sql.NullTime
	err := s.db.QueryRowContext(c.Request.Context(), `SELECT l.id::text,l.state,l.version::text,
 p.id::text,p.revision_no::text,p.submitted_at,p.payload_canonical,
 a.id::text,a.revision_no::text,a.submitted_at,a.payload_canonical,
 d.revision_no::text,d.action,d.reason_code,d.note_to_user_key,d.reviewed_at
 FROM listings l JOIN compa_perfil cp ON cp.id=l.compa_id JOIN usuario u ON u.id=cp.usuario_id
 LEFT JOIN listing_revisions p ON p.id=l.pending_revision_id
 LEFT JOIN listing_revisions a ON a.id=l.published_revision_id
 LEFT JOIN LATERAL (SELECT r.revision_no,x.action,x.reason_code,x.note_to_user_key,x.reviewed_at
  FROM listing_revision_decisions x JOIN listing_revisions r ON r.id=x.revision_id
  WHERE r.listing_id=l.id ORDER BY x.reviewed_at DESC,r.revision_no DESC LIMIT 1) d ON true
 WHERE u.keycloak_id=$1`, platform.Principal(c).Subject).Scan(&id, &state, &version,
		&pendingID, &pendingNo, &pendingAt, &pendingPayload, &publishedID, &publishedNo, &publishedAt, &publishedPayload,
		&decisionNo, &decision, &reason, &note, &decidedAt)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(200, gin.H{"listing": nil})
		return
	}
	if err != nil {
		c.JSON(503, gin.H{"error": "listing_unavailable"})
		return
	}
	revision := func(id, number sql.NullString, at sql.NullTime, payload sql.NullString) *ownRevision {
		if !id.Valid {
			return nil
		}
		return &ownRevision{ID: id.String, Number: number.String, SubmittedAt: at.Time.UTC(), Listing: json.RawMessage(payload.String)}
	}
	var last *ownDecision
	if decision.Valid {
		last = &ownDecision{Number: decisionNo.String, Decision: decision.String, ReasonCode: reason.String, NoteKey: note.String, DecidedAt: decidedAt.Time.UTC()}
	}
	c.JSON(200, gin.H{"listing": gin.H{"id": id, "state": state, "version": version,
		"pending":       revision(pendingID, pendingNo, pendingAt, pendingPayload),
		"published":     revision(publishedID, publishedNo, publishedAt, publishedPayload),
		"last_decision": last}})
}
