package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"github.com/cazocarma/rac-platform/standing"
	standingdb "github.com/cazocarma/rac-platform/standing/postgres"
	"github.com/cazocarma/rac-user-service/internal/platform"
	"github.com/gin-gonic/gin"
	"os"
	"time"
)

func (s *Server) reviewPermit(c *gin.Context) (context.Context, *standing.Permit, context.CancelFunc, bool) {
	ctx := c.Request.Context()
	if !standingEnabled() {
		return ctx, nil, func() {}, true
	}
	var counterpart string
	err := s.db.QueryRowContext(ctx, `SELECT p.keycloak_id FROM sesion b
 JOIN usuario a ON a.id=b.cliente_id JOIN usuario p ON p.id=b.compa_id
 WHERE b.id=$1 AND a.keycloak_id=$2`, c.Param("id"), platform.Principal(c).Subject).Scan(&counterpart)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(404, gin.H{"error": "booking_not_found"})
		} else {
			c.JSON(503, gin.H{"error": "account_authorization_unavailable"})
		}
		return ctx, nil, func() {}, false
	}
	return s.userPermit(c,
		standing.Requirement{Subject: platform.Principal(c).Subject, Capability: standing.WriteReview},
		standing.Requirement{Subject: counterpart, Capability: standing.WriteReview})
}

func (s *Server) userPermit(c *gin.Context, requirements ...standing.Requirement) (context.Context, *standing.Permit, context.CancelFunc, bool) {
	ctx := c.Request.Context()
	if !standingEnabled() {
		return ctx, nil, func() {}, true
	}
	bounded, p, cancel, err := standing.Acquire(ctx, s.standingCache, requirements...)
	if err != nil {
		reviewStandingFailure(c, err)
		return ctx, nil, cancel, false
	}
	return bounded, p, cancel, true
}
func reviewStandingFailure(c *gin.Context, err error) {
	if errors.Is(err, standing.ErrDenied) {
		c.JSON(403, gin.H{"error": "account_operation_restricted"})
	} else {
		c.JSON(503, gin.H{"error": "account_authorization_unavailable"})
	}
}

// ownStanding exposes decisions for the authenticated account only. Private
// case references and restriction details never enter the public response.
// Clients must treat these decisions as hints and still handle write denials.
func (s *Server) ownStanding(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	if !standingEnabled() {
		c.JSON(200, gin.H{"enforcement_enabled": false})
		return
	}
	started := time.Now()
	snapshot, err := standingdb.New(s.db).Load(c.Request.Context(), platform.Principal(c).Subject)
	if err != nil {
		reviewStandingFailure(c, err)
		return
	}
	lease, ok := standing.NewLease(snapshot, started, time.Now())
	if !ok {
		reviewStandingFailure(c, standing.ErrUnavailable)
		return
	}
	capabilities := make(map[standing.Capability]bool)
	now := time.Now()
	for _, capability := range []standing.Capability{
		standing.PublishListing, standing.RequestBooking, standing.AcceptBooking,
		standing.SendMessage, standing.WriteReview, standing.SubmitReport,
		standing.Appeal, standing.AccessSafety, standing.CancelOwnBooking,
		standing.RequestPrivacy, standing.RecoverAccount, standing.AcceptDocuments,
	} {
		capabilities[capability] = lease.Authorize(capability, now, snapshot.Version).Allowed
	}
	c.JSON(200, gin.H{"enforcement_enabled": true, "status": snapshot.Status, "version": snapshot.Version, "capabilities": capabilities})
}

func standingEnabled() bool { return os.Getenv("STANDING_ENFORCEMENT_ENABLED") == "true" }
