package httpapi

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/cazocarma/rac-user-service/internal/identity"
	"github.com/cazocarma/rac-user-service/internal/platform"
	"github.com/gin-gonic/gin"
)

// SetIdentity configures identity verification before Router is called; nil
// keeps the endpoints unavailable rather than inventing a result.
func (s *Server) SetIdentity(service *identity.Service) { s.identity = service }

func identityContext(c *gin.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(c.Request.Context(), 10*time.Second)
}

func identityFailure(c *gin.Context, err error) {
	switch {
	case errors.Is(err, identity.ErrNoProfile):
		c.JSON(409, gin.H{"error": "profile_required"})
	case errors.Is(err, identity.ErrInvalidResult):
		c.JSON(400, gin.H{"error": "invalid_request"})
	default:
		c.JSON(503, gin.H{"error": "identity_unavailable"})
	}
}

// ownIdentity exposes only the state: no provider data, country or fingerprint.
func (s *Server) ownIdentity(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	if s.identity == nil {
		c.JSON(503, gin.H{"error": "identity_unavailable"})
		return
	}
	ctx, cancel := identityContext(c)
	defer cancel()
	status, err := s.identity.Current(ctx, platform.Principal(c).Subject)
	if err != nil {
		identityFailure(c, err)
		return
	}
	c.JSON(200, gin.H{"status": status})
}

type identitySessionRequest struct {
	Purpose identity.Purpose `json:"purpose"`
}

func (s *Server) startIdentity(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	if s.identity == nil {
		c.JSON(503, gin.H{"error": "identity_unavailable"})
		return
	}
	var in identitySessionRequest
	if decodeUniqueJSON(io.LimitReader(c.Request.Body, 1024), &in) != nil || !in.Purpose.Valid() {
		c.JSON(400, gin.H{"error": "invalid_request"})
		return
	}
	ctx, cancel := identityContext(c)
	defer cancel()
	status, session, err := s.identity.Start(ctx, platform.Principal(c).Subject, in.Purpose)
	if err != nil {
		identityFailure(c, err)
		return
	}
	if status == identity.Approved {
		c.JSON(200, gin.H{"status": status})
		return
	}
	c.JSON(201, gin.H{"status": status, "url": session.URL})
}

// identityWebhook is authenticated by the provider signature, not a bearer
// token. Responses carry no state that could serve as a registration oracle.
func (s *Server) identityWebhook(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	if s.identity == nil {
		c.JSON(503, gin.H{"error": "identity_unavailable"})
		return
	}
	result, err := s.identity.Provider().VerifyWebhook(c.Request)
	if err != nil {
		c.JSON(401, gin.H{"error": "invalid_signature"})
		return
	}
	ctx, cancel := identityContext(c)
	defer cancel()
	switch _, err = s.identity.Apply(ctx, result); {
	case err == nil:
		c.JSON(200, gin.H{"ok": true})
	case errors.Is(err, identity.ErrUnknownSession):
		c.JSON(404, gin.H{"error": "unknown_session"})
	case errors.Is(err, identity.ErrConflict):
		c.JSON(409, gin.H{"error": "already_decided"})
	default:
		identityFailure(c, err)
	}
}
