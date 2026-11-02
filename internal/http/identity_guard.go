package httpapi

import (
	"os"
	"time"

	platformidentity "github.com/cazocarma/rac-platform/identity"
	identitytransport "github.com/cazocarma/rac-platform/identity/transport"
	"github.com/cazocarma/rac-user-service/internal/platform"
	"github.com/gin-gonic/gin"
)

func identityEnabled() bool { return os.Getenv("IDENTITY_ENFORCEMENT_ENABLED") == "true" }

// requireIdentity gates publication on an approved verification (ADR-005).
// A compa role or a verified email never stands in for it. Approvals are not
// revoked yet, so checking before the write cannot race with a withdrawal.
func (s *Server) requireIdentity(purpose platformidentity.Purpose) gin.HandlerFunc {
	return func(c *gin.Context) {
		if identityEnabled() {
			query := platformidentity.Query{AccountID: platform.Principal(c).Subject, Purpose: purpose}
			if err := platformidentity.Check(c.Request.Context(), s.identityGate, query, time.Second); err != nil {
				status, problem := identitytransport.Failure(err, purpose)
				c.Header("Cache-Control", "no-store")
				c.AbortWithStatusJSON(status, problem)
				return
			}
		}
		c.Next()
	}
}
