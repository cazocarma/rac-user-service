package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"time"

	"github.com/cazocarma/rac-platform/documents"
	documentsdb "github.com/cazocarma/rac-platform/documents/postgres"
	documentstransport "github.com/cazocarma/rac-platform/documents/transport"
	"github.com/cazocarma/rac-platform/standing"
	"github.com/cazocarma/rac-user-service/internal/platform"
	"github.com/gin-gonic/gin"
)

var errOwnerPrerequisites = errors.New("owner prerequisites required")

func documentsEnabled() bool { return os.Getenv("DOCUMENTS_ENFORCEMENT_ENABLED") == "true" }
func documentQuery(subject string, role documents.Role, capability standing.Capability) documents.Query {
	// The current product is Spanish. A public request cannot choose a different
	// language/registry to evade its requirements. Locale rollout is explicit.
	return documents.Query{AccountID: subject, Role: role, Capability: capability, Locale: "es"}
}
func writeDocumentFailure(c *gin.Context, err error) {
	if errors.Is(err, errOwnerPrerequisites) {
		c.Header("Cache-Control", "no-store")
		c.JSON(409, gin.H{"error": "owner_prerequisites_required"})
		return
	}

	if errors.Is(err, errAssessmentRequired) || errors.Is(err, errAssessmentUnavailable) {
		c.Header("Cache-Control", "no-store")
		if errors.Is(err, errAssessmentRequired) {
			c.JSON(428, gin.H{"error": "COMPA_ATTESTATION_REQUIRED"})
		} else {
			assessmentFailure(c)
		}
		return
	}

	status, problem := documentstransport.Failure(err)
	c.Header("Cache-Control", "no-store")
	c.JSON(status, problem)
}
func isDocumentFailure(err error) bool {
	return errors.Is(err, errOwnerPrerequisites) || errors.Is(err, documents.ErrRequired) || errors.Is(err, documents.ErrUnavailable) || errors.Is(err, errAssessmentRequired) || errors.Is(err, errAssessmentUnavailable)
}
func (s *Server) requireDocuments(role documents.Role, capability standing.Capability) gin.HandlerFunc {
	return func(c *gin.Context) {
		if documentsEnabled() {
			err := documents.Check(c.Request.Context(), s.documentsSource, documentQuery(platform.Principal(c).Subject, role, capability), time.Second)
			if err != nil {
				writeDocumentFailure(c, err)
				c.Abort()
				return
			}
		}
		c.Next()
	}
}
func (s *Server) lockedDocuments(ctx context.Context, tx *sql.Tx, subject string, role documents.Role, capability standing.Capability) error {
	if !documentsEnabled() {
		return nil
	}
	if err := documentsdb.CheckLocked(ctx, tx, documentQuery(subject, role, capability), time.Second); err != nil {
		return err
	}
	if role == documents.Compa && capability == standing.PublishListing {
		return checkAssessment(ctx, tx, subject)
	}
	return nil
}
func (s *Server) documentCommit(ctx context.Context, c *gin.Context, tx *sql.Tx, role documents.Role, capability standing.Capability) bool {
	if err := s.lockedDocuments(ctx, tx, platform.Principal(c).Subject, role, capability); err != nil {
		writeDocumentFailure(c, err)
		return false
	}
	return true
}
