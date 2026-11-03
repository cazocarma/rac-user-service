package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/cazocarma/rac-platform/documents"
	platformidentity "github.com/cazocarma/rac-platform/identity"
	"github.com/cazocarma/rac-platform/standing"
	"github.com/cazocarma/rac-user-service/internal/listings"
)

// ListingPrerequisites re-evaluates, at approval time, the owner gates that
// publishing a compa profile requires. Standing, catalog, photo and policy are
// rechecked by the approval function itself under the listing lock.
func (s *Server) ListingPrerequisites() listings.Prerequisites {
	return func(ctx context.Context, tx *sql.Tx, subject string) (listings.Checked, error) {
		checked := listings.Checked{Documents: documentsEnabled(), Identity: identityEnabled()}
		if err := s.lockedDocuments(ctx, tx, subject, documents.Compa, standing.PublishListing); err != nil {
			if errors.Is(err, documents.ErrRequired) || errors.Is(err, errAssessmentRequired) {
				return checked, listings.ErrPrerequisites
			}
			return checked, err
		}
		if checked.Identity {
			query := platformidentity.Query{AccountID: subject, Purpose: platformidentity.CompaOnboarding}
			if err := platformidentity.Check(ctx, s.identityGate, query, time.Second); err != nil {
				if errors.Is(err, platformidentity.ErrRequired) {
					return checked, listings.ErrPrerequisites
				}
				return checked, err
			}
		}
		return checked, nil
	}
}
