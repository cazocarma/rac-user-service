package identity

import (
	"context"
	"time"

	platformidentity "github.com/cazocarma/rac-platform/identity"
)

// ReadIdentity answers the shared authority: only whether the account holds an
// approved verification. Approval is per person; the purpose is echoed so the
// caller can route the person to the right flow.
func (s *Service) ReadIdentity(ctx context.Context, q platformidentity.Query) (platformidentity.Observation, error) {
	if s == nil || !q.Valid() {
		return platformidentity.Observation{}, platformidentity.ErrUnavailable
	}
	var approved bool
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM identity_verifications v JOIN usuario u ON u.id=v.user_id
 WHERE u.keycloak_id=$1 AND v.status='approved')`, q.AccountID).Scan(&approved); err != nil {
		return platformidentity.Observation{}, platformidentity.ErrUnavailable
	}
	return platformidentity.Observation{Query: q, Approved: approved, ObservedAt: time.Now()}, nil
}

var _ platformidentity.Source = (*Service)(nil)
