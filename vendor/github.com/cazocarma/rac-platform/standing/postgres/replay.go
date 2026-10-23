package postgres

import (
	"context"
	"github.com/cazocarma/rac-platform/standing"
)

// Head reads the account and its original current event in one MVCC snapshot.
// The (subject_id,standing_version) unique index bounds the outbox lookup.
// A missing event for a changed account is an integrity failure, never an
// invitation to invent event identity or downgrade the consumer projection.
func (s *Source) Head(ctx context.Context, subject string) (standing.ReplayHead, error) {
	h := standing.ReplayHead{Subject: subject}
	if s.db == nil || !standing.ValidAccountID(subject) {
		return h, standing.ErrUnavailable
	}
	var raw []byte
	err := s.db.QueryRowContext(ctx, `SELECT a.version,o.payload FROM standing.account a
 LEFT JOIN standing.outbox o ON o.subject_id=a.subject_id AND o.standing_version=a.version
 WHERE a.subject_id=$1`, subject).Scan(&h.Version, &raw)
	h.Event = raw
	if err != nil || !h.Valid() {
		return standing.ReplayHead{}, standing.ErrUnavailable
	}
	return h, nil
}

var _ standing.ReplaySource = (*Source)(nil)
