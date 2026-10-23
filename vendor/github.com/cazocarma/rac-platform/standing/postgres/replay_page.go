package postgres

import (
	"context"
	"encoding/json"

	"github.com/cazocarma/rac-platform/standing"
)

func (s *Source) Page(ctx context.Context, subject string, after uint64) (standing.ReplayPage, error) {
	p := standing.ReplayPage{Subject: subject, After: after}
	if s.db == nil || !standing.ValidAccountID(subject) || after > uint64(1<<63-1) {
		return p, standing.ErrUnavailable
	}
	var raw []byte
	err := s.db.QueryRowContext(ctx, `SELECT a.version,COALESCE(jsonb_agg(e.payload ORDER BY e.standing_version)
 FILTER(WHERE e.standing_version IS NOT NULL),'[]'::jsonb)
 FROM standing.account a LEFT JOIN LATERAL (
 SELECT standing_version,payload FROM standing.outbox
 WHERE subject_id=a.subject_id AND standing_version>GREATEST($2::bigint,1)
 ORDER BY standing_version LIMIT 50) e ON true
 WHERE a.subject_id=$1 GROUP BY a.version`, subject, after).Scan(&p.HeadVersion, &raw)
	if err != nil || json.Unmarshal(raw, &p.Events) != nil {
		return standing.ReplayPage{}, standing.ErrUnavailable
	}
	p.NextVersion = after
	if p.NextVersion == 0 {
		p.NextVersion = 1
	}
	p.NextVersion += uint64(len(p.Events))
	if !p.Valid() {
		return standing.ReplayPage{}, standing.ErrUnavailable
	}
	return p, nil
}
