// Package postgres reads the user-owned standing authority using its scoped DB
// identity. Other services must use authenticated transport, not these tables.
package postgres

import (
	"context"
	"database/sql"

	"github.com/cazocarma/rac-platform/standing"
)

type Queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type Source struct{ db Queryer }

func New(db Queryer) *Source { return &Source{db: db} }

// One statement gives account and restrictions from the same committed snapshot.
// Bind the verified OIDC subject through usuario, never caller-provided user IDs.
const snapshotSQL = `SELECT a.status,a.version,r.capability,r.starts_at,r.ends_at
 FROM standing.account a JOIN public.usuario u ON u.id=a.subject_id
 LEFT JOIN standing.restriction r ON r.subject_id=a.subject_id
 WHERE u.keycloak_id=$1 ORDER BY r.capability,r.starts_at`

func (s *Source) Load(ctx context.Context, subject string) (standing.Snapshot, error) {
	if s.db == nil || subject == "" {
		return standing.Snapshot{}, standing.ErrUnavailable
	}
	rows, err := s.db.QueryContext(ctx, snapshotSQL, subject)
	if err != nil {
		return standing.Snapshot{}, standing.ErrUnavailable
	}
	defer rows.Close()
	var result standing.Snapshot
	found := false
	for rows.Next() {
		var status standing.Status
		var version uint64
		var capability sql.NullString
		var start, end sql.NullTime
		if err := rows.Scan(&status, &version, &capability, &start, &end); err != nil {
			return standing.Snapshot{}, standing.ErrUnavailable
		}
		if found && (result.Status != status || result.Version != version) {
			return standing.Snapshot{}, standing.ErrUnavailable
		}
		result.Status, result.Version, found = status, version, true
		if capability.Valid {
			if !start.Valid {
				return standing.Snapshot{}, standing.ErrUnavailable
			}
			r := standing.Restriction{Capability: standing.Capability(capability.String), StartsAt: start.Time}
			if end.Valid {
				value := end.Time
				r.EndsAt = &value
			}
			result.Restrictions = append(result.Restrictions, r)
		} else if start.Valid || end.Valid {
			return standing.Snapshot{}, standing.ErrUnavailable
		}
	}
	if rows.Err() != nil || !found || result.Version == 0 {
		return standing.Snapshot{}, standing.ErrUnavailable
	}
	return result, nil
}

func (s *Source) LatestVersion(ctx context.Context, subject string) (uint64, error) {
	if s.db == nil || subject == "" {
		return 0, standing.ErrUnavailable
	}
	var version uint64
	err := s.db.QueryRowContext(ctx, `SELECT a.version FROM standing.account a
 JOIN public.usuario u ON u.id=a.subject_id WHERE u.keycloak_id=$1`, subject).Scan(&version)
	if err != nil || version == 0 {
		return 0, standing.ErrUnavailable
	}
	return version, nil
}

var _ standing.Source = (*Source)(nil)
