package postgres

import (
	"context"
	"database/sql"
	"time"

	"github.com/cazocarma/rac-platform/documents"
	"github.com/cazocarma/rac-platform/standing"
)

// CheckLocked coordinates a user-owned write with registry activation. Keep the
// transaction open through the covered effect and commit. It does not replace
// authentication, ownership or standing checks.
func CheckLocked(ctx context.Context, tx *sql.Tx, q documents.Query, maxAge time.Duration) error {
	return CheckRemoteLocked(ctx, tx, New(tx), q, maxAge)
}

type fencedSource struct {
	source   documents.Source
	revision uint64
	policy   string
}

func (s fencedSource) ReadDocuments(ctx context.Context, q documents.Query) (documents.Observation, error) {
	o, err := s.source.ReadDocuments(ctx, q)
	if err != nil || o.Revision != s.revision || o.Snapshot.Policy.ID != s.policy {
		return documents.Observation{}, documents.ErrUnavailable
	}
	return o, nil
}

// CheckRemoteLocked reads private prerequisites through an authenticated source
// while holding only a registry metadata fence in the writer's transaction.
// This requires the current shared-PostgreSQL topology: the writer and authority
// must coordinate on the same registry. It is not a distributed lock across
// separate databases. Missing migrations/privileges or revision disagreement
// fail closed. Services never read another owner's private tables through this.
func CheckRemoteLocked(ctx context.Context, tx *sql.Tx, source documents.Source, q documents.Query, maxAge time.Duration) error {
	if standing.IsProtective(q.Capability) {
		return nil
	}
	if ctx == nil || ctx.Err() != nil || tx == nil || source == nil || !q.Valid() || maxAge <= 0 || maxAge > 5*time.Second {
		return documents.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, maxAge)
	defer cancel()
	var revision uint64
	var policy string
	if err := tx.QueryRowContext(ctx, "SELECT registry_version,policy_version FROM documents.lock_registry($1)", q.Locale).Scan(&revision, &policy); err != nil || revision == 0 || !standing.ValidAccountID(policy) {
		return documents.ErrUnavailable
	}
	return documents.Check(ctx, fencedSource{source, revision, policy}, q, maxAge)
}
