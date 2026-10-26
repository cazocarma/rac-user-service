package postgres

import (
	"context"
	"database/sql"
	"time"

	"github.com/cazocarma/rac-platform/documents"
	"github.com/cazocarma/rac-platform/standing"
)

// CheckLocked is for user-owned writes only. It serializes a document check and
// the caller's transaction with registry activation. Keep the transaction open
// through the covered effect and commit; never use a pooled DB autocommit lock.
// The caller still authenticates, checks resource ownership and standing.
func CheckLocked(ctx context.Context, tx *sql.Tx, q documents.Query, maxAge time.Duration) error {
	if standing.IsProtective(q.Capability) {
		return nil
	}
	if ctx == nil || ctx.Err() != nil || tx == nil || !q.Valid() {
		return documents.ErrUnavailable
	}
	var revision uint64
	if err := tx.QueryRowContext(ctx, "SELECT documents.lock_head($1)", q.Locale).Scan(&revision); err != nil || revision == 0 {
		return documents.ErrUnavailable
	}
	return documents.Check(ctx, New(tx), q, maxAge)
}
