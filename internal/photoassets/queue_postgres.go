package photoassets

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	staffpg "github.com/cazocarma/rac-platform/staff/postgres"
	"github.com/lib/pq"
)

// PostgresQueue uses a dedicated function-only LOGIN, never rac_user or the
// migration credential. No transaction is exposed to the caller: each command
// commits before CPU/object-store work starts or its acknowledgment is returned.
type PostgresQueue struct{ db *sql.DB }

var queueRolePolicy = staffpg.RolePolicy{Functions: []string{
	"photo.claim_processing(text,text,text)",
	"photo.complete_processing(uuid,uuid,text,text,text,text,bytea,integer,jsonb,text,integer)",
}}

func NewPostgresQueue(ctx context.Context, db *sql.DB) (*PostgresQueue, error) {
	if err := staffpg.CheckRole(ctx, db, queueRolePolicy); err != nil {
		return nil, err
	}
	return &PostgresQueue{db: db}, nil
}

func (q *PostgresQueue) Claim(ctx context.Context, release Release) (*Attempt, error) {
	if !release.valid() {
		return nil, ErrInvalid
	}
	if err := staffpg.CheckRole(ctx, q.db, queueRolePolicy); err != nil {
		return nil, err
	}
	var a Attempt
	var digest []byte
	err := q.db.QueryRowContext(ctx, `SELECT attempt_id,asset_id,object_key,source_sha256,source_size,media_type,width,height,pipeline_version FROM photo.claim_processing($1,$2,$3)`,
		release.Pipeline, release.Commit, release.ImageDigest).Scan(&a.ID, &a.Source.id, &a.Source.key, &digest, &a.Source.size, &a.Source.media, &a.Source.width, &a.Source.height, &a.Source.pipeline)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, queueError(ctx, err)
	}
	if len(digest) != 32 || !attemptPattern.MatchString(a.ID) || a.Source.pipeline != release.Pipeline {
		return nil, ErrIntegrity
	}
	copy(a.Source.digest[:], digest)
	return &a, nil
}

func (q *PostgresQueue) Complete(ctx context.Context, attempt Attempt, release Release, artifact Artifact) error {
	if !release.valid() || !attemptPattern.MatchString(attempt.ID) || strings.Trim(attempt.ID, "0") == "" || attempt.Source.id == "" ||
		artifact.key != attempt.ObjectKey() || artifact.size < 1 || len(artifact.assessment) == 0 {
		return ErrInvalid
	}
	if err := staffpg.CheckRole(ctx, q.db, queueRolePolicy); err != nil {
		return err
	}
	id := attempt.ID[:8] + "-" + attempt.ID[8:12] + "-" + attempt.ID[12:16] + "-" + attempt.ID[16:20] + "-" + attempt.ID[20:]
	var applied bool
	err := q.db.QueryRowContext(ctx, `SELECT photo.complete_processing($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11)`,
		id, attempt.Source.id, release.Pipeline, release.Commit, release.ImageDigest, artifact.key, artifact.digest[:], artifact.size, string(artifact.assessment), artifact.disposition, artifact.risk).Scan(&applied)
	if err != nil {
		return queueError(ctx, err)
	}
	if !applied {
		return ErrClaimLost
	}
	return nil
}

func queueError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var pg *pq.Error
	if errors.As(err, &pg) {
		switch pg.Code {
		case "22000":
			return ErrIntegrity
		case "40001":
			return ErrClaimLost
		}
	}
	return ErrStorage
}

var _ WorkQueue = (*PostgresQueue)(nil)
