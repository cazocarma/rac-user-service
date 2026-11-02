package listings

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"math"
)

var (
	ErrConflict = errors.New("listing_revision_conflict")
	ErrNotFound = errors.New("listing_not_found")
	ErrStorage  = errors.New("listing_storage_unavailable")
)

type Receipt struct {
	ListingID   string
	RevisionID  string
	RevisionNo  int64
	Version     int64
	PayloadHash [32]byte
}

// Submit stores a prepared snapshot in the caller's transaction. Analysis is
// already finished before row locks. The caller must enforce identity, staff
// boundaries and documents, recheck standing just before commit, and roll back
// on ANY error; this helper deliberately never commits a partial business action.
// expectedVersion is mandatory (zero for the first submission).
func Submit(ctx context.Context, tx *sql.Tx, subject, compaProfileID string, expectedVersion int64, submission Submission) (Receipt, error) {
	if tx == nil || subject == "" || compaProfileID == "" || expectedVersion < 0 || expectedVersion == math.MaxInt64 || len(submission.payload) == 0 || submission.policyVersion == "" {
		return Receipt{}, ErrInvalidDraft
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO public.listings(compa_id)
 SELECT cp.id FROM public.compa_perfil cp JOIN public.usuario u ON u.id=cp.usuario_id
 WHERE cp.id=$1 AND u.keycloak_id=$2 ON CONFLICT(compa_id) DO NOTHING`, compaProfileID, subject)
	if err != nil {
		return Receipt{}, ErrStorage
	}
	var id string
	var version, previous int64
	err = tx.QueryRowContext(ctx, `SELECT l.id::text,l.version
 FROM public.listings l JOIN public.compa_perfil cp ON cp.id=l.compa_id JOIN public.usuario u ON u.id=cp.usuario_id
 WHERE cp.id=$1 AND u.keycloak_id=$2 FOR NO KEY UPDATE OF l`, compaProfileID, subject).Scan(&id, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return Receipt{}, ErrNotFound
	}
	if err != nil {
		return Receipt{}, ErrStorage
	}
	if version != expectedVersion {
		return Receipt{}, ErrConflict
	}
	// A separate statement gets a fresh READ COMMITTED snapshot AFTER the lock
	// wait. A scalar subquery in the locking SELECT could retain a stale max.
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(max(revision_no),0) FROM public.listing_revisions WHERE listing_id=$1`, id).Scan(&previous); err != nil || previous == math.MaxInt64 {
		return Receipt{}, ErrStorage
	}
	var revisionID string
	var digest []byte
	err = tx.QueryRowContext(ctx, `INSERT INTO public.listing_revisions
 (listing_id,revision_no,payload_canonical,assessment,risk_score,policy_version)
 VALUES($1,$2,$3,$4::jsonb,$5,$6) RETURNING id::text,payload_hash`, id, previous+1, string(submission.payload), string(submission.assessment), submission.risk, submission.policyVersion).Scan(&revisionID, &digest)
	if err != nil || !bytes.Equal(digest, submission.hash[:]) {
		return Receipt{}, ErrStorage
	}
	result, err := tx.ExecContext(ctx, `UPDATE public.listings SET pending_revision_id=$2,version=version+1 WHERE id=$1 AND version=$3`, id, revisionID, expectedVersion)
	if err != nil {
		return Receipt{}, ErrStorage
	}
	count, err := result.RowsAffected()
	if err != nil {
		return Receipt{}, ErrStorage
	}
	if count != 1 {
		return Receipt{}, ErrConflict
	}
	return Receipt{ListingID: id, RevisionID: revisionID, RevisionNo: previous + 1, Version: version + 1, PayloadHash: submission.hash}, nil
}
