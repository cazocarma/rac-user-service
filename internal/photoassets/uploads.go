package photoassets

import (
	"context"
	"database/sql"
	"errors"
	"regexp"

	"github.com/cazocarma/rac-user-service/internal/photostore"
)

var ErrQuota = errors.New("photo_upload_quota_exceeded")
var ErrRequestConflict = errors.New("photo_upload_request_conflict")

// Transaction must start READ COMMITTED, authorize the authenticated owner,
// execute work, recheck required authority immediately before committing, and
// roll back on any failure. It must never retain locks across object I/O.
type Transaction func(context.Context, string, func(context.Context, *sql.Tx) error) error
type UploadPolicy struct {
	Pipeline  string
	MaxPerDay int
}
type UploadStore interface {
	Reader
	Put(context.Context, string, []byte) error
}
type Uploads struct {
	db       *sql.DB
	store    UploadStore
	policy   UploadPolicy
	transact Transaction
}
type UploadStatus struct {
	AssetID string `json:"asset_id"`
	State   string `json:"status"`
}

func NewUploads(db *sql.DB, store UploadStore, policy UploadPolicy, transact Transaction) (*Uploads, error) {
	if db == nil || store == nil || transact == nil || !versionPattern.MatchString(policy.Pipeline) || policy.MaxPerDay < 1 || policy.MaxPerDay > 100 {
		return nil, ErrInvalid
	}
	return &Uploads{db: db, store: store, policy: policy, transact: transact}, nil
}

// UUID accepts canonical nonzero v4 IDs, as generated for sources and by clients
// for upload idempotency. It rejects malformed path/query input before SQL casts.
func UUID(id string) bool { return uuidPattern.MatchString(id) }

var uuidPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)

func (s *Uploads) Upload(ctx context.Context, subject, requestID string, raw []byte, media string) (UploadStatus, error) {
	if subject == "" || !UUID(requestID) {
		return UploadStatus{}, ErrInvalid
	}
	upload, err := Prepare(ctx, raw, media, s.policy.Pipeline)
	if err != nil {
		return UploadStatus{}, err
	}
	var source Source
	err = s.transact(ctx, subject, func(ctx context.Context, tx *sql.Tx) error {
		var owner string
		// Serializes distinct requests and duplicate retries across API instances.
		// This lock mode remains compatible with identity FK checks by sanctions.
		err := tx.QueryRowContext(ctx, `SELECT id::text FROM public.usuario WHERE keycloak_id=$1 FOR NO KEY UPDATE`, subject).Scan(&owner)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return ErrStorage
		}
		var prior string
		err = tx.QueryRowContext(ctx, `SELECT asset_id::text FROM photo.upload_requests WHERE owner_user_id=$1 AND request_id=$2`, owner, requestID).Scan(&prior)
		if err == nil {
			source, err = Load(ctx, tx, subject, prior)
			if err != nil {
				return err
			}
			candidate := upload.source
			if source.digest != candidate.digest || source.size != candidate.size || source.media != candidate.media || source.pipeline != candidate.pipeline || source.width != candidate.width || source.height != candidate.height {
				return ErrRequestConflict
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return ErrStorage
		}
		// Separate statement after taking the owner lock: no stale pre-lock CTE
		// snapshot can let two requests both observe a spare quota slot.
		var used int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM photo.sources WHERE owner_user_id=$1 AND created_at>=clock_timestamp()-interval '24 hours'`, owner).Scan(&used); err != nil {
			return ErrStorage
		}
		if used >= s.policy.MaxPerDay {
			return ErrQuota
		}
		source, err = Reserve(ctx, tx, subject, upload)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO photo.upload_requests(owner_user_id,request_id,asset_id) VALUES($1,$2,$3)`, owner, requestID, source.id); err != nil {
			return ErrStorage
		}
		return nil
	})
	if err != nil {
		return UploadStatus{}, err
	}
	receipt := UploadStatus{AssetID: source.id, State: "awaiting_upload"}
	// The reservation is committed before Put. A failed/lost response retains
	// the same key for retry; it never deletes potentially committed objects.
	err = s.store.Put(ctx, source.key, upload.Bytes())
	if err != nil && !errors.Is(err, photostore.ErrExists) {
		return receipt, ErrStorage
	}
	if err := s.confirmSource(ctx, subject, source); err != nil {
		return receipt, err
	}
	status, err := s.Status(ctx, subject, source.id)
	if err != nil {
		return receipt, err
	}
	return status, nil
}

func (s *Uploads) Confirm(ctx context.Context, subject, id string) (UploadStatus, error) {
	if subject == "" || !UUID(id) {
		return UploadStatus{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return UploadStatus{}, ErrStorage
	}
	source, err := Load(ctx, tx, subject, id)
	tx.Rollback()
	if err != nil {
		return UploadStatus{}, err
	}
	if err := s.confirmSource(ctx, subject, source); err != nil {
		return UploadStatus{AssetID: id, State: "awaiting_upload"}, err
	}
	status, err := s.Status(ctx, subject, id)
	if err != nil {
		return UploadStatus{AssetID: id}, err
	}
	return status, nil
}

func (s *Uploads) confirmSource(ctx context.Context, subject string, source Source) error {
	verified, err := Verify(ctx, s.store, source)
	if err != nil {
		return err
	}
	return s.transact(ctx, subject, func(ctx context.Context, tx *sql.Tx) error { return Confirm(ctx, tx, subject, verified) })
}

// Status is available for the owner even when commercial operations are denied.
// It exposes no raw keys, hashes, signals, scores or reviewer identities.
func (s *Uploads) Status(ctx context.Context, subject, id string) (UploadStatus, error) {
	if subject == "" || !UUID(id) {
		return UploadStatus{}, ErrInvalid
	}
	var result UploadStatus
	err := s.db.QueryRowContext(ctx, `SELECT asset_id,state FROM photo.owner_upload_status($1,$2)`, subject, id).Scan(&result.AssetID, &result.State)
	if errors.Is(err, sql.ErrNoRows) {
		return UploadStatus{}, ErrNotFound
	}
	if err != nil {
		return UploadStatus{}, ErrStorage
	}
	switch result.State {
	case "awaiting_upload", "queued", "processing", "processing_unavailable", "correction_required", "awaiting_review":
	default:
		return UploadStatus{}, ErrStorage
	}
	return result, nil
}

// RequestStatus recovers a receipt even if the original HTTP response was lost
// entirely or a later sanction prevents retrying a commercial write.
func (s *Uploads) RequestStatus(ctx context.Context, subject, requestID string) (UploadStatus, error) {
	if subject == "" || !UUID(requestID) {
		return UploadStatus{}, ErrInvalid
	}
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT r.asset_id::text FROM photo.upload_requests r JOIN public.usuario u ON u.id=r.owner_user_id WHERE u.keycloak_id=$1 AND r.request_id=$2`, subject, requestID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return UploadStatus{}, ErrNotFound
	}
	if err != nil {
		return UploadStatus{}, ErrStorage
	}
	return s.Status(ctx, subject, id)
}

// ReadyReference is a boolean owner/pipeline check for listing submission. It
// deliberately reveals no private assessment, storage key or detector details.
// The INSERT trigger independently derives the immutable reference in the same
// transaction that creates the listing revision.
func (s *Uploads) ReadyReference(ctx context.Context, tx *sql.Tx, subject, id string) (bool, error) {
	if tx == nil || subject == "" || !UUID(id) {
		return false, nil
	}
	var ready bool
	if err := tx.QueryRowContext(ctx, `SELECT photo.owner_ready_reference($1,$2,$3)`, subject, id, s.policy.Pipeline).Scan(&ready); err != nil {
		return false, ErrStorage
	}
	return ready, nil
}
