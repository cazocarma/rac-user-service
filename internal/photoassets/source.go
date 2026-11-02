// Package photoassets tracks private source uploads. A confirmed source means
// verified object bytes and a durable analysis intent, never human approval.
package photoassets

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"regexp"
	"slices"

	"github.com/cazocarma/rac-user-service/internal/photos"
)

var (
	ErrInvalid     = errors.New("invalid_photo_source")
	ErrNotFound    = errors.New("photo_source_not_found")
	ErrStorage     = errors.New("photo_source_storage_unavailable")
	ErrIntegrity   = errors.New("photo_source_integrity_mismatch")
	versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
)

type Source struct {
	id, key, pipeline, media string
	digest                   [32]byte
	size, width, height      int
}

func (s Source) ID() string              { return s.id }
func (s Source) ObjectKey() string       { return s.key }
func (s Source) Digest() [32]byte        { return s.digest }
func (s Source) Size() int               { return s.size }
func (s Source) PipelineVersion() string { return s.pipeline }

type Upload struct {
	source Source
	raw    []byte
}

func (u Upload) Source() Source { return u.source }
func (u Upload) Bytes() []byte  { return slices.Clone(u.raw) }

func Prepare(ctx context.Context, raw []byte, media, pipeline string) (Upload, error) {
	if err := ctx.Err(); err != nil {
		return Upload{}, err
	}
	if !versionPattern.MatchString(pipeline) {
		return Upload{}, ErrInvalid
	}
	metadata, err := photos.Inspect(raw, media)
	if err != nil {
		return Upload{}, ErrInvalid
	}
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		return Upload{}, ErrStorage
	}
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(id[:])
	uuid := encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
	source := Source{id: uuid, key: encoded + ".raw", pipeline: pipeline, media: media, digest: sha256.Sum256(raw), size: len(raw), width: metadata.Width, height: metadata.Height}
	if err := ctx.Err(); err != nil {
		return Upload{}, err
	}
	return Upload{source: source, raw: slices.Clone(raw)}, nil
}

// Reserve must commit BEFORE the caller writes the private object, so an
// uncertain remote write has a durable reference for owner-scoped recovery.
// This helper owns no commit and never changes the personal/public photo key.
func Reserve(ctx context.Context, tx *sql.Tx, subject string, upload Upload) (Source, error) {
	s := upload.source
	if tx == nil || subject == "" || s.id == "" || len(upload.raw) != s.size || sha256.Sum256(upload.raw) != s.digest {
		return Source{}, ErrInvalid
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO photo.sources
 (id,owner_user_id,object_key,source_sha256,source_size,declared_media_type,source_width,source_height,pipeline_version)
 SELECT $1,u.id,$2,$3,$4,$5,$6,$7,$8 FROM public.usuario u WHERE u.keycloak_id=$9
 ON CONFLICT(id) DO NOTHING`, s.id, s.key, s.digest[:], s.size, s.media, s.width, s.height, s.pipeline, subject)
	if err != nil {
		return Source{}, ErrStorage
	}
	stored, err := Load(ctx, tx, subject, s.id)
	if err != nil {
		return Source{}, err
	}
	if stored != s {
		return Source{}, ErrIntegrity
	}
	return stored, nil
}

// Load deliberately returns metadata only, after deriving ownership from the
// authenticated subject. Recovery cannot select a different user's source.
func Load(ctx context.Context, tx *sql.Tx, subject, id string) (Source, error) {
	if tx == nil || subject == "" || id == "" {
		return Source{}, ErrInvalid
	}
	var s Source
	var digest []byte
	err := tx.QueryRowContext(ctx, `SELECT s.id::text,s.object_key,s.source_sha256,s.source_size,
 s.declared_media_type,s.source_width,s.source_height,s.pipeline_version
 FROM photo.sources s JOIN public.usuario u ON u.id=s.owner_user_id
 WHERE s.id=$1 AND u.keycloak_id=$2`, id, subject).Scan(&s.id, &s.key, &digest, &s.size, &s.media, &s.width, &s.height, &s.pipeline)
	if errors.Is(err, sql.ErrNoRows) {
		return Source{}, ErrNotFound
	}
	if err != nil || len(digest) != 32 {
		return Source{}, ErrStorage
	}
	copy(s.digest[:], digest)
	return s, nil
}

// Reader is a PRIVATE quarantine object store. No URL or personal-photo store
// is accepted from a public request; the server configures the scoped adapter.
type Reader interface {
	Get(context.Context, string) ([]byte, error)
}
type Verified struct{ source Source }

// Verify reads the actual stored bytes outside database locks. Knowing a hash
// or an S3 ETag is not sufficient to confirm an upload. Source metadata and
// object keys are immutable; Confirm rechecks ownership inside its transaction.
func Verify(ctx context.Context, reader Reader, source Source) (Verified, error) {
	if err := ctx.Err(); err != nil {
		return Verified{}, err
	}
	if reader == nil || source.id == "" || source.key == "" || source.size < 1 {
		return Verified{}, ErrInvalid
	}
	raw, err := reader.Get(ctx, source.key)
	if err := ctx.Err(); err != nil {
		return Verified{}, err
	}
	if err != nil {
		return Verified{}, ErrStorage
	}
	actual := sha256.Sum256(raw)
	if len(raw) != source.size || !bytes.Equal(actual[:], source.digest[:]) {
		return Verified{}, ErrIntegrity
	}
	return Verified{source: source}, nil
}

// Confirm atomically stores verification and one analysis intent. It may be
// retried after a lost ACK; it does not make the raw object public or approved.
func Confirm(ctx context.Context, tx *sql.Tx, subject string, verified Verified) error {
	s, err := Load(ctx, tx, subject, verified.source.id)
	if err != nil {
		return err
	}
	if s != verified.source {
		return ErrIntegrity
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO photo.upload_confirmations(asset_id,verified_sha256,verified_size)
 VALUES($1,$2,$3) ON CONFLICT(asset_id) DO NOTHING`, s.id, s.digest[:], s.size); err != nil {
		return ErrStorage
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO photo.analysis_outbox(asset_id) VALUES($1) ON CONFLICT(asset_id) DO NOTHING`, s.id); err != nil {
		return ErrStorage
	}
	return nil
}
