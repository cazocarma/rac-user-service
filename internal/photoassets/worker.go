package photoassets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"slices"
	"strings"

	"github.com/cazocarma/rac-user-service/internal/photostore"
)

var ErrClaimLost = errors.New("photo_processing_claim_lost")

// Release binds an attempt to an explicitly selected pipeline and immutable
// build. It is provenance, not an assertion that the build has been reviewed.
type Release struct {
	Pipeline, Commit, ImageDigest string
}

var commitPattern = regexp.MustCompile(`^[a-f0-9]{40}$`)
var imageDigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var attemptPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

func (r Release) valid() bool {
	return versionPattern.MatchString(r.Pipeline) && commitPattern.MatchString(r.Commit) && imageDigestPattern.MatchString(r.ImageDigest)
}

// Attempt.ID is a fresh random 128-bit identifier, never reused across leases.
// A claim must be committed before returning it, including this artifact key.
// Source must belong to a confirmed upload with the selected pipeline.
type Attempt struct {
	ID     string
	Source Source
}

func (a Attempt) ObjectKey() string { return a.ID + ".jpg" }

// WorkQueue is the durable boundary. Claim returns nil when no work is ready.
// Complete MUST atomically check the lease token, database-clock expiry and
// release, then append the result and acknowledge the job in one transaction.
// Lost leases return ErrClaimLost. Exact repeated completion is idempotent;
// different receipts for an already completed attempt must conflict.
// A failed/uncertain operation is left leased for bounded retry/backoff by the
// queue. In particular, a lost completion ACK must not be rewritten as failure.
type WorkQueue interface {
	Claim(context.Context, Release) (*Attempt, error)
	Complete(context.Context, Attempt, Release, Artifact) error
}

// ArtifactStore is PRIVATE staging. Put is create-only; Get must be bounded.
// Deliberately no Delete, public URL or publication operation is exposed here.
type ArtifactStore interface {
	Put(context.Context, string, []byte) error
	Get(context.Context, string) ([]byte, error)
}

// Artifact can only be constructed after the runner verifies the stored bytes.
// The queue persists its digest, size and private assessment, never the image.
type Artifact struct {
	key         string
	size        int
	digest      [32]byte
	assessment  []byte
	disposition string
	risk        int
}

func (a Artifact) ObjectKey() string   { return a.key }
func (a Artifact) Size() int           { return a.size }
func (a Artifact) Digest() [32]byte    { return a.digest }
func (a Artifact) Assessment() []byte  { return slices.Clone(a.assessment) }
func (a Artifact) Disposition() string { return a.disposition }
func (a Artifact) RiskScore() int      { return a.risk }

type Worker struct {
	queue     WorkQueue
	source    Reader
	staging   ArtifactStore
	processor *Processor
	release   Release
}

func NewWorker(queue WorkQueue, source Reader, staging ArtifactStore, processor *Processor, release Release) (*Worker, error) {
	if queue == nil || source == nil || staging == nil || processor == nil || !release.valid() || processor.version != release.Pipeline {
		return nil, ErrInvalid
	}
	return &Worker{queue: queue, source: source, staging: staging, processor: processor, release: release}, nil
}

// RunOnce performs CPU/network work without holding a database transaction.
// true means a claim was obtained, not that the photo was approved or published.
// On failure the attempt's staging object is retained for reconciliation: it
// must never delete an object after an uncertain completion transaction.
func (w *Worker) RunOnce(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	attempt, err := w.queue.Claim(ctx, w.release)
	if err != nil {
		return false, err
	}
	if attempt == nil {
		return false, nil
	}
	if !attemptPattern.MatchString(attempt.ID) || strings.Trim(attempt.ID, "0") == "" || attempt.Source.id == "" || attempt.Source.pipeline != w.release.Pipeline {
		return true, ErrInvalid
	}
	// Copy the claim before handing control to external adapters.
	claim := *attempt
	processed, err := w.processor.Process(ctx, claim.Source, w.source)
	if err != nil {
		return true, err
	}
	if err := ctx.Err(); err != nil {
		return true, err
	}
	err = w.staging.Put(ctx, claim.ObjectKey(), processed.Image())
	if err != nil && !errors.Is(err, photostore.ErrExists) {
		if ctx.Err() != nil {
			return true, ctx.Err()
		}
		return true, ErrStorage
	}
	// Existing does not mean correct: validate every readback, including a
	// successful Put. Never use an ETag as a substitute for actual bytes.
	stored, err := w.staging.Get(ctx, claim.ObjectKey())
	if ctx.Err() != nil {
		return true, ctx.Err()
	}
	if err != nil {
		return true, ErrStorage
	}
	stored = slices.Clone(stored)
	digest := sha256.Sum256(stored)
	if len(stored) != len(processed.image) || digest != processed.digest {
		return true, ErrIntegrity
	}
	artifact := Artifact{key: claim.ObjectKey(), size: len(stored), digest: digest,
		assessment: processed.Assessment(), disposition: processed.disposition, risk: processed.risk}
	if err := ctx.Err(); err != nil {
		return true, err
	}
	return true, w.queue.Complete(ctx, claim, w.release, artifact)
}

// DigestHex is convenient for adapters that persist a textual digest. Keep the
// underlying fixed-size digest so JSON/browser number conversion is irrelevant.
func (a Artifact) DigestHex() string { return hex.EncodeToString(a.digest[:]) }
