package listingreview

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/cazocarma/rac-platform/audit"
	"github.com/cazocarma/rac-platform/staff"
	"github.com/cazocarma/rac-user-service/internal/photostore"
)

type promotionDestination interface {
	Create(context.Context, string, []byte) (string, error)
	CurrentVersion(context.Context, string) (string, error)
	Version(context.Context, string, string) ([]byte, error)
}

// Private process receipt, not a client assertion or publication decision.
// It can be produced only after explicit-version byte verification. The durable
// finalization command still has to revalidate all business/session conditions.
type promotionCopyReceipt struct {
	intent, attempt, key, version string
	digest                        [32]byte
	size                          int
}

// No transaction/SQL handle is accepted by the copy stage. The marker is set
// by prepare only after its intent/access audit committed; JSON cannot set it.
// Every error retains the private object for retry/reconciliation. Neither
// storage port has Delete, so a lost ACK can never trigger destructive cleanup.
func copyPreparedPhoto(parent context.Context, session staff.Session, intent promotionIntent, source PreviewStore, destination promotionDestination, now func() time.Time) (promotionCopyReceipt, error) {
	var empty promotionCopyReceipt
	if !intent.committed || source == nil || destination == nil || now == nil ||
		!audit.ValidID(intent.ID) || !audit.ValidID(intent.Attempt) || intent.Actor != session.Subject ||
		!previewKey.MatchString(intent.SourceKey) || intent.DestinationKey != strings.ReplaceAll(intent.ID, "-", "")+".jpg" ||
		intent.NormalizedSize < 1 || intent.NormalizedSize > photostore.MaxStoredBytes || !reviewDigest.MatchString(intent.NormalizedSHA256) {
		return empty, errUnavailable
	}
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := session.Check(staff.ListingsReview, now()); err != nil {
			return err
		}
		if !intent.ExpiresAt.After(now()) {
			return errUnavailable
		}
		return nil
	}
	if err := check(); err != nil {
		return empty, err
	}
	expected, _ := hex.DecodeString(intent.NormalizedSHA256)
	var digest [32]byte
	copy(digest[:], expected)
	raw, err := source.Get(ctx, intent.SourceKey)
	if err != nil {
		return empty, errUnavailable
	}
	body := slices.Clone(raw)
	if len(body) != intent.NormalizedSize || len(body) < 3 || !bytes.Equal(body[:3], []byte{0xff, 0xd8, 0xff}) || sha256.Sum256(body) != digest {
		return empty, errUnavailable
	}
	if err := check(); err != nil {
		return empty, err
	}
	version, err := destination.Create(ctx, intent.DestinationKey, body)
	if errors.Is(err, photostore.ErrExists) {
		version, err = destination.CurrentVersion(ctx, intent.DestinationKey)
	}
	if err != nil || !photostore.ValidVersionID(version) {
		return empty, errUnavailable
	}
	if err := check(); err != nil {
		return empty, err
	}
	// Always read the captured version, even after a successful conditional PUT.
	// Neither an ETag nor an unpinned latest GET proves the intended version.
	stored, err := destination.Version(ctx, intent.DestinationKey, version)
	if err != nil {
		return empty, errUnavailable
	}
	stored = slices.Clone(stored)
	if len(stored) != intent.NormalizedSize || sha256.Sum256(stored) != digest {
		return empty, errUnavailable
	}
	if err := check(); err != nil {
		return empty, err
	}
	return promotionCopyReceipt{intent: intent.ID, attempt: intent.Attempt, key: intent.DestinationKey, version: version, digest: digest, size: len(stored)}, nil
}
