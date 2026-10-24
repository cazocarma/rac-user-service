package standing

import (
	"context"
	"errors"
	"time"
)

var ErrUnavailable = errors.New("standing authority unavailable")

// Source must use an authenticated authority, not an unleased local projection.
// Load must bind the returned state to subject. LatestVersion is a monotonic
// high-water mark maintained by the adapter from committed state/events.
type Source interface {
	Load(context.Context, string) (Snapshot, error)
	LatestVersion(context.Context, string) (uint64, error)
}

// AuthorityAuthorizer intentionally performs a fresh authority lookup. A future
// cache may reuse Lease, but must preserve the same expiry and version checks.
type AuthorityAuthorizer struct {
	Source Source
	Now    func() time.Time
}

var _ Authorizer = AuthorityAuthorizer{}

func (a AuthorityAuthorizer) Authorize(ctx context.Context, subject string, capability Capability) (Decision, error) {
	if subject == "" || ctx.Err() != nil {
		return Decision{}, ErrUnavailable
	}
	if protective(capability) {
		return Decision{Allowed: true}, nil
	}
	if !commercial(capability) {
		return Decision{}, nil
	}
	if a.Source == nil || a.Now == nil {
		return Decision{}, ErrUnavailable
	}
	started := a.Now()
	snapshot, err := a.Source.Load(ctx, subject)
	if err != nil {
		return Decision{}, ErrUnavailable
	}
	lease, ok := NewLease(snapshot, started, a.Now())
	if !ok {
		return Decision{}, ErrUnavailable
	}
	version, err := a.Source.LatestVersion(ctx, subject)
	if err != nil || version < snapshot.Version || ctx.Err() != nil {
		return Decision{}, ErrUnavailable
	}
	return lease.Authorize(capability, a.Now(), version), nil
}
