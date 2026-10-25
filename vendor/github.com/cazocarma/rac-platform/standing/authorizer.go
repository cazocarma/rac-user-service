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

// AuthorityAuthorizer may acquire an original bounded lease from LeasedSource,
// but always confirms its version through the authority before deciding.
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
	lease, _, err := sourceLease(ctx, a.Source, subject, capability, started, a.Now)
	if err != nil {
		return Decision{}, ErrUnavailable
	}
	version, err := a.Source.LatestVersion(ctx, subject)
	if err != nil || version < lease.snapshot.Version || ctx.Err() != nil {
		return Decision{}, ErrUnavailable
	}
	return lease.Authorize(capability, a.Now(), version), nil
}
