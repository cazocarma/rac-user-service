package documents

import (
	"context"
	"time"

	"github.com/cazocarma/rac-platform/standing"
)

// Query is constructed by the authenticated operation owner, never decoded
// directly from a public request. Role is the target document persona.
type Query struct {
	AccountID  string
	Role       Role
	Capability standing.Capability
	Locale     string
}

// Valid permits only covered commercial queries. Protective operations bypass
// document dependency at Check and never need a document authority request.
func (q Query) Valid() bool {
	return standing.ValidAccountID(q.AccountID) && len(kinds(q.Role)) > 0 &&
		standing.IsCommercial(q.Capability) && (q.Locale == "es" || q.Locale == "en")
}

// Observation binds a consistent authority read to its requested operation.
// Revision is the monotonic registry version, not a client-selected policy.
type Observation struct {
	Query    Query
	Revision uint64
	Snapshot Snapshot
}

// Source must authenticate the authority and read registry, policy and consent
// consistently. Implementations must propagate cancellation and reject partial
// responses. This interface intentionally provides no cache or success lease.
type Source interface {
	ReadDocuments(context.Context, Query) (Observation, error)
}

// Check performs a fresh prerequisite read. Invoke it again immediately before
// a covered effect. It is not an atomic database fence: owners must coordinate
// their final read with the write transaction to eliminate commit races.
// Protective rights do not contact the document authority.
func Check(ctx context.Context, source Source, query Query, maxAge time.Duration) error {
	if standing.IsProtective(query.Capability) {
		return nil
	}
	if ctx == nil || ctx.Err() != nil || source == nil ||
		!query.Valid() ||
		maxAge <= 0 || maxAge > 5*time.Second {
		return ErrUnavailable
	}
	started := time.Now()
	observation, err := source.ReadDocuments(ctx, query)
	finished := time.Now()
	if err != nil || ctx.Err() != nil || observation.Query != query || observation.Revision == 0 ||
		finished.Sub(started) > maxAge || observation.Snapshot.ObservedAt.Before(finished.Add(-maxAge)) ||
		observation.Snapshot.ObservedAt.After(finished) {
		return ErrUnavailable
	}
	return RequireAcceptedDocuments(observation.Snapshot, query.Role, query.Capability)
}
