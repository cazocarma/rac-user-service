package standing

import "time"

const MaxLease = 2 * time.Second

// Lease is created only from a successful authority request. Start is the local
// time immediately BEFORE that request, so network latency consumes its budget.
// Reading a projection or receiving a broker heartbeat must never renew it.
// Transport adapters must authenticate the authority and validate its response.
type Lease struct {
	snapshot Snapshot
	start    time.Time
	received time.Time
	end      time.Time
}

func NewLease(s Snapshot, requestStarted, received time.Time) (Lease, bool) {
	end := requestStarted.Add(MaxLease)
	if requestStarted.IsZero() || s.ObservedAt.IsZero() || received.Before(requestStarted) || !received.Before(end) ||
		s.Version == 0 || (s.Status != Active && s.Status != Restricted && s.Status != Suspended && s.Status != Banned) {
		return Lease{}, false
	}
	// Do not retain caller-owned mutable slices/pointers in an authorization.
	s.Restrictions = append([]Restriction(nil), s.Restrictions...)
	for i := range s.Restrictions {
		if s.Restrictions[i].EndsAt != nil {
			endCopy := *s.Restrictions[i].EndsAt
			s.Restrictions[i].EndsAt = &endCopy
		}
	}
	return Lease{snapshot: s, start: requestStarted, received: received, end: end}, true
}

// Authorize must be called again at commit. A newer observed version invalidates
// the lease even before expiry; a lower incoming event cannot extend its life.
func (l Lease) Authorize(c Capability, now time.Time, observedVersion uint64) Decision {
	if protective(c) {
		return Evaluate(l.snapshot, c, now)
	}
	if l.snapshot.ObservedAt.IsZero() || now.Before(l.received) || !now.Before(l.end) || observedVersion > l.snapshot.Version {
		return Decision{Version: l.snapshot.Version}
	}
	// The authority sampled its time somewhere between request start and
	// response receipt. Local monotonic elapsed durations bound its current
	// time without trusting the caller's UTC offset. Deny if a restriction
	// overlaps any part of this interval; network time never grants permission.
	return evaluateWindow(l.snapshot, c,
		l.snapshot.ObservedAt.Add(now.Sub(l.received)),
		l.snapshot.ObservedAt.Add(now.Sub(l.start)))
}
