package standing

import "time"

// Restriction applies on [StartsAt, EndsAt). A nil end means no scheduled end.
type Restriction struct {
	Capability Capability `json:"capability"`
	StartsAt   time.Time  `json:"starts_at"`
	EndsAt     *time.Time `json:"ends_at"`
}

type Snapshot struct {
	Version      uint64        `json:"version"`
	Status       Status        `json:"status"`
	Restrictions []Restriction `json:"restrictions"`
	// ObservedAt is sampled by the authority in the same statement as state.
	// A caller's wall clock must not decide a remote restriction's boundaries.
	ObservedAt time.Time `json:"observed_at"`
}

func protective(c Capability) bool {
	switch c {
	case SubmitReport, Appeal, AccessSafety, CancelOwnBooking, RequestPrivacy,
		RecoverAccount, AcceptDocuments:
		return true
	default:
		return false
	}
}

func commercial(c Capability) bool {
	switch c {
	case PublishListing, RequestBooking, AcceptBooking, SendMessage, WriteReview:
		return true
	default:
		return false
	}
}

// Evaluate preserves protective rights under D02, including when state cannot
// be loaded. This does not grant authentication, resource ownership or staff
// privileges. Unknown commercial capabilities and malformed snapshots fail closed.
func Evaluate(s Snapshot, c Capability, now time.Time) Decision {
	return evaluateWindow(s, c, now, now)
}

// evaluateWindow grants a capability only if it is allowed throughout the
// uncertainty interval. Restriction ends are exclusive, starts inclusive.
func evaluateWindow(s Snapshot, c Capability, earliest, latest time.Time) Decision {
	d := Decision{Version: s.Version}
	if protective(c) {
		d.Allowed = true
		return d
	}
	if !commercial(c) || s.Version == 0 || earliest.IsZero() || latest.Before(earliest) {
		return d
	}
	if s.Status != Active && s.Status != Restricted {
		return d
	}
	for _, r := range s.Restrictions {
		// Invalid restriction data must not silently restore privileges.
		if !commercial(r.Capability) || r.StartsAt.IsZero() ||
			(r.EndsAt != nil && !r.EndsAt.After(r.StartsAt)) {
			return d
		}
		if r.Capability == c && !latest.Before(r.StartsAt) &&
			(r.EndsAt == nil || earliest.Before(*r.EndsAt)) {
			return d
		}
	}
	d.Allowed = true
	return d
}
