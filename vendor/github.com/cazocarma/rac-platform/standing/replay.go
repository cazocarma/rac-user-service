package standing

import (
	"context"
	"encoding/json"
	"regexp"
)

// ReplayHead is recovery evidence, not a snapshot or authorization lease.
// Subject is the application's stable account UUID, not an OIDC subject.
// Version 1 has no change event. Later versions require the original event.
type ReplayHead struct {
	Subject string          `json:"subject"`
	Version uint64          `json:"version"`
	Event   json.RawMessage `json:"event"`
}

var accountID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func ValidAccountID(id string) bool {
	return accountID.MatchString(id) && id != "00000000-0000-0000-0000-000000000000"
}

func (h ReplayHead) Valid() bool {
	if !ValidAccountID(h.Subject) || h.Version == 0 {
		return false
	}
	if h.Version == 1 {
		return len(h.Event) == 0 || string(h.Event) == "null"
	}
	return len(h.Event) > 0 && len(h.Event) <= 8192 && string(h.Event) != "null" && json.Valid(h.Event)
}

type ReplaySource interface {
	Head(context.Context, string) (ReplayHead, error)
}

// ReplayPage preserves every intermediate change. A recovery cursor is separate
// from a projection version: receiving version 5 over the broker does not prove
// that versions 2..4 and their irreversible effects were consumed.
type ReplayPage struct {
	Subject     string            `json:"subject"`
	After       uint64            `json:"after"`
	HeadVersion uint64            `json:"head_version"`
	NextVersion uint64            `json:"next_version"`
	Events      []json.RawMessage `json:"events"`
}

func (p ReplayPage) Valid() bool {
	base := p.After
	if base == 0 {
		base = 1
	}
	if !ValidAccountID(p.Subject) || p.HeadVersion < base || len(p.Events) > 50 || p.NextVersion < base || p.NextVersion > p.HeadVersion || p.NextVersion-base != uint64(len(p.Events)) {
		return false
	}
	if p.NextVersion < p.HeadVersion && len(p.Events) != 50 {
		return false
	}
	for i, raw := range p.Events {
		if len(raw) == 0 || len(raw) > 8192 {
			return false
		}
		var identity struct {
			Subject string `json:"subject_id"`
			Version uint64 `json:"standing_version"`
		}
		if json.Unmarshal(raw, &identity) != nil || identity.Subject != p.Subject || identity.Version != base+uint64(i)+1 {
			return false
		}
	}
	return true
}

type ReplayPageSource interface {
	Page(context.Context, string, uint64) (ReplayPage, error)
}
