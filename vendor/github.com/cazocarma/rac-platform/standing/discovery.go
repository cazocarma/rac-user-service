package standing

import "context"

// Discovery identifies changed accounts for an owner's independent replay.
// Versions are discovery hints, never permission leases. Repeated keyset sweeps
// discover commits inserted before an earlier cursor without a global sequence.
type ChangedAccount struct {
	Subject string `json:"subject"`
	Version uint64 `json:"version"`
}
type DiscoveryPage struct {
	After    string           `json:"after"`
	Next     string           `json:"next"`
	HasMore  bool             `json:"has_more"`
	Accounts []ChangedAccount `json:"accounts"`
}

func (p DiscoveryPage) Valid() bool {
	if (p.After != "" && !ValidAccountID(p.After)) || len(p.Accounts) > 100 || (p.HasMore && len(p.Accounts) != 100) {
		return false
	}
	previous := p.After
	for _, account := range p.Accounts {
		if !ValidAccountID(account.Subject) || account.Subject <= previous || account.Version < 2 {
			return false
		}
		previous = account.Subject
	}
	if len(p.Accounts) == 0 {
		return !p.HasMore && p.Next == ""
	}
	return p.Next == previous
}

type DiscoverySource interface {
	Discover(context.Context, string) (DiscoveryPage, error)
}
