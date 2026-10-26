// Package documents evaluates document prerequisites from an authoritative
// owner snapshot. It is not authentication, ownership, standing authorization,
// transport freshness, or a replacement for the final pre-commit check.
package documents

import (
	"errors"
	"time"

	"github.com/cazocarma/rac-platform/policy"
	"github.com/cazocarma/rac-platform/standing"
)

type Kind string

const (
	TermsClient    Kind = "terms_client"
	TermsCompa     Kind = "terms_compa"
	CommunityRules Kind = "community_rules"
	Privacy        Kind = "privacy"
	SafetyRules    Kind = "safety_rules"
)

// Role is the document persona derived by the owner from the operation/profile,
// not a caller-supplied JWT staff role. Admin privileges never skip this gate.
type Role string

const (
	Client Role = "cliente"
	Compa  Role = "compa"
)

// MaterialVersion is an owner-established immutable acceptance lineage, not
// a client-chosen version. Nonmaterial revisions retain it; material changes
// replace it. The adapter must derive this relationship from reviewed records.
type Document struct {
	ID              string
	Kind            Kind
	MaterialVersion string
	SHA256          [32]byte
	PublishedAt     time.Time
	Approved        bool
}
type Acceptance struct {
	DocumentID      string
	Kind            Kind
	MaterialVersion string
	SHA256          [32]byte
	AcceptedAt      time.Time
}
type Snapshot struct {
	Policy      policy.Version
	ObservedAt  time.Time
	Documents   []Document
	Acceptances []Acceptance
}

var ErrUnavailable = errors.New("document prerequisites unavailable")
var ErrRequired = errors.New("document acceptance required")

type RequiredError struct{ Documents []Document }

func (*RequiredError) Error() string { return ErrRequired.Error() }
func (*RequiredError) Unwrap() error { return ErrRequired }

func kinds(role Role) []Kind {
	switch role {
	case Client:
		return []Kind{TermsClient, CommunityRules, Privacy, SafetyRules}
	case Compa:
		return []Kind{TermsClient, TermsCompa, CommunityRules, Privacy, SafetyRules}
	default:
		return nil
	}
}
func known(kind Kind) bool {
	switch kind {
	case TermsClient, TermsCompa, CommunityRules, Privacy, SafetyRules:
		return true
	}
	return false
}
func identity(id string) bool      { return standing.ValidAccountID(id) }
func hashValid(hash [32]byte) bool { return hash != [32]byte{} }

// RequireAcceptedDocuments evaluates only the document prerequisite. The caller
// supplies an owner-authenticated, bounded-freshness snapshot and must refresh
// it before committing a covered write. This function never grants access on
// its own. Protective actions deliberately do not depend on document state.
func RequireAcceptedDocuments(s Snapshot, role Role, capability standing.Capability) error {
	if standing.IsProtective(capability) {
		return nil
	}
	if !standing.IsCommercial(capability) || len(kinds(role)) == 0 || s.ObservedAt.IsZero() || s.Policy.RequireActive(s.ObservedAt) != nil {
		return ErrUnavailable
	}
	required := kinds(role)
	current := make(map[Kind]Document, len(s.Documents))
	ids := make(map[string]bool, len(s.Documents))
	for _, d := range s.Documents {
		if !known(d.Kind) || !identity(d.ID) || ids[d.ID] || !identity(d.MaterialVersion) || !hashValid(d.SHA256) ||
			!d.Approved || d.PublishedAt.IsZero() || d.PublishedAt.After(s.ObservedAt) {
			return ErrUnavailable
		}
		if _, duplicate := current[d.Kind]; duplicate {
			return ErrUnavailable
		}
		ids[d.ID] = true
		current[d.Kind] = d
	}
	// Missing registry entries are an unavailable policy, not a successful empty
	// gate and not an invitation to accept an empty list in an interstitial.
	for _, kind := range required {
		if _, ok := current[kind]; !ok {
			return ErrUnavailable
		}
	}
	accepted := make(map[Kind]map[string]bool)
	seen := make(map[string]bool, len(s.Acceptances))
	for _, a := range s.Acceptances {
		if !known(a.Kind) || !identity(a.DocumentID) || seen[a.DocumentID] || !identity(a.MaterialVersion) ||
			!hashValid(a.SHA256) || a.AcceptedAt.IsZero() || a.AcceptedAt.After(s.ObservedAt) {
			return ErrUnavailable
		}
		seen[a.DocumentID] = true
		for _, d := range current {
			if d.ID == a.DocumentID && (d.Kind != a.Kind || d.SHA256 != a.SHA256 || d.MaterialVersion != a.MaterialVersion || a.AcceptedAt.Before(d.PublishedAt)) {
				return ErrUnavailable
			}
		}
		if accepted[a.Kind] == nil {
			accepted[a.Kind] = make(map[string]bool)
		}
		accepted[a.Kind][a.MaterialVersion] = true
	}
	missing := []Document{}
	for _, kind := range required {
		d := current[kind]
		if !accepted[kind][d.MaterialVersion] {
			missing = append(missing, d)
		}
	}
	if len(missing) > 0 {
		return &RequiredError{Documents: missing}
	}
	return nil
}
