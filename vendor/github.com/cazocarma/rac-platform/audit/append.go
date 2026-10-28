package audit

import (
	"context"
	"errors"
)

// Input contains no asserted actor identity or private content. The persistence
// boundary must derive the actor from its authenticated principal, not this DTO.
type Input struct {
	EventID, Action, ResourceID, Purpose, PolicyVersion, CaseID string
}

func (i Input) Validate() error {
	for _, id := range []string{i.EventID, i.ResourceID, i.PolicyVersion} {
		if !ValidID(id) {
			return errors.New("invalid audit reference")
		}
	}
	if i.CaseID != "" && !ValidID(i.CaseID) {
		return errors.New("invalid audit case reference")
	}
	switch i.Action {
	case "evidence.accessed", "standing.changed", "policy.published", "listing.reviewed", "document.drafted", "document.reviewed", "document.published":
	default:
		return errors.New("unregistered audit action")
	}
	switch i.Purpose {
	case "operational", "case_review", "legal_request", "security":
	default:
		return errors.New("unregistered audit purpose")
	}
	return nil
}

type Appender interface {
	Append(context.Context, Input) (Record, error)
}
