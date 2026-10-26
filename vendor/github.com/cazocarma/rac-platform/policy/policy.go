// Package policy provides the activation gate shared by future policy owners.
package policy

import (
	"errors"
	"time"
)

type Approval string

const (
	DecisionRequired Approval = "decision_required"
	LegalPending     Approval = "legal_pending"
	OpsPending       Approval = "ops_pending"
	Approved         Approval = "approved"
)

type Version struct {
	ID          string
	State       Approval
	ApprovedBy  string
	EffectiveAt time.Time
}

// RequireActive is fail-closed for unknown states, absent approval or future
// versions. It does not let a caller approve policy; that is an owner API duty.
func (v Version) RequireActive(now time.Time) error {
	if v.ID == "" || v.State != Approved || v.ApprovedBy == "" || v.EffectiveAt.IsZero() || v.EffectiveAt.After(now) {
		return errors.New("policy is not active")
	}
	return nil
}
