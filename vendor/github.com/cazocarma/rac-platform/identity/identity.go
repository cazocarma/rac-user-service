// Package identity shares the identity-verification fact owned by user.
// Consumers learn only whether an account holds an approved verification:
// never provider data, country, fingerprint or why it is not approved. Email
// verification is a different fact and never satisfies this check.
package identity

import (
	"context"
	"errors"
	"time"

	"github.com/cazocarma/rac-platform/standing"
)

var (
	ErrUnavailable = errors.New("identity_unavailable")
	ErrRequired    = errors.New("identity_verification_required")
)

// Purpose names the flow a person is sent to when verification is missing.
type Purpose string

const (
	CompaOnboarding Purpose = "compa_onboarding"
	ClientBooking   Purpose = "client_booking"
)

func (p Purpose) Valid() bool { return p == CompaOnboarding || p == ClientBooking }

// Query is built from the authenticated operation and stored ownership; no
// caller-provided subject reaches it.
type Query struct {
	AccountID string
	Purpose   Purpose
}

func (q Query) Valid() bool { return standing.ValidAccountID(q.AccountID) && q.Purpose.Valid() }

// Observation binds the authority answer to its query and read time.
type Observation struct {
	Query      Query
	Approved   bool
	ObservedAt time.Time
}

type Source interface {
	ReadIdentity(context.Context, Query) (Observation, error)
}

// Check fails closed: a missing, slow, stale or mismatched authority read
// blocks the action as unavailable; only an approved observation passes.
func Check(ctx context.Context, source Source, query Query, maxAge time.Duration) error {
	if ctx == nil || ctx.Err() != nil || source == nil || !query.Valid() || maxAge <= 0 || maxAge > 5*time.Second {
		return ErrUnavailable
	}
	started := time.Now()
	observation, err := source.ReadIdentity(ctx, query)
	finished := time.Now()
	if err != nil || ctx.Err() != nil || observation.Query != query || finished.Sub(started) > maxAge ||
		observation.ObservedAt.Before(finished.Add(-maxAge)) || observation.ObservedAt.After(finished) {
		return ErrUnavailable
	}
	if !observation.Approved {
		return ErrRequired
	}
	return nil
}
