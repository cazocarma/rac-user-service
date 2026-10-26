package sessioncontrol

import "context"

type Work struct {
	Event, Subject, KeycloakSubject, Claim string
	Version                                int64
	Sessions                               []Ref // nil is pending capture; [] is a captured empty list.
	Next                                   int
}

type Stats struct {
	Pending       int64
	OldestSeconds float64
}

type Store interface {
	Claim(context.Context) (*Work, error)
	Capture(context.Context, *Work, []Ref) error
	Advance(context.Context, *Work, int) error
	Retry(context.Context, *Work) error
	Stats(context.Context) (Stats, error)
}

type Worker struct {
	Store   Store
	Gateway Gateway
}

// Step performs at most one capture and one bounded revocation batch. HTTP is
// never inside a DB transaction. Captures are saved under the authority lock
// before the first external mutation. Retries never enumerate a saved capture.
func (w *Worker) Step(ctx context.Context) (worked bool, err error) {
	work, err := w.Store.Claim(ctx)
	if err != nil || work == nil {
		return false, err
	}
	defer func() {
		if err != nil && err != ErrClaimLost {
			_ = w.Store.Retry(ctx, work)
		}
		// Claim loss is ordinary fencing, not an instruction to retry as a new
		// owner. A reversal may have superseded this operation.
		if err == ErrClaimLost {
			err = nil
		}
	}()
	if work.Sessions == nil {
		refs, loadErr := w.Gateway.Snapshot(ctx, work.KeycloakSubject)
		if loadErr != nil || refs == nil || !validRefs(refs) {
			return true, ErrUnavailable
		}
		refs = append([]Ref{}, refs...)
		if err = w.Store.Capture(ctx, work, refs); err != nil {
			return true, err
		}
		if len(refs) == 0 {
			return true, nil
		}
		work.Sessions = refs
	}
	if !validRefs(work.Sessions) || work.Next < 0 || work.Next >= len(work.Sessions) {
		return true, ErrUnavailable
	}
	next := min(work.Next+BatchSize, len(work.Sessions))
	if err = w.Gateway.Revoke(ctx, work.KeycloakSubject, work.Sessions[work.Next:next]); err != nil {
		return true, ErrUnavailable
	}
	if err = w.Store.Advance(ctx, work, next); err != nil {
		return true, err
	}
	return true, nil
}
