package standing

import (
	"context"
	"errors"
	"sync"
	"time"
)

var ErrDenied = errors.New("standing capability denied")

type Requirement struct {
	Subject    string
	Capability Capability
}

// Permit binds a bounded business transaction to authority leases. It does not
// provide a distributed lock: revocation concurrent with the final check still
// has the documented MaxLease window and requires event effects/reconciliation.
type Permit struct {
	source       Source
	requirements []Requirement
	leases       []Lease
	versions     []uint64
	deadline     time.Time
}

// Version returns the authority version used by this permit for provenance.
// It is not an authorization check: callers must still Check before Commit.
// When a subject has multiple requirements, retain the oldest observed version.
func (p *Permit) Version(subject string) (uint64, bool) {
	if p == nil {
		return 0, false
	}
	var version uint64
	for i, r := range p.requirements {
		if r.Subject == subject && (version == 0 || p.versions[i] < version) {
			version = p.versions[i]
		}
	}
	return version, version > 0
}

// Acquire loads both parties concurrently. Use the returned context to begin
// the SQL transaction, call Check immediately before Commit, and always cancel.
// Lock waits and remote reads consume the same budget; Check never renews it.
func Acquire(ctx context.Context, source Source, requirements ...Requirement) (context.Context, *Permit, context.CancelFunc, error) {
	started := time.Now()
	ctx, cancel := context.WithDeadline(ctx, started.Add(MaxLease))
	fail := func(err error) (context.Context, *Permit, context.CancelFunc, error) {
		cancel()
		return nil, nil, func() {}, err
	}
	if source == nil || len(requirements) == 0 || len(requirements) > 16 || ctx.Err() != nil {
		return fail(ErrUnavailable)
	}
	for _, r := range requirements {
		if r.Subject == "" || !commercial(r.Capability) {
			return fail(ErrDenied)
		}
	}
	p := &Permit{source: source, requirements: append([]Requirement(nil), requirements...),
		leases: make([]Lease, len(requirements)), versions: make([]uint64, len(requirements)), deadline: started.Add(MaxLease)}
	errors := make([]error, len(requirements))
	var wg sync.WaitGroup
	for i, requirement := range p.requirements {
		wg.Add(1)
		go func(i int, r Requirement) {
			defer wg.Done()
			snapshot, err := source.Load(ctx, r.Subject)
			if err != nil {
				errors[i] = ErrUnavailable
				return
			}
			lease, ok := NewLease(snapshot, started, time.Now())
			if !ok {
				errors[i] = ErrUnavailable
				return
			}
			if !lease.Authorize(r.Capability, time.Now(), snapshot.Version).Allowed {
				errors[i] = ErrDenied
				return
			}
			p.leases[i], p.versions[i] = lease, snapshot.Version
		}(i, requirement)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return fail(ErrUnavailable)
	}
	for _, err := range errors {
		if err != nil {
			return fail(err)
		}
	}
	return ctx, p, cancel, nil
}

// Check fails closed on unavailable/regressed authority or any new version.
// The caller must not perform further work between this check and SQL Commit.
func (p *Permit) Check(ctx context.Context) error {
	if p == nil || ctx.Err() != nil || !time.Now().Before(p.deadline) {
		return ErrUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, p.deadline)
	defer cancel()
	errors := make([]error, len(p.requirements))
	var wg sync.WaitGroup
	for i, r := range p.requirements {
		wg.Add(1)
		go func(i int, r Requirement) {
			defer wg.Done()
			version, err := p.source.LatestVersion(ctx, r.Subject)
			if err != nil || version < p.versions[i] {
				errors[i] = ErrUnavailable
				return
			}
			if !p.leases[i].Authorize(r.Capability, time.Now(), version).Allowed {
				errors[i] = ErrDenied
			}
		}(i, r)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	for _, err := range errors {
		if err != nil {
			return err
		}
	}
	return nil
}
