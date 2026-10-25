package standing

import (
	"container/list"
	"context"
	"sync"
	"time"
)

// LeasedSource preserves original authority request/receipt times. Caching
// Snapshot in Load would incorrectly mint a new MaxLease on every cache hit.
type LeasedSource interface {
	LoadLease(context.Context, string) (Lease, bool, error)
}

// CapabilityLeasedSource can refresh a denied cached capability immediately,
// so reversing a restriction does not leave a caller stuck on a negative lease.
type CapabilityLeasedSource interface {
	LoadCapabilityLease(context.Context, string, Capability) (Lease, bool, error)
}

type cacheEntry struct {
	subject    string
	lease      Lease
	version    uint64
	generation uint64
	loading    chan struct{}
	lru        *list.Element
}

// LeaseCache accelerates acquisition only. Load and LatestVersion ALWAYS read
// the authority. In particular, Permit.Check never trusts cached freshness.
// Entries, including observed version watermarks, are bounded to 1024 subjects.
type LeaseCache struct {
	source   Source
	now      func() time.Time
	mu       sync.Mutex
	entries  map[string]*cacheEntry
	lru      list.List
	capacity int
	metrics  cacheMetrics
}

func NewLeaseCache(source Source) *LeaseCache {
	return &LeaseCache{source: source, now: time.Now, capacity: 1024, entries: make(map[string]*cacheEntry)}
}

func (c *LeaseCache) entry(subject string) *cacheEntry {
	if entry := c.entries[subject]; entry != nil {
		c.lru.MoveToFront(entry.lru)
		return entry
	}
	if len(c.entries) >= c.capacity {
		old := c.lru.Back()
		delete(c.entries, old.Value.(*cacheEntry).subject)
		c.lru.Remove(old)
	}
	entry := &cacheEntry{subject: subject}
	entry.lru = c.lru.PushFront(entry)
	c.entries[subject] = entry
	return entry
}

func (c *LeaseCache) Load(ctx context.Context, subject string) (Snapshot, error) {
	if c == nil || c.source == nil {
		return Snapshot{}, ErrUnavailable
	}
	return c.source.Load(ctx, subject)
}

func (c *LeaseCache) LatestVersion(ctx context.Context, subject string) (uint64, error) {
	if c == nil || c.source == nil || subject == "" {
		return 0, ErrUnavailable
	}
	version, err := c.source.LatestVersion(ctx, subject)
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.entry(subject)
	if err != nil || ctx.Err() != nil || version == 0 || version < entry.version {
		entry.generation++
		entry.lease = Lease{}
		return 0, ErrUnavailable
	}
	if version > entry.version {
		entry.version = version
		entry.generation++
		if entry.lease.snapshot.Version != version {
			entry.lease = Lease{}
		}
	}
	return version, nil
}

func (c *LeaseCache) LoadLease(ctx context.Context, subject string) (Lease, bool, error) {
	return c.loadLease(ctx, subject, "")
}

func (c *LeaseCache) LoadCapabilityLease(ctx context.Context, subject string, capability Capability) (Lease, bool, error) {
	return c.loadLease(ctx, subject, capability)
}

func (c *LeaseCache) loadLease(ctx context.Context, subject string, capability Capability) (Lease, bool, error) {
	if c == nil || c.source == nil || subject == "" {
		return Lease{}, false, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, MaxLease)
	defer cancel()
	for ctx.Err() == nil {
		c.mu.Lock()
		entry := c.entry(subject)
		now := c.now()
		// Keep at least half the original budget for the business transaction
		// and its fresh final check. Reuse never moves either lease boundary.
		if entry.lease.snapshot.Version > 0 && !now.Before(entry.lease.received) &&
			entry.lease.end.Sub(now) >= MaxLease/2 && entry.lease.snapshot.Version == entry.version &&
			(capability == "" || entry.lease.Authorize(capability, now, entry.version).Allowed) {
			lease := entry.lease
			c.mu.Unlock()
			return lease, true, nil
		}
		if entry.loading != nil {
			ready := entry.loading
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return Lease{}, false, ErrUnavailable
			case <-ready:
				continue
			}
		}
		ready := make(chan struct{})
		entry.loading = ready
		generation := entry.generation
		c.mu.Unlock()
		started := c.now()
		snapshot, err := c.source.Load(ctx, subject)
		lease, valid := NewLease(snapshot, started, c.now())
		c.mu.Lock()
		entry.loading = nil
		close(ready)
		// An evicted or invalidated flight may finish, but cannot repopulate
		// a newer entry or return an authorization which ignored that change.
		if err != nil || !valid || ctx.Err() != nil || c.entries[subject] != entry ||
			entry.generation != generation || snapshot.Version < entry.version {
			c.mu.Unlock()
			return Lease{}, false, ErrUnavailable
		}
		entry.lease, entry.version = lease, snapshot.Version
		c.mu.Unlock()
		return lease, false, nil
	}
	return Lease{}, false, ErrUnavailable
}

func sourceLease(ctx context.Context, source Source, subject string, capability Capability, started time.Time, now func() time.Time) (Lease, bool, error) {
	if cached, ok := source.(CapabilityLeasedSource); ok {
		return cached.LoadCapabilityLease(ctx, subject, capability)
	}
	if cached, ok := source.(LeasedSource); ok {
		return cached.LoadLease(ctx, subject)
	}
	snapshot, err := source.Load(ctx, subject)
	if err != nil {
		return Lease{}, false, ErrUnavailable
	}
	lease, ok := NewLease(snapshot, started, now())
	if !ok {
		return Lease{}, false, ErrUnavailable
	}
	return lease, false, nil
}

var _ Source = (*LeaseCache)(nil)
var _ LeasedSource = (*LeaseCache)(nil)
