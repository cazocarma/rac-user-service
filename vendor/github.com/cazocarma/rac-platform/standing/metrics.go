package standing

import (
	"fmt"
	"io"
	"sync"
	"time"
)

var durationBounds = [...]time.Duration{100 * time.Microsecond, 250 * time.Microsecond,
	500 * time.Microsecond, time.Millisecond, 2 * time.Millisecond, 5 * time.Millisecond,
	10 * time.Millisecond, 50 * time.Millisecond, 500 * time.Millisecond, 2 * time.Second}

type durationHistogram struct {
	mu          sync.Mutex
	count       uint64
	nanoseconds uint64
	buckets     [len(durationBounds)]uint64
}

func (h *durationHistogram) observe(duration time.Duration) {
	if duration < 0 {
		duration = 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.nanoseconds += uint64(duration)
	for i, bound := range durationBounds {
		if duration <= bound {
			h.buckets[i]++
		}
	}
	h.count++
}

type cacheMetrics struct {
	acquire [2]durationHistogram
	check   durationHistogram
}

type acquisitionObserver interface{ ObserveAcquire(time.Duration, bool) }
type checkObserver interface{ ObserveCheck(time.Duration) }

// ObserveAcquire includes context/requirements, concurrent cache lookups and
// capability evaluation. A hit means every required subject reused a lease.
func (c *LeaseCache) ObserveAcquire(duration time.Duration, hit bool) {
	if c == nil {
		return
	}
	index := 0
	if hit {
		index = 1
	}
	c.metrics.acquire[index].observe(duration)
}
func (c *LeaseCache) ObserveCheck(duration time.Duration) {
	if c != nil {
		c.metrics.check.observe(duration)
	}
}

func writeHistogram(w io.Writer, name, labels string, histogram *durationHistogram) {
	histogram.mu.Lock()
	buckets, count, sum := histogram.buckets, histogram.count, histogram.nanoseconds
	histogram.mu.Unlock()
	for i, bound := range durationBounds {
		fmt.Fprintf(w, "%s_bucket{%sle=%q} %d\n", name, labels, fmt.Sprint(bound.Seconds()), buckets[i])
	}
	fmt.Fprintf(w, "%s_bucket{%sle=\"+Inf\"} %d\n", name, labels, count)
	if labels != "" {
		labels = "{" + labels[:len(labels)-1] + "}"
	}
	fmt.Fprintf(w, "%s_count%s %d\n%s_sum%s %g\n", name, labels, count, name, labels, float64(sum)/1e9)
}

// Metrics appends fixed-cardinality Prometheus metrics to an internal endpoint.
// It never exports subjects, roles, tokens, decisions or case identifiers.
func Metrics(source Source) func(io.Writer) {
	return func(w io.Writer) {
		cache, ok := source.(*LeaseCache)
		if !ok || cache == nil {
			return
		}
		fmt.Fprintln(w, "# TYPE rac_standing_acquire_duration_seconds histogram")
		writeHistogram(w, "rac_standing_acquire_duration_seconds", "cache=\"miss\",", &cache.metrics.acquire[0])
		writeHistogram(w, "rac_standing_acquire_duration_seconds", "cache=\"hit\",", &cache.metrics.acquire[1])
		fmt.Fprintln(w, "# TYPE rac_standing_commit_check_duration_seconds histogram")
		writeHistogram(w, "rac_standing_commit_check_duration_seconds", "", &cache.metrics.check)
	}
}
