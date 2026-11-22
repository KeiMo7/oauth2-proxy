package strict

import (
	"sync"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

// degradedSnapshot is a last-known-good session kept for the fail-open-stale
// degradation policy. It is only consulted after the backing store has already
// reported ErrStoreUnavailable, never on the normal request path.
type degradedSnapshot struct {
	session  *sessions.SessionState
	captured time.Time
}

// snapshotCache is a process-local, bounded cache of recent good sessions keyed
// by ticket ID. Entries expire independently of the (possibly unreachable)
// backing store so a long outage cannot serve an arbitrarily stale identity.
type snapshotCache struct {
	mu         sync.RWMutex
	entries    map[string]degradedSnapshot
	ttl        time.Duration
	maxEntries int // upper bound on retained sessions to avoid unbounded growth
}

// newSnapshotCache builds a cache with the given staleness TTL. A TTL of zero
// disables caching (Get always misses), which is the fail-closed setting.
func newSnapshotCache(ttl time.Duration) *snapshotCache {
	return &snapshotCache{
		entries:    map[string]degradedSnapshot{},
		ttl:        ttl,
		maxEntries: 4096, // bound the number of retained sessions per process
	}
}

// put stores a copy of session under ticketID. The Lock is dropped: a degraded
// session must not participate in distributed locking or refresh.
func (c *snapshotCache) put(ticketID string, session *sessions.SessionState, now time.Time) {
	if c.ttl <= 0 || ticketID == "" || session == nil {
		return
	}
	snapshot := *session
	snapshot.Lock = nil

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.maxEntries {
		// Evict one arbitrary expired/old entry to keep the cache bounded.
		for k, e := range c.entries {
			if now.Sub(e.captured) > c.ttl {
				delete(c.entries, k)
				break
			}
		}
		// If nothing was evictable, drop the oldest entry.
		if len(c.entries) >= c.maxEntries {
			var oldestKey string
			var oldestAt time.Time
			for k, e := range c.entries {
				if oldestAt.IsZero() || e.captured.Before(oldestAt) {
					oldestKey, oldestAt = k, e.captured
				}
			}
			delete(c.entries, oldestKey)
		}
	}
	c.entries[ticketID] = degradedSnapshot{session: &snapshot, captured: now}
}

// get returns a fresh-enough snapshot for ticketID. Expired entries are
// removed on access.
func (c *snapshotCache) get(ticketID string, now time.Time) (*sessions.SessionState, bool) {
	if c.ttl <= 0 || ticketID == "" {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[ticketID]
	if !ok {
		return nil, false
	}
	if now.Sub(e.captured) > c.ttl {
		delete(c.entries, ticketID)
		return nil, false
	}
	snapshot := *e.session
	return &snapshot, true
}

// delete drops a snapshot, used when a session is revoked or destroyed.
func (c *snapshotCache) delete(ticketID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, ticketID)
}
