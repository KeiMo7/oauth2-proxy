package strict

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/redis/go-redis/v9"
)

// revocationKeyPrefix namespaces revocation records so they never collide with
// session ticket keys.
const revocationKeyPrefix = "oauth2-proxy:revocation:"

// RevocationRecord is the audit payload stored when a session is deliberately
// invalidated. Natural expiry writes no record, so revocation and expiry stay
// cleanly separated in the audit trail.
type RevocationRecord struct {
	TicketID string                    `json:"ticket_id"`
	Reason   sessions.RevocationReason `json:"reason"`
	User     string                    `json:"user,omitempty"`
	At       time.Time                 `json:"at"`
}

// RevocationStore is the storage capability required for server-side
// revocation. Both the Redis-backed and the in-process implementations satisfy
// it.
type RevocationStore interface {
	// MarkRevoked writes a revocation record with a TTL. It is idempotent:
	// marking an already-revoked ticket refreshes the TTL and keeps the first
	// stored reason.
	MarkRevoked(ctx context.Context, ticketID string, record RevocationRecord, ttl time.Duration) error
	// IsRevoked returns the stored record and true when a live revocation
	// record exists for ticketID.
	IsRevoked(ctx context.Context, ticketID string) (RevocationRecord, bool, error)
}

// redisRevocationStore shares a redis client with the session backend.
type redisRevocationStore struct {
	client redis.UniversalClient
	now    func() time.Time
}

// NewRedisRevocationStore builds a RevocationStore over an existing redis
// client. The client type is the same umbrella interface implemented by both
// standalone and cluster clients.
func NewRedisRevocationStore(client redis.UniversalClient) RevocationStore {
	return &redisRevocationStore{client: client, now: time.Now}
}

func revocationKey(ticketID string) string {
	return revocationKeyPrefix + ticketID
}

func (r *redisRevocationStore) MarkRevoked(ctx context.Context, ticketID string, record RevocationRecord, ttl time.Duration) error {
	if record.At.IsZero() {
		record.At = r.now().UTC()
	}
	record.TicketID = ticketID
	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode revocation record: %w", err)
	}
	if err := r.client.Set(ctx, revocationKey(ticketID), payload, ttl).Err(); err != nil {
		return fmt.Errorf("%w: write revocation record: %v", sessions.ErrStoreUnavailable, err)
	}
	return nil
}

func (r *redisRevocationStore) IsRevoked(ctx context.Context, ticketID string) (RevocationRecord, bool, error) {
	raw, err := r.client.Get(ctx, revocationKey(ticketID)).Bytes()
	if errors.Is(err, redis.Nil) {
		return RevocationRecord{}, false, nil
	}
	if err != nil {
		return RevocationRecord{}, false, fmt.Errorf("%w: read revocation record: %v", sessions.ErrStoreUnavailable, err)
	}
	var record RevocationRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		// A malformed record must not leave a revoked session usable: treat an
		// unreadable record as a revocation with an unknown reason.
		return RevocationRecord{TicketID: ticketID, Reason: sessions.RevocationReason("unknown"), At: r.now()}, true, nil
	}
	return record, true, nil
}

// memoryRevocationStore is the process-local counterpart, used with the
// in-memory session backend and in tests. It cannot coordinate replicas; that
// limitation is documented on the memory session store itself.
type memoryRevocationStore struct {
	mu      sync.RWMutex
	records map[string]RevocationRecord
	expiry  map[string]time.Time
	now     func() time.Time

	// fault, when non-nil, is consulted before each operation; test support for
	// simulating a backing-store outage shared with the session store.
	fault func(op string) error
}

// NewMemoryRevocationStore builds a process-local RevocationStore.
func NewMemoryRevocationStore() *memoryRevocationStore {
	return &memoryRevocationStore{
		records: map[string]RevocationRecord{},
		expiry:  map[string]time.Time{},
		now:     time.Now,
	}
}

// SetFaultFunc installs a fault injection callback. Test support only.
func (m *memoryRevocationStore) SetFaultFunc(f func(op string) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fault = f
}

func (m *memoryRevocationStore) MarkRevoked(_ context.Context, ticketID string, record RevocationRecord, ttl time.Duration) error {
	if m.fault != nil {
		if err := m.fault("mark-revoked"); err != nil {
			return err
		}
	}
	if record.At.IsZero() {
		record.At = m.now().UTC()
	}
	record.TicketID = ticketID

	m.mu.Lock()
	defer m.mu.Unlock()
	// Idempotent: keep the earliest revocation record, refresh the TTL.
	if existing, ok := m.records[ticketID]; !ok {
		m.records[ticketID] = record
	} else {
		m.records[ticketID] = existing
	}
	m.expiry[ticketID] = m.now().Add(ttl)
	return nil
}

func (m *memoryRevocationStore) IsRevoked(_ context.Context, ticketID string) (RevocationRecord, bool, error) {
	if m.fault != nil {
		if err := m.fault("is-revoked"); err != nil {
			return RevocationRecord{}, false, err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	exp, ok := m.expiry[ticketID]
	if !ok {
		return RevocationRecord{}, false, nil
	}
	if m.now().After(exp) {
		delete(m.records, ticketID)
		delete(m.expiry, ticketID)
		return RevocationRecord{}, false, nil
	}
	record, ok := m.records[ticketID]
	return record, ok, nil
}

// MemoryRevocationStoreControl is a test/load-test-only fault-injection handle
// for a memoryRevocationStore. It deliberately lives as a separate, explicitly
// named control type rather than exporting test hooks on the store itself.
type MemoryRevocationStoreControl struct {
	target *memoryRevocationStore
}

// SetFaultFunc installs a fault callback on the controlled store.
func (c *MemoryRevocationStoreControl) SetFaultFunc(f func(op string) error) {
	c.target.SetFaultFunc(f)
}

// RevocationControl returns a fault-injection handle for a process-local
// revocation store. Intended for tests and the load-test harness only.
func RevocationControl(store RevocationStore) *MemoryRevocationStoreControl {
	mem, ok := store.(*memoryRevocationStore)
	if !ok {
		return nil
	}
	return &MemoryRevocationStoreControl{target: mem}
}

var (
	_ RevocationStore = (*redisRevocationStore)(nil)
	_ RevocationStore = (*memoryRevocationStore)(nil)
)
