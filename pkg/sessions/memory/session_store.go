package memory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/persistence"
)

// entry holds an encrypted session blob and its absolute expiry time.
type entry struct {
	data    []byte
	expires time.Time
}

// SessionStore is an in-process implementation of persistence.Store. It keeps
// encrypted session blobs in a map guarded by a RWMutex and reuses the
// persistence.Manager ticket/encryption machinery, so its on-the-wire cookie
// format is identical to the Redis backend.
//
// Semantics:
//   - data is lost on process restart;
//   - state is NOT shared between replicas — each process has its own map.
//
// It is therefore only suitable for single-replica deployments, local
// development and tests. Multi-replica strict semantics require a shared
// backend (Redis).
type SessionStore struct {
	mu      sync.RWMutex
	data    map[string]entry
	nowFunc func() time.Time
	offset  time.Duration

	// faultToggle, when non-nil, is consulted before every operation; returning
	// an error simulates a store outage (timeout/unavailability) for tests and
	// load tests. Production wiring leaves it nil.
	faultToggle func(op string) error
}

// NewSessionStore initialises an in-memory SessionStore wrapped in a
// persistence.Manager, matching the construction shape of the Redis backend.
// It also returns the raw store so test harnesses can control its clock and
// inject faults.
func NewSessionStore(_ *options.SessionOptions, cookieOpts *options.Cookie) (sessions.SessionStore, error) {
	store := NewRawStore()
	return persistence.NewManager(store, cookieOpts), nil
}

// NewSessionStoreRaw is the test/factory variant returning both the wrapped
// store and the controllable raw backend.
func NewSessionStoreRaw(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessions.SessionStore, *SessionStore, error) {
	store := NewRawStore()
	return persistence.NewManager(store, cookieOpts), store, nil
}

// SetFaultFunc installs a fault injection callback. It is intended for tests
// and the load-test harness; never call it on a production request path.
func (s *SessionStore) SetFaultFunc(f func(op string) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faultToggle = f
}

// Save stores the (already encrypted) session value under key with an absolute
// expiry derived from exp. A failing write never mutates an existing entry.
func (s *SessionStore) Save(_ context.Context, key string, value []byte, exp time.Duration) error {
	if s.faultToggle != nil {
		if err := s.faultToggle("save"); err != nil {
			return err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// Copy the caller's bytes: callers may reuse the buffer after returning.
	cp := make([]byte, len(value))
	copy(cp, value)
	s.data[key] = entry{
		data:    cp,
		expires: s.nowFunc().Add(exp),
	}
	return nil
}

// Load returns the session blob for key, mapping a missing/expired key to
// sessions.ErrSessionNotFound so callers can distinguish "no session" from a
// storage failure. Expired entries are removed lazily.
func (s *SessionStore) Load(_ context.Context, key string) ([]byte, error) {
	if s.faultToggle != nil {
		if err := s.faultToggle("load"); err != nil {
			return nil, err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[key]
	if !ok {
		return nil, fmt.Errorf("%w: key %q", sessions.ErrSessionNotFound, key)
	}
	if !e.expires.IsZero() && s.nowFunc().After(e.expires) {
		delete(s.data, key)
		return nil, fmt.Errorf("%w: key %q expired", sessions.ErrSessionNotFound, key)
	}
	out := make([]byte, len(e.data))
	copy(out, e.data)
	return out, nil
}

// Clear removes a session key. Deleting a missing key is not an error.
func (s *SessionStore) Clear(_ context.Context, key string) error {
	if s.faultToggle != nil {
		if err := s.faultToggle("clear"); err != nil {
			return err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	return nil
}

// Lock returns a process-local no-op-ish lock. In-process sessions cannot need
// a distributed lock; the returned lock coordinates goroutines within this
// process only.
func (s *SessionStore) Lock(key string) sessions.Lock {
	return newMemoryLock(s, key)
}

// VerifyConnection always succeeds for the in-process store.
func (s *SessionStore) VerifyConnection(_ context.Context) error {
	return nil
}

// NewRawStore builds an empty SessionStore without the persistence.Manager
// wrapper. It is used by tests (including the strict-semantics suite) that need
// direct access to the map backend to inject faults or inspect state.
func NewRawStore() *SessionStore {
	s := &SessionStore{
		data: map[string]entry{},
	}
	s.nowFunc = func() time.Time { return time.Now().Add(s.offset) }
	return s
}

// AdvanceClock shifts the store's logical clock forward by d, cumulatively.
// Production stores use time.Now; this is test support for TTL conformance.
func (s *SessionStore) AdvanceClock(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.offset += d
}

// CorruptAll overwrites every stored blob with undecodable bytes. Test
// support for the "corrupt session" handling path.
func (s *SessionStore) CorruptAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.data {
		e.data = []byte("this is not a valid encrypted session blob")
		s.data[k] = e
	}
}

// ExpireAll forces every entry's expiry into the past, simulating natural TTL
// expiry. Test support.
func (s *SessionStore) ExpireAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.data {
		e.expires = s.nowFunc().Add(-time.Second)
		s.data[k] = e
	}
}

// Len returns the number of live entries. Test support.
func (s *SessionStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.data)
}

var _ persistence.Store = (*SessionStore)(nil)
