package memory

import (
	"context"
	"sync"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

// memoryLock is a process-local implementation of sessions.Lock. It only
// coordinates goroutines inside one process; it cannot (and is not meant to)
// coordinate replicas. That matches the in-memory store's single-replica
// contract.
type memoryLock struct {
	store *SessionStore
	key   string

	mu      sync.Mutex
	held    bool
	expires time.Time
}

func newMemoryLock(store *SessionStore, key string) *memoryLock {
	return &memoryLock{store: store, key: key}
}

// Obtain takes the lock if it is free or its previous TTL has elapsed.
func (l *memoryLock) Obtain(_ context.Context, expiration time.Duration) error {
	l.store.mu.Lock()
	defer l.store.mu.Unlock()

	now := l.store.nowFunc()
	if l.held && l.expires.After(now) {
		return sessions.ErrLockNotObtained
	}
	l.held = true
	l.expires = now.Add(expiration)
	return nil
}

// Peek reports whether the lock is currently held and unexpired.
func (l *memoryLock) Peek(_ context.Context) (bool, error) {
	l.store.mu.Lock()
	defer l.store.mu.Unlock()
	return l.held && l.expires.After(l.store.nowFunc()), nil
}

// Refresh extends the lock's TTL.
func (l *memoryLock) Refresh(_ context.Context, expiration time.Duration) error {
	l.store.mu.Lock()
	defer l.store.mu.Unlock()
	if !l.held {
		return sessions.ErrNotLocked
	}
	l.expires = l.store.nowFunc().Add(expiration)
	return nil
}

// Release drops the lock.
func (l *memoryLock) Release(_ context.Context) error {
	l.store.mu.Lock()
	defer l.store.mu.Unlock()
	if !l.held {
		return sessions.ErrNotLocked
	}
	l.held = false
	l.expires = time.Time{}
	return nil
}

var _ sessions.Lock = (*memoryLock)(nil)
