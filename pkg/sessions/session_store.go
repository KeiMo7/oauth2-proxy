package sessions

import (
	"fmt"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/cookie"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/memory"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/persistence"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/redis"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/strict"
)

// NewSessionStore creates a SessionStore from the provided configuration.
//
// When opts.Session.Strict.Enabled is false (the default) the returned store
// behaves exactly as before, with no strict wrapper. When it is true the
// underlying backend is composed with a strict.Store that classifies errors,
// retries timed-out operations, enforces shared revocation and reliable
// logout, and applies the configured unavailable policy.
func NewSessionStore(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessions.SessionStore, error) {
	base, backend, err := newBaseStore(opts, cookieOpts)
	if err != nil {
		return nil, err
	}

	if !opts.Strict.Enabled {
		return base, nil
	}

	// Strict semantics (store-unavailable classification, shared revocation,
	// reliable logout) require server-side session state keyed by a ticket. The
	// cookie backend keeps all state in the client and has no shared store, so
	// wrapping it would both break ticket decoding and provide none of the
	// guarantees. Fail fast with a precise message rather than misbehaving.
	if backend == options.CookieSessionStoreType {
		return nil, fmt.Errorf("session-strict-semantics requires a server-side session backend (redis or memory); the cookie backend has no shared store to classify unavailability or share revocation records")
	}

	opts.Strict.EnsureDefaults(cookieOpts.Expire)
	if err := opts.Strict.Validate(); err != nil {
		return nil, err
	}

	cfg := strict.ConfigFromOptions(opts.Strict, cookieOpts)

	var revocations strict.RevocationStore
	if opts.Strict.RevocationEnabled {
		switch backend {
		case options.RedisSessionStoreType:
			rs, ok := base.(*persistence.Manager).Store.(*redis.SessionStore)
			if !ok {
				return nil, fmt.Errorf("strict revocation requires the redis session backend, got %T", base)
			}
			revocations = strict.NewRedisRevocationStore(rs.Client.UniversalClient())
		case options.MemorySessionStoreType:
			// Process-local revocation: effective within this process only;
			// the memory backend's single-replica contract makes that explicit.
			revocations = strict.NewMemoryRevocationStore()
		}
	}

	return strict.NewStore(base, cookieOpts, cfg, revocations, nil), nil
}

// newBaseStore constructs the backend store without the strict wrapper and
// also returns the backend type, so callers can wire backend-specific strict
// components (e.g. redis revocation records).
func newBaseStore(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessions.SessionStore, string, error) {
	switch opts.Type {
	case options.CookieSessionStoreType:
		store, err := cookie.NewCookieSessionStore(opts, cookieOpts)
		return store, options.CookieSessionStoreType, err
	case options.RedisSessionStoreType:
		store, err := redis.NewRedisSessionStore(opts, cookieOpts)
		return store, options.RedisSessionStoreType, err
	case options.MemorySessionStoreType:
		store, err := memory.NewSessionStore(opts, cookieOpts)
		return store, options.MemorySessionStoreType, err
	default:
		return nil, "", fmt.Errorf("unknown session store type '%s'", opts.Type)
	}
}
