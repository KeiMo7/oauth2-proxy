package options

import (
	"fmt"
	"time"
)

// SessionOptions contains configuration options for the SessionStore providers.
type SessionOptions struct {
	Type   string               `flag:"session-store-type" cfg:"session_store_type"`
	Cookie CookieStoreOptions   `cfg:",squash"`
	Redis  RedisStoreOptions    `cfg:",squash"`
	Memory MemoryStoreOptions   `cfg:",squash"`
	Strict StrictSessionOptions `cfg:",squash"`
}

// CookieSessionStoreType is used to indicate the CookieSessionStore should be
// used for storing sessions.
var CookieSessionStoreType = "cookie"

// RedisSessionStoreType is used to indicate the RedisSessionStore should be
// used for storing sessions.
var RedisSessionStoreType = "redis"

// MemorySessionStoreType is used to indicate the in-process MemorySessionStore
// should be used for storing sessions. It shares the persistence.Manager
// ticket/encryption path with Redis but keeps data in a per-process map, so it
// is only suitable for single-replica deployments.
var MemorySessionStoreType = "memory"

// CookieStoreOptions contains configuration options for the CookieSessionStore.
type CookieStoreOptions struct {
	Minimal bool `flag:"session-cookie-minimal" cfg:"session_cookie_minimal"`
}

// MemoryStoreOptions contains configuration options for the in-memory
// SessionStore. There is nothing to configure today beyond the store type;
// the struct exists so flags and config stay symmetrical with the other
// backends.
type MemoryStoreOptions struct{}

// Unavailable policy names. The two degradation behaviours deliberately have
// explicit, non-ambiguous names:
//   - UnavailablePolicyFailClosed: every request needing the store while it is
//     unavailable is rejected (503).
//   - UnavailablePolicyFailOpenStale: requests proceed using the last known
//     good session snapshot, but the session is neither refreshed nor written
//     back for the duration of the outage.
const (
	UnavailablePolicyFailClosed    = "fail-closed"
	UnavailablePolicyFailOpenStale = "fail-open-stale"
)

// StrictSessionOptions controls the strict session semantics. Every field
// defaults to a value that preserves the historical behaviour; strict
// semantics are only active when Enabled is true.
type StrictSessionOptions struct {
	// Enabled turns on the strict wrapper: error classification (unavailable
	// vs. not-found vs. revoked vs. corrupt), degradation policy, revocation
	// records and reliable logout. Default false keeps the legacy behaviour.
	Enabled bool `flag:"session-strict-semantics" cfg:"session_strict_semantics"`

	// UnavailablePolicy selects what happens when the backing store cannot be
	// reached during a session read. One of:
	//   fail-closed (default)      -> 503 + Retry-After
	//   fail-open-stale            -> serve last known snapshot, skip writes
	UnavailablePolicy string `flag:"session-unavailable-policy" cfg:"session_unavailable_policy"`

	// OperationTimeout is the per-attempt timeout for a single store operation
	// (Load/Save/Clear) in strict mode.
	OperationTimeout time.Duration `flag:"session-operation-timeout" cfg:"session_operation_timeout"`

	// MaxRetries is the number of retries (with exponential backoff) for
	// ordinary Load/Save operations that fail with ErrStoreUnavailable.
	MaxRetries int `flag:"session-operation-max-retries" cfg:"session_operation_max_retries"`

	// LogoutMaxRetries is the retry budget for logout (Clear) operations.
	// Logout must never silently succeed, so it has a separate, larger budget.
	LogoutMaxRetries int `flag:"session-logout-max-retries" cfg:"session_logout_max_retries"`

	// RevocationEnabled turns on the shared revocation records that make
	// logout and administrative revocation effective on every replica.
	RevocationEnabled bool `flag:"session-revocation-enabled" cfg:"session_revocation_enabled"`

	// RevocationTTL is how long a revocation record is retained. It must be at
	// least as long as the cookie/session lifetime so revoked tickets cannot
	// become acceptable again. Zero falls back to the cookie expire duration.
	RevocationTTL time.Duration `flag:"session-revocation-ttl" cfg:"session_revocation_ttl"`

	// UserInfoStaleMaxAge, when > 0, enables upstream-change propagation: a
	// session whose embedded user-info snapshot is older than this age is
	// re-validated against the identity provider on the next request and
	// invalidated (revoked, reason upstream-userinfo-changed) if the upstream
	// rejects it. 0 (default) disables the feature, preserving the previous
	// "wait until expiry, up to 24h" behaviour.
	UserInfoStaleMaxAge time.Duration `flag:"session-userinfo-stale-max-age" cfg:"session_userinfo_stale_max_age"`
}

// EnsureDefaults fills the zero values of StrictSessionOptions with the
// behaviour-preserving defaults.
func (s *StrictSessionOptions) EnsureDefaults(cookieExpire time.Duration) {
	if s.UnavailablePolicy == "" {
		s.UnavailablePolicy = UnavailablePolicyFailClosed
	}
	if s.OperationTimeout == 0 {
		s.OperationTimeout = 2 * time.Second
	}
	if s.MaxRetries == 0 {
		s.MaxRetries = 3
	}
	if s.LogoutMaxRetries == 0 {
		s.LogoutMaxRetries = 5
	}
	if s.RevocationTTL == 0 {
		s.RevocationTTL = cookieExpire
	}
}

// Validate checks the strict-session configuration.
func (s StrictSessionOptions) Validate() error {
	switch s.UnavailablePolicy {
	case UnavailablePolicyFailClosed, UnavailablePolicyFailOpenStale:
	default:
		return fmt.Errorf("invalid session-unavailable-policy %q: expected %q or %q",
			s.UnavailablePolicy, UnavailablePolicyFailClosed, UnavailablePolicyFailOpenStale)
	}
	if s.OperationTimeout < 0 {
		return fmt.Errorf("session-operation-timeout must not be negative")
	}
	if s.MaxRetries < 0 || s.LogoutMaxRetries < 0 {
		return fmt.Errorf("session retry counts must not be negative")
	}
	if s.UserInfoStaleMaxAge < 0 || s.RevocationTTL < 0 {
		return fmt.Errorf("session revocation TTL and user-info stale age must not be negative")
	}
	return nil
}

// RedisStoreOptions contains configuration options for the RedisSessionStore.
type RedisStoreOptions struct {
	ConnectionURL          string   `flag:"redis-connection-url" cfg:"redis_connection_url"`
	Username               string   `flag:"redis-username" cfg:"redis_username"`
	Password               string   `flag:"redis-password" cfg:"redis_password"`
	UseSentinel            bool     `flag:"redis-use-sentinel" cfg:"redis_use_sentinel"`
	SentinelPassword       string   `flag:"redis-sentinel-password" cfg:"redis_sentinel_password"`
	SentinelMasterName     string   `flag:"redis-sentinel-master-name" cfg:"redis_sentinel_master_name"`
	SentinelConnectionURLs []string `flag:"redis-sentinel-connection-urls" cfg:"redis_sentinel_connection_urls"`
	UseCluster             bool     `flag:"redis-use-cluster" cfg:"redis_use_cluster"`
	ClusterConnectionURLs  []string `flag:"redis-cluster-connection-urls" cfg:"redis_cluster_connection_urls"`
	CAPath                 string   `flag:"redis-ca-path" cfg:"redis_ca_path"`
	InsecureSkipTLSVerify  bool     `flag:"redis-insecure-skip-tls-verify" cfg:"redis_insecure_skip_tls_verify"`
	IdleTimeout            int      `flag:"redis-connection-idle-timeout" cfg:"redis_connection_idle_timeout"`
}

func sessionOptionsDefaults() SessionOptions {
	return SessionOptions{
		Type: CookieSessionStoreType,
		Cookie: CookieStoreOptions{
			Minimal: false,
		},
		Strict: StrictSessionOptions{
			Enabled:           false,
			UnavailablePolicy: UnavailablePolicyFailClosed,
			// Keep these in sync with the defaults registered in NewFlagSet;
			// EnsureDefaults applies the same values when strict mode is built
			// directly (e.g. in tests) without going through flag parsing.
			OperationTimeout: 2 * time.Second,
			MaxRetries:       3,
			LogoutMaxRetries: 5,
		},
	}
}
