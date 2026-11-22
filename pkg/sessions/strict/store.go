package strict

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/persistence"
)

// UserInfoValidator re-checks a session's embedded user information against
// the upstream identity provider. Returning false means the upstream no longer
// accepts the identity (e.g. permissions were withdrawn) and the local session
// must be revoked. A non-nil error means the check could not be completed; the
// strict store treats that as store-unavailable rather than revoking on
// uncertainty.
type UserInfoValidator func(ctx context.Context, s *sessions.SessionState) (bool, error)

// Config carries the strict-semantics settings resolved from options.
type Config struct {
	UnavailablePolicy   string
	OperationTimeout    time.Duration
	MaxRetries          int
	LogoutMaxRetries    int
	RevocationEnabled   bool
	RevocationTTL       time.Duration
	UserInfoStaleMaxAge time.Duration
	CookieName          string
	SnapshotTTL         time.Duration
}

// Store wraps any sessions.SessionStore and adds the strict semantics:
// classified errors, retries with timeouts, shared revocation records,
// reliable logout and last-known-good degradation. It implements
// sessions.SessionStore without changing that interface.
type Store struct {
	inner        sessions.SessionStore
	cookieOpts   *options.Cookie
	cfg          Config
	revocations  RevocationStore
	snapshots    *snapshotCache
	validateInfo UserInfoValidator
	now          func() time.Time

	// reliableClear is implemented by persistence.Manager-backed inner stores
	// and performs the store deletion before touching the cookie, which is the
	// ordering required for a reliable logout.
	reliableClear interface {
		ClearStoreBeforeCookie(rw http.ResponseWriter, req *http.Request) error
	}
}

// NewStore wraps inner with the strict semantics described by cfg. When
// revocation is enabled, revocations must be non-nil; validateInfo may be nil
// when upstream-change propagation is disabled.
func NewStore(inner sessions.SessionStore, cookieOpts *options.Cookie, cfg Config, revocations RevocationStore, validateInfo UserInfoValidator) *Store {
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 1
	}
	if cfg.LogoutMaxRetries <= 0 {
		cfg.LogoutMaxRetries = cfg.MaxRetries
	}
	s := &Store{
		inner:        inner,
		cookieOpts:   cookieOpts,
		cfg:          cfg,
		revocations:  revocations,
		snapshots:    newSnapshotCache(cfg.SnapshotTTL),
		validateInfo: validateInfo,
		now:          time.Now,
	}
	if rc, ok := inner.(interface {
		ClearStoreBeforeCookie(http.ResponseWriter, *http.Request) error
	}); ok {
		s.reliableClear = rc
	}
	return s
}

// VerifyConnection delegates to the inner store.
func (s *Store) VerifyConnection(ctx context.Context) error {
	return s.inner.VerifyConnection(ctx)
}

// Load reads a session with strict error classification:
//   - http.ErrNoCookie (no cookie at all) is returned untouched: unauthenticated.
//   - ErrStoreUnavailable after retries is returned for the middleware to apply
//     the degradation policy; it is NEVER converted to "not logged in".
//   - ErrSessionCorrupt destroys the session and writes an audit record.
//   - ErrSessionRevoked is returned with its reason code when a live revocation
//     record exists.
//   - Successful loads refresh the last-known-good snapshot cache and, when
//     configured, re-validate stale user information upstream.
func (s *Store) Load(req *http.Request) (*sessions.SessionState, error) {
	ticketID, idErr := persistence.TicketIDFromRequest(req, s.cookieOpts)
	if idErr != nil {
		if errors.Is(idErr, http.ErrNoCookie) {
			return nil, http.ErrNoCookie
		}
		// An undecodable ticket cookie is a client-side corruption, not a store
		// outage: classify as corrupt so it is destroyed rather than retried.
		return nil, fmt.Errorf("%w: ticket cookie: %v", sessions.ErrSessionCorrupt, idErr)
	}

	// Revocation is checked BEFORE loading the session. The revocation record
	// is the durable security decision (written first during logout/revoke and
	// retained with a TTL); even if the session key is already gone or cannot
	// be read, a live record must surface as a revocation rather than a
	// benign-looking "not found".
	if s.cfg.RevocationEnabled && s.revocations != nil {
		record, revoked, revErr := s.revocations.IsRevoked(req.Context(), ticketID)
		if revErr != nil {
			// The revocation lookup itself depends on the store; if it cannot
			// be answered, the safe state is "unavailable", never "allowed".
			return nil, revErr
		}
		if revoked {
			s.snapshots.delete(ticketID)
			return nil, &sessions.RevokedError{Reason: record.Reason, At: record.At}
		}
	}

	var session *sessions.SessionState
	err := retry(req.Context(), s.cfg.MaxRetries, s.cfg.OperationTimeout, func(ctx context.Context) error {
		var loadErr error
		session, loadErr = s.inner.Load(req.WithContext(ctx))
		return loadErr
	})
	if err != nil {
		if errors.Is(err, sessions.ErrStoreUnavailable) {
			// Do not clear anything: the authentication state is unknown.
			return nil, err
		}
		switch {
		case errors.Is(err, sessions.ErrSessionNotFound):
			// Natural expiry: nothing to destroy, no revocation record.
			s.snapshots.delete(ticketID)
			return nil, err
		case errors.Is(err, sessions.ErrSessionCorrupt):
			s.destroyCorrupt(req, ticketID)
			return nil, err
		default:
			// Any other decode/decryption error from the inner store is treated
			// as corruption rather than, as in legacy code, an unauthenticated
			// user: never serve a half-parsed identity.
			logger.Errorf("session: unexpected load error for ticket %q, treating as corrupt: %v", ticketLabel(ticketID), err)
			s.destroyCorrupt(req, ticketID)
			return nil, fmt.Errorf("%w: %v", sessions.ErrSessionCorrupt, err)
		}
	}

	if s.cfg.UserInfoStaleMaxAge > 0 && s.validateInfo != nil {
		if s.userInfoIsStale(session) {
			ok, vErr := s.validateInfo(req.Context(), session)
			if vErr != nil {
				// Upstream check inconclusive: degrade, do not revoke on doubt.
				return nil, fmt.Errorf("%w: upstream user-info validation: %v", sessions.ErrStoreUnavailable, vErr)
			}
			if !ok {
				if markErr := s.markRevoked(req.Context(), ticketID, session, sessions.ReasonUpstreamUserInfoChanged); markErr != nil {
					return nil, markErr
				}
				s.snapshots.delete(ticketID)
				return nil, &sessions.RevokedError{Reason: sessions.ReasonUpstreamUserInfoChanged, At: s.now().UTC()}
			}
			now := s.now().UTC()
			session.UserInfoSnapshotAt = &now
		}
	}

	s.snapshots.put(ticketID, session, s.now())
	return session, nil
}

// Save writes the session without ever destroying an established login on
// failure. A failed Save returns ErrStoreUnavailable; the previously stored
// session (if any) and the cookie are left intact, and the caller keeps serving
// the in-memory session state.
func (s *Store) Save(rw http.ResponseWriter, req *http.Request, session *sessions.SessionState) error {
	err := retry(req.Context(), s.cfg.MaxRetries, s.cfg.OperationTimeout, func(ctx context.Context) error {
		return s.inner.Save(rw, req.WithContext(ctx), session)
	})
	if err != nil {
		// Explicitly do NOT Clear and do NOT overwrite the cookie.
		logger.Errorf("session: save failed for ticket, existing session preserved: %v", err)
		return err
	}
	// Refresh the degraded snapshot with the freshly persisted good state.
	if ticketID, idErr := persistence.TicketIDFromRequest(req, s.cookieOpts); idErr == nil {
		s.snapshots.put(ticketID, session, s.now())
	}
	return nil
}

// Clear implements reliable logout: the shared revocation record is written
// FIRST, then the session is deleted in the store, and only then is the cookie
// removed. Store operations use the dedicated logout retry budget; if they
// cannot be confirmed, the error is returned and the cookie is kept, so the
// user can retry logout and never gets a silent "signed out" while the session
// still exists.
func (s *Store) Clear(rw http.ResponseWriter, req *http.Request) error {
	ticketID, idErr := persistence.TicketIDFromRequest(req, s.cookieOpts)
	if idErr != nil && !errors.Is(idErr, http.ErrNoCookie) {
		// Even with an unreadable ticket we still attempt the inner Clear so a
		// bad cookie gets removed; but revocation cannot be keyed reliably.
		logger.Errorf("session: logout with undecodable ticket cookie: %v", idErr)
		return s.retryClear(rw, req)
	}

	if s.cfg.RevocationEnabled && s.revocations != nil && ticketID != "" {
		markErr := retry(req.Context(), s.cfg.LogoutMaxRetries, s.cfg.OperationTimeout, func(ctx context.Context) error {
			return s.markRevoked(ctx, ticketID, nil, sessions.ReasonUserLogout)
		})
		if markErr != nil {
			// Keep the cookie: the user must be able to retry.
			return fmt.Errorf("logout could not be confirmed (revocation record write failed): %w", markErr)
		}
	}

	if err := s.retryClear(rw, req); err != nil {
		return fmt.Errorf("logout could not be confirmed (session delete failed): %w", err)
	}
	s.snapshots.delete(ticketID)
	return nil
}

// retryClear deletes the server-side session with the logout retry budget.
// When the inner store supports the reliable ordering (store first, cookie
// second) it is used; otherwise we fall back to the ordinary Clear.
func (s *Store) retryClear(rw http.ResponseWriter, req *http.Request) error {
	return retry(req.Context(), s.cfg.LogoutMaxRetries, s.cfg.OperationTimeout, func(ctx context.Context) error {
		ctxReq := req.WithContext(ctx)
		if s.reliableClear != nil {
			return s.reliableClear.ClearStoreBeforeCookie(rw, ctxReq)
		}
		return s.inner.Clear(rw, ctxReq)
	})
}

// markRevoked writes a revocation record for ticketID, enriching it with the
// user identity when a session is available.
func (s *Store) markRevoked(ctx context.Context, ticketID string, session *sessions.SessionState, reason sessions.RevocationReason) error {
	if !s.cfg.RevocationEnabled || s.revocations == nil {
		return nil
	}
	record := RevocationRecord{Reason: reason, At: s.now().UTC()}
	if session != nil {
		record.User = session.User
		if record.User == "" {
			record.User = session.Email
		}
	}
	return s.revocations.MarkRevoked(ctx, ticketID, record, s.cfg.RevocationTTL)
}

// destroyCorrupt removes a session whose payload could not be decoded and
// records the destruction for audit. Best effort: a failed delete during an
// outage is logged, not fatal, because the corrupt blob is unusable regardless.
func (s *Store) destroyCorrupt(req *http.Request, ticketID string) {
	logger.Errorf("session: corrupt session %q invalidated", ticketLabel(ticketID))
	if err := s.markRevoked(req.Context(), ticketID, nil, sessions.ReasonCorruptDestroyed); err != nil {
		logger.Errorf("session: could not write corruption revocation record: %v", err)
	}
	if err := s.inner.Clear(noopResponseWriter{}, req); err != nil {
		logger.Errorf("session: best-effort delete of corrupt session failed: %v", err)
	}
	s.snapshots.delete(ticketID)
}

// userInfoIsStale reports whether the embedded user-info snapshot needs an
// upstream re-check. Sessions written by older versions have no snapshot
// timestamp; they are treated as stale so the first strict-mode request
// re-validates them once.
func (s *Store) userInfoIsStale(session *sessions.SessionState) bool {
	if session.UserInfoSnapshotAt == nil || session.UserInfoSnapshotAt.IsZero() {
		return true
	}
	return s.now().Sub(*session.UserInfoSnapshotAt) > s.cfg.UserInfoStaleMaxAge
}

// DegradedSnapshot returns the last-known-good session for ticketID when the
// store is unavailable and the fail-open-stale policy is active. The middleware
// calls this only after Load returned ErrStoreUnavailable.
func (s *Store) DegradedSnapshot(ticketID string) (*sessions.SessionState, bool) {
	return s.snapshots.get(ticketID, s.now())
}

// TicketID exposes the ticket ID for a request so the middleware can look up a
// degraded snapshot after an unavailable error.
func (s *Store) TicketID(req *http.Request) (string, error) {
	return persistence.TicketIDFromRequest(req, s.cookieOpts)
}

// UnavailablePolicyName reports the configured store-unavailable policy. It
// lets the middleware read the policy through a narrow interface without
// importing this package.
func (s *Store) UnavailablePolicyName() string {
	return s.cfg.UnavailablePolicy
}

// UserInfoValidatorSetter is implemented by stores that can accept an upstream
// user-info validation callback after construction. The session store is built
// before the identity provider in the proxy bootstrap, so the callback is
// wired once the provider exists.
type UserInfoValidatorSetter interface {
	SetUserInfoValidator(UserInfoValidator)
}

// SetUserInfoValidator installs (or replaces) the upstream user-info
// validation callback used by the stale-user-info feature.
func (s *Store) SetUserInfoValidator(v UserInfoValidator) {
	s.validateInfo = v
}

// Revoker is the capability to invalidate a session with an explicit audit
// reason distinct from natural expiry. The strict store implements it; the
// middleware uses it when an upstream event (e.g. a revoked refresh token)
// demands immediate invalidation.
type Revoker interface {
	Revoke(req *http.Request, session *sessions.SessionState, reason sessions.RevocationReason) error
}

// Revoke writes a revocation record for the ticket carried by req and deletes
// the stored session. Unlike Clear (the logout path) it does not remove the
// cookie itself; the caller's normal error flow handles the response. It is
// safe to call when revocation is disabled: it then performs a plain delete.
func (s *Store) Revoke(req *http.Request, session *sessions.SessionState, reason sessions.RevocationReason) error {
	ticketID, err := persistence.TicketIDFromRequest(req, s.cookieOpts)
	if err != nil {
		return fmt.Errorf("resolve ticket for revocation: %w", err)
	}
	if err := s.markRevoked(req.Context(), ticketID, session, reason); err != nil {
		return err
	}
	if err := s.inner.Clear(noopResponseWriter{}, req); err != nil {
		return fmt.Errorf("delete revoked session: %w", err)
	}
	s.snapshots.delete(ticketID)
	logger.Printf("session revoked (reason=%s) ticket=%q", reason, ticketLabel(ticketID))
	return nil
}

// ticketLabel returns a non-sensitive identifier for logs: the ticket prefix
// plus a short hash, never the full ID.
func ticketLabel(ticketID string) string {
	if len(ticketID) <= 12 {
		return ticketID
	}
	return ticketID[:12] + "…"
}

// noopResponseWriter swallows the cookie writes produced by an inner Clear so
// the best-effort corrupt-session delete does not mutate the real response.
type noopResponseWriter struct{}

func (noopResponseWriter) Header() http.Header       { return http.Header{} }
func (noopResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (noopResponseWriter) WriteHeader(int)           {}

var _ sessions.SessionStore = (*Store)(nil)

// ConfigFromOptions resolves the strict wrapper Config from parsed options.
func ConfigFromOptions(strict options.StrictSessionOptions, cookieOpts *options.Cookie) Config {
	snapshotTTL := time.Duration(0)
	if strict.UnavailablePolicy == options.UnavailablePolicyFailOpenStale {
		// Cap how long a snapshot may be served without any store contact.
		snapshotTTL = cookieOpts.Refresh
		if snapshotTTL <= 0 {
			snapshotTTL = 5 * time.Minute
		}
	}
	return Config{
		UnavailablePolicy:   strict.UnavailablePolicy,
		OperationTimeout:    strict.OperationTimeout,
		MaxRetries:          strict.MaxRetries,
		LogoutMaxRetries:    strict.LogoutMaxRetries,
		RevocationEnabled:   strict.RevocationEnabled,
		RevocationTTL:       strict.RevocationTTL,
		UserInfoStaleMaxAge: strict.UserInfoStaleMaxAge,
		CookieName:          cookieOpts.Name,
		SnapshotTTL:         snapshotTTL,
	}
}
