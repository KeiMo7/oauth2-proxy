package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/justinas/alice"
	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
)

const (
	// When attempting to obtain the lock, if it's not done before this timeout
	// then exit and fail the refresh attempt.
	// TODO: This should probably be configurable by the end user.
	sessionRefreshObtainTimeout = 5 * time.Second

	// Maximum time allowed for a session refresh attempt.
	// If the refresh request isn't finished within this time, the lock will be
	// released.
	// TODO: This should probably be configurable by the end user.
	sessionRefreshLockDuration = 2 * time.Second

	// How long to wait after failing to obtain the lock before trying again.
	// TODO: This should probably be configurable by the end user.
	sessionRefreshRetryPeriod = 10 * time.Millisecond
)

// isFatalRefreshError checks if a refresh error indicates a revoked or
// non-existent session that should be immediately invalidated.
// Fatal errors indicate the session is no longer valid at the provider level.
// Non-fatal errors (network issues, timeouts) should not invalidate the session.
//
// Only checks standard OAuth2 error codes (RFC 6749 Section 5.2).
// Does NOT check error_description strings as they are optional and provider-specific.
func isFatalRefreshError(err error) bool {
	if err == nil {
		return false
	}

	// Only check standard OAuth2 error codes (RFC 6749 Section 5.2)
	// Do NOT check error_description strings as they are optional and provider-specific
	fatalErrors := []string{
		"invalid_grant",  // refresh token revoked, expired, or session terminated
		"invalid_client", // client credentials no longer valid
	}

	for _, fe := range fatalErrors {
		if strings.Contains(err.Error(), fe) {
			return true
		}
	}
	return false
}

// StoredSessionLoaderOptions contains all of the requirements to construct
// a stored session loader.
// All options must be provided.
type StoredSessionLoaderOptions struct {
	// Session storage backend
	SessionStore sessionsapi.SessionStore

	// How often should sessions be refreshed
	RefreshPeriod time.Duration

	// Provider based session refreshing
	RefreshSession func(context.Context, *sessionsapi.SessionState) (bool, error)

	// Provider based session validation.
	// If the sesssion is older than `RefreshPeriod` but the provider doesn't
	// refresh it, we must re-validate using this validation.
	ValidateSession func(context.Context, *sessionsapi.SessionState) bool
}

// NewStoredSessionLoader creates a new storedSessionLoader which loads
// sessions from the session store.
// If no session is found, the request will be passed to the nex handler.
// If a session was loader by a previous handler, it will not be replaced.
func NewStoredSessionLoader(opts *StoredSessionLoaderOptions) alice.Constructor {
	ss := &storedSessionLoader{
		store:            opts.SessionStore,
		refreshPeriod:    opts.RefreshPeriod,
		sessionRefresher: opts.RefreshSession,
		sessionValidator: opts.ValidateSession,
	}
	return ss.loadSession
}

// strictStore is the optional capability surface implemented by the strict
// session semantics wrapper. Presence of this interface switches the loader
// onto the classified-error path; ordinary stores (legacy behaviour) do not
// implement it and keep their original handling.
type strictStore interface {
	// DegradedSnapshot returns a last-known-good session for ticketID when the
	// store is unavailable and fail-open-stale is configured.
	DegradedSnapshot(ticketID string) (*sessionsapi.SessionState, bool)
	// TicketID resolves the ticket ID carried by the request.
	TicketID(req *http.Request) (string, error)
}

// policyReader is implemented by the strict wrapper to report its configured
// unavailable policy without the middleware importing the strict package.
type policyReader interface {
	UnavailablePolicyName() string
}

// revoker is the strict-store capability to invalidate a session with an
// explicit audit reason. It mirrors strict.Revoker through a local interface to
// avoid an import cycle (the strict package already depends on apis/sessions).
type revoker interface {
	Revoke(req *http.Request, session *sessionsapi.SessionState, reason sessionsapi.RevocationReason) error
}

// storedSessionLoader is responsible for loading sessions from cookie
// identified sessions in the session store.
type storedSessionLoader struct {
	store            sessionsapi.SessionStore
	refreshPeriod    time.Duration
	sessionRefresher func(context.Context, *sessionsapi.SessionState) (bool, error)
	sessionValidator func(context.Context, *sessionsapi.SessionState) bool
}

// strictEnabled reports whether the wrapped store provides strict semantics.
func (s *storedSessionLoader) strictEnabled() (strictStore, bool) {
	st, ok := s.store.(strictStore)
	return st, ok
}

// unavailablePolicy returns the configured degradation policy, defaulting to
// fail-closed when the store does not expose one.
func (s *storedSessionLoader) unavailablePolicy(st strictStore) string {
	if pr, ok := st.(policyReader); ok {
		return pr.UnavailablePolicyName()
	}
	return options.UnavailablePolicyFailClosed
}

// loadSession attempts to load a session as identified by the request cookies.
// If no session is found, the request will be passed to the next handler.
// If a session was loader by a previous handler, it will not be replaced.
func (s *storedSessionLoader) loadSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		scope := middlewareapi.GetRequestScope(req)
		// If scope is nil, this will panic.
		// A scope should always be injected before this handler is called.
		if scope.Session != nil {
			// The session was already loaded, pass to the next handler
			next.ServeHTTP(rw, req)
			return
		}

		st, strict := s.strictEnabled()

		session, err := s.getValidatedSession(rw, req)
		if err == nil {
			scope.Session = session
			next.ServeHTTP(rw, req)
			return
		}

		if strict {
			// stop is true when the response is already complete (503) and the
			// request must not continue down the chain.
			if stop := s.handleStrictError(rw, req, st, err, scope); stop {
				return
			}
			// If the degradation policy attached a last-known-good snapshot,
			// mark the request context so downstream code skips refresh/write.
			if scope.SessionDegraded {
				req = req.WithContext(withDegraded(req.Context()))
			}
			// Classified conditions (not-found/revoked/corrupt/no-cookie, or a
			// degraded snapshot) fall through: scope.Session is either nil
			// (sign-in redirect) or a degraded session (request continues).
			next.ServeHTTP(rw, req)
			return
		}

		if !errors.Is(err, http.ErrNoCookie) {
			// Legacy behaviour: any load error clears the session cookie.
			logger.Errorf("Error loading cookied session: %v, removing session", err)
			if clearErr := s.store.Clear(rw, req); clearErr != nil {
				logger.Errorf("Error removing session: %v", clearErr)
			}
		}

		// Add the session to the scope if it was found
		scope.Session = session
		next.ServeHTTP(rw, req)
	})
}

// handleStrictError applies the degradation policy to a classified session
// error. It returns true when the response is fully written and the caller must
// stop processing (the fail-closed 503 path); false means the request should
// continue with scope.Session either nil or a degraded snapshot.
func (s *storedSessionLoader) handleStrictError(rw http.ResponseWriter, req *http.Request, st strictStore, err error, scope *middlewareapi.RequestScope) bool {
	kind := sessionsapi.ClassifyError(err)

	switch kind {
	case sessionsapi.KindUnavailable:
		if s.unavailablePolicy(st) == options.UnavailablePolicyFailOpenStale {
			ticketID, idErr := st.TicketID(req)
			if idErr == nil {
				if snapshot, ok := st.DegradedSnapshot(ticketID); ok {
					scope.Session = snapshot
					scope.SessionDegraded = true
					logger.Errorf("session store unavailable, serving degraded last-known-good session for ticket %q: %v", shortTicketID(ticketID), err)
					return false
				}
			}
			logger.Errorf("session store unavailable and no degraded snapshot available, failing closed: %v", err)
		} else {
			logger.Errorf("session store unavailable, fail-closed policy rejecting request: %v", err)
		}
		// fail-closed, or fail-open-stale without a usable snapshot
		rw.Header().Set("Retry-After", "2")
		rw.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(rw, "session store temporarily unavailable, please retry shortly")
		return true

	case sessionsapi.KindRevoked:
		// Deliberate invalidation: no Clear (the revocation record already
		// exists), normal sign-in redirect with scope.Session == nil.
		logger.Printf("session rejected: revoked: %v", err)
		return false

	case sessionsapi.KindCorrupt:
		// The strict wrapper already destroyed the session and wrote an audit
		// record; make sure the stale cookie is removed as well.
		logger.Errorf("session rejected: corrupt: %v", err)
		if clearErr := s.store.Clear(rw, req); clearErr != nil {
			logger.Errorf("error clearing corrupt session cookie: %v", clearErr)
		}
		return false

	case sessionsapi.KindNotFound:
		// Natural expiry: no Clear and no audit alarm; normal sign-in redirect.
		logger.Printf("session not found in store (natural expiry): %v", err)
		return false

	case sessionsapi.KindUnauthenticated:
		// No cookie: plain unauthenticated request.
		return false

	default:
		// Unclassified error in strict mode still must not destroy the
		// session: reject until the condition clears rather than sign the user
		// out.
		logger.Errorf("unclassified session error, treating as unavailable: %v", err)
		rw.Header().Set("Retry-After", "2")
		rw.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(rw, "session handling error, please retry shortly")
		return true
	}
}

// shortTicketID returns a shortened, non-sensitive ticket identifier for logs.
func shortTicketID(ticketID string) string {
	if len(ticketID) <= 12 {
		return ticketID
	}
	return ticketID[:12] + "…"
}

// getValidatedSession is responsible for loading a session and making sure
// that it is valid.
func (s *storedSessionLoader) getValidatedSession(rw http.ResponseWriter, req *http.Request) (*sessionsapi.SessionState, error) {
	session, err := s.store.Load(req)
	if err != nil || session == nil {
		// No session was found in the storage or error occurred, nothing more to do
		return nil, err
	}

	// A degraded snapshot (fail-open-stale during a store outage) is served
	// without refresh, re-validation or write-back: the store cannot be trusted
	// for any of those operations right now.
	if isDegraded(req.Context()) {
		return session, nil
	}

	err = s.refreshSessionIfNeeded(rw, req, session)
	if err != nil {
		return nil, fmt.Errorf("error refreshing access token for session (%s): %v", session, err)
	}

	return session, nil
}

// refreshSessionIfNeeded will attempt to refresh a session if the session
// is older than the refresh period.
// Success or fail, we will then validate the session.
func (s *storedSessionLoader) refreshSessionIfNeeded(rw http.ResponseWriter, req *http.Request, session *sessionsapi.SessionState) error {
	if !needsRefresh(s.refreshPeriod, session) {
		// Refresh is disabled or the session is not old enough, do nothing
		return nil
	}

	var lockObtained bool
	ctx, cancel := context.WithTimeout(context.Background(), sessionRefreshObtainTimeout)
	defer cancel()

	for !lockObtained {
		select {
		case <-ctx.Done():
			return errors.New("timeout obtaining session lock")
		default:
			err := session.ObtainLock(req.Context(), sessionRefreshLockDuration)
			if err != nil && !errors.Is(err, sessionsapi.ErrLockNotObtained) {
				return fmt.Errorf("error occurred while trying to obtain lock: %v", err)
			} else if errors.Is(err, sessionsapi.ErrLockNotObtained) {
				time.Sleep(sessionRefreshRetryPeriod)
				continue
			}
			// No error means we obtained the lock
			lockObtained = true
		}
	}

	// The rest of this function is carried out under lock, but we must release it
	// wherever we exit from this function.
	defer func() {
		if session == nil {
			return
		}
		if err := session.ReleaseLock(req.Context()); err != nil {
			logger.Errorf("unable to release lock: %v", err)
		}
	}()

	// Reload the session in case it was changed underneath us.
	freshSession, err := s.store.Load(req)
	if err != nil {
		return fmt.Errorf("could not load session: %v", err)
	}
	if freshSession == nil {
		return errors.New("session no longer exists, it may have been removed by another request")
	}
	// Restore the state of the fresh session into the original pointer.
	// This is important so that changes are passed up the to the parent scope.
	lock := session.Lock
	*session = *freshSession

	// Ensure we maintain the session lock after we have refreshed the session.
	// Loading from the session store creates a new lock in the session.
	session.Lock = lock

	if !needsRefresh(s.refreshPeriod, session) {
		// The session must have already been refreshed while we were waiting to
		// obtain the lock.
		return nil
	}

	// We are holding the lock and the session needs a refresh
	logger.Printf("Refreshing session - User: %s; SessionAge: %s", session.User, session.Age())
	if err := s.refreshSession(rw, req, session); err != nil {
		logger.Errorf("Unable to refresh session: %v", err)

		// Check if this is a fatal error that indicates the session is revoked
		// or no longer valid at the provider level
		if isFatalRefreshError(err) {
			logger.Printf("Fatal refresh error detected (session revoked or invalid), clearing session for user: %s", session.User)

			if revoker, ok := s.store.(revoker); ok {
				// Strict mode: record an auditable revocation with the provider
				// reason rather than a plain cookie clear.
				if revErr := revoker.Revoke(req, session, sessionsapi.ReasonRefreshTokenRevoked); revErr != nil {
					logger.Errorf("failed revoking session: %v", revErr)
				}
				// Always clear the cookie so the user is sent to re-authenticate
				// even if the revocation record could not be written yet.
				if clearErr := s.store.Clear(rw, req); clearErr != nil {
					logger.Errorf("failed clearing session cookie: %v", clearErr)
				}
			} else {
				// Clear the session from storage (Redis) and remove the cookie
				if err := s.store.Clear(rw, req); err != nil {
					logger.Errorf("failed clearing session: %v", err)
				}
			}

			// Return error immediately to force re-authentication
			return fmt.Errorf("session invalidated due to fatal refresh error: %w", err)
		}

		// For non-fatal errors (network issues, timeouts), keep the session
		// and let validateSession determine if it's still usable
	}

	// Validate all sessions after any Redeem/Refresh operation (fail or success)
	return s.validateSession(req.Context(), session)
}

// needsRefresh determines whether we should attempt to refresh a session or not.
func needsRefresh(refreshPeriod time.Duration, session *sessionsapi.SessionState) bool {
	return refreshPeriod > time.Duration(0) && session.Age() > refreshPeriod
}

// refreshSession attempts to refresh the session with the provider
// and will save the session if it was updated.
func (s *storedSessionLoader) refreshSession(rw http.ResponseWriter, req *http.Request, session *sessionsapi.SessionState) error {
	refreshed, err := s.sessionRefresher(req.Context(), session)
	if err != nil && !errors.Is(err, providers.ErrNotImplemented) {
		return fmt.Errorf("error refreshing tokens: %v", err)
	}

	// HACK:
	// Providers that don't implement `RefreshSession` use the default
	// implementation which returns `ErrNotImplemented`.
	// Pretend it refreshed to reset the refresh timer so that `ValidateSession`
	// isn't triggered every subsequent request and is only called once during
	// this request.
	if errors.Is(err, providers.ErrNotImplemented) {
		refreshed = true
	}

	// Session not refreshed, nothing to persist.
	if !refreshed {
		logger.Printf("Session not refreshed - User: %s; no refresh token available or provider returned false", session.User)
		return nil
	}

	// If we refreshed, update the `CreatedAt` time to reset the refresh timer
	// (In case underlying provider implementations forget)
	session.CreatedAtNow()

	// Because the session was refreshed, make sure to save it
	err = s.store.Save(rw, req, session)
	if err != nil {
		logger.PrintAuthf(session.Email, req, logger.AuthError, "error saving session: %v", err)
		if _, strict := s.strictEnabled(); strict && errors.Is(err, sessionsapi.ErrStoreUnavailable) {
			// The write failed but the established login must not be destroyed:
			// keep serving with the in-memory session state. The strict store
			// already retried and left the old stored value untouched; the next
			// successful request will persist the refreshed state.
			logger.Printf("session write unavailable, preserving existing login for user %q", session.User)
			return nil
		}
		return fmt.Errorf("error saving session: %v", err)
	}
	return nil
}

// validateSession checks whether the session has expired and performs
// provider validation on the session.
// An error implies the session is not longer valid.
func (s *storedSessionLoader) validateSession(ctx context.Context, session *sessionsapi.SessionState) error {
	if session.IsExpired() {
		return errors.New("session is expired")
	}

	if !s.sessionValidator(ctx, session) {
		return errors.New("session is invalid")
	}

	return nil
}
