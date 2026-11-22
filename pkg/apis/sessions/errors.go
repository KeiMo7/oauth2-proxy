package sessions

import (
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Distinct session error conditions. These sentinel errors let callers tell
// "not logged in" apart from "the store is temporarily unavailable" and
// "the session was deliberately revoked" — which previously all surfaced as
// indistinguishable generic errors and were treated as unauthenticated.
var (
	// ErrSessionNotFound means a session ticket was presented but no session
	// exists for it in the store (e.g. it expired naturally and the TTL key was
	// removed, or it never existed). This is a natural expiry/missing condition,
	// not a storage failure.
	ErrSessionNotFound = errors.New("session not found")

	// ErrSessionCorrupt means session data was present but could not be
	// decrypted or decoded. The session must be invalidated rather than letting
	// a request proceed with a partial identity.
	ErrSessionCorrupt = errors.New("session data is corrupt")

	// ErrStoreUnavailable means the backing store could not be reached or did
	// not answer in time. The authentication state is unknown; callers must
	// apply a configured degradation policy rather than assume unauthenticated.
	ErrStoreUnavailable = errors.New("session store temporarily unavailable")

	// ErrSessionRevoked means the session was deliberately invalidated
	// (logout, admin revocation, upstream user-info change). This is distinct
	// from ErrSessionNotFound so audit logs can separate revocation from
	// natural expiry.
	ErrSessionRevoked = errors.New("session has been revoked")
)

// ErrorKind classifies a session error into a small fixed set used by the
// middleware to pick a behaviour and by tests/load tests to count outcomes.
type ErrorKind string

const (
	// KindUnauthenticated: no session cookie was presented (not logged in).
	KindUnauthenticated ErrorKind = "unauthenticated"
	// KindNotFound: ticket present but no session behind it (natural expiry).
	KindNotFound ErrorKind = "not_found"
	// KindCorrupt: session payload could not be parsed.
	KindCorrupt ErrorKind = "corrupt"
	// KindUnavailable: store timeout / connection failure (retryable).
	KindUnavailable ErrorKind = "unavailable"
	// KindRevoked: session deliberately revoked with a reason code.
	KindRevoked ErrorKind = "revoked"
	// KindUnknown: anything not covered above.
	KindUnknown ErrorKind = "unknown"
)

// ClassifyError maps any error returned by a session store to an ErrorKind.
// nil returns the empty kind. http.ErrNoCookie (or any wrapping of it) means
// the request carried no session cookie at all: KindUnauthenticated.
func ClassifyError(err error) ErrorKind {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrStoreUnavailable):
		return KindUnavailable
	case errors.Is(err, ErrSessionRevoked):
		return KindRevoked
	case errors.Is(err, ErrSessionCorrupt):
		return KindCorrupt
	case errors.Is(err, ErrSessionNotFound):
		return KindNotFound
	case errors.Is(err, http.ErrNoCookie):
		return KindUnauthenticated
	default:
		return KindUnknown
	}
}

// RevocationReason explains why a session was revoked. Reason codes are the
// audit-level distinction between natural expiry and human/system action.
type RevocationReason string

const (
	// ReasonUserLogout: end user explicitly signed out.
	ReasonUserLogout RevocationReason = "user-logout"
	// ReasonAdminRevoke: an administrator invalidated the session.
	ReasonAdminRevoke RevocationReason = "admin-revoke"
	// ReasonUpstreamUserInfoChanged: upstream identity info changed (e.g. the
	// user's permissions were withdrawn) and the local session was invalidated.
	ReasonUpstreamUserInfoChanged RevocationReason = "upstream-userinfo-changed"
	// ReasonRefreshTokenRevoked: the provider reported the refresh/access grant
	// is no longer valid (fatal OAuth refresh error).
	ReasonRefreshTokenRevoked RevocationReason = "refresh-token-revoked"
	// ReasonCorruptDestroyed: undecodable session data was destroyed.
	ReasonCorruptDestroyed RevocationReason = "corrupt-destroyed"
)

// RevokedError wraps ErrSessionRevoked with the audit reason and the time the
// revocation was recorded. Use errors.Is(err, ErrSessionRevoked) to detect it.
type RevokedError struct {
	Reason RevocationReason
	// At is when the revocation record was written.
	At time.Time
}

// Error implements the error interface.
func (e *RevokedError) Error() string {
	if e.At.IsZero() {
		return fmt.Sprintf("%s: %s", ErrSessionRevoked.Error(), e.Reason)
	}
	return fmt.Sprintf("%s: %s at %s", ErrSessionRevoked.Error(), e.Reason, e.At.UTC().Format(time.RFC3339))
}

// Unwrap allows errors.Is(err, ErrSessionRevoked).
func (e *RevokedError) Unwrap() error {
	return ErrSessionRevoked
}
