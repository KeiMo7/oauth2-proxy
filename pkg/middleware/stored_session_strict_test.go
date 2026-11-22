package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

// strictFakeStore implements sessions.SessionStore plus the strictStore and
// policyReader capabilities used by the loader's classified-error path.
type strictFakeStore struct {
	loadErr     error
	loadSession *sessionsapi.SessionState
	clearErr    error
	clearCalls  int
	policy      string
	snapshot    *sessionsapi.SessionState
	snapshotOK  bool
	ticketID    string
	ticketErr   error
}

func (f *strictFakeStore) Save(_ http.ResponseWriter, _ *http.Request, _ *sessionsapi.SessionState) error {
	return nil
}

func (f *strictFakeStore) Load(_ *http.Request) (*sessionsapi.SessionState, error) {
	if f.loadErr != nil {
		return nil, f.loadErr
	}
	return f.loadSession, nil
}

func (f *strictFakeStore) Clear(_ http.ResponseWriter, _ *http.Request) error {
	f.clearCalls++
	return f.clearErr
}

func (f *strictFakeStore) VerifyConnection(_ context.Context) error {
	return nil
}

func (f *strictFakeStore) DegradedSnapshot(_ string) (*sessionsapi.SessionState, bool) {
	return f.snapshot, f.snapshotOK
}

func (f *strictFakeStore) TicketID(_ *http.Request) (string, error) {
	return f.ticketID, f.ticketErr
}

func (f *strictFakeStore) UnavailablePolicyName() string { return f.policy }

func newStrictLoader(store sessionsapi.SessionStore) http.Handler {
	opts := &StoredSessionLoaderOptions{
		SessionStore: store,
		RefreshSession: func(_ context.Context, _ *sessionsapi.SessionState) (bool, error) {
			return false, nil
		},
		ValidateSession: func(_ context.Context, _ *sessionsapi.SessionState) bool {
			return true
		},
	}
	return NewStoredSessionLoader(opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

func scopedRequest() (*httptest.ResponseRecorder, *http.Request) {
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req = middlewareapi.AddRequestScope(req, &middlewareapi.RequestScope{})
	return rw, req
}

func TestStrictUnavailableFailClosedReturns503(t *testing.T) {
	store := &strictFakeStore{
		loadErr: sessionsapi.ErrStoreUnavailable,
		policy:  options.UnavailablePolicyFailClosed,
	}
	rw, req := scopedRequest()
	newStrictLoader(store).ServeHTTP(rw, req)

	if rw.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rw.Code)
	}
	if rw.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header on 503")
	}
	if store.clearCalls != 0 {
		t.Fatalf("clear called %d times; unavailable must never clear the session", store.clearCalls)
	}
}

func TestStrictUnavailableFailOpenStaleServesSnapshot(t *testing.T) {
	snapshot := &sessionsapi.SessionState{User: "stale-user"}
	store := &strictFakeStore{
		loadErr:    sessionsapi.ErrStoreUnavailable,
		policy:     options.UnavailablePolicyFailOpenStale,
		snapshot:   snapshot,
		snapshotOK: true,
		ticketID:   "ticket-1",
	}
	rw, req := scopedRequest()
	newStrictLoader(store).ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with degraded snapshot", rw.Code)
	}
	scope := middlewareapi.GetRequestScope(req)
	if scope.Session == nil || scope.Session.User != "stale-user" {
		t.Fatalf("scope session = %+v, want degraded snapshot", scope.Session)
	}
	if !scope.SessionDegraded {
		t.Fatal("expected SessionDegraded flag on scope")
	}
}

func TestStrictFailOpenWithoutSnapshotFallsBackTo503(t *testing.T) {
	store := &strictFakeStore{
		loadErr:    sessionsapi.ErrStoreUnavailable,
		policy:     options.UnavailablePolicyFailOpenStale,
		snapshotOK: false,
		ticketID:   "ticket-1",
	}
	rw, req := scopedRequest()
	newStrictLoader(store).ServeHTTP(rw, req)

	if rw.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when no snapshot is available", rw.Code)
	}
}

func TestStrictNotFoundDoesNotClearAndPassesThrough(t *testing.T) {
	store := &strictFakeStore{loadErr: sessionsapi.ErrSessionNotFound}
	rw, req := scopedRequest()
	newStrictLoader(store).ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d, want chain to continue with nil session", rw.Code)
	}
	if store.clearCalls != 0 {
		t.Fatalf("natural expiry triggered %d clears; it must not", store.clearCalls)
	}
	if middlewareapi.GetRequestScope(req).Session != nil {
		t.Fatal("session must remain nil for not-found")
	}
}

func TestStrictRevokedPassesThroughWithoutClear(t *testing.T) {
	store := &strictFakeStore{loadErr: &sessionsapi.RevokedError{Reason: sessionsapi.ReasonUserLogout}}
	rw, req := scopedRequest()
	newStrictLoader(store).ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d", rw.Code)
	}
	if store.clearCalls != 0 {
		t.Fatalf("revocation path must not double-clear, got %d", store.clearCalls)
	}
}

func TestStrictCorruptClearsCookie(t *testing.T) {
	store := &strictFakeStore{loadErr: sessionsapi.ErrSessionCorrupt}
	rw, req := scopedRequest()
	newStrictLoader(store).ServeHTTP(rw, req)

	if store.clearCalls != 1 {
		t.Fatalf("corrupt path clear calls = %d, want 1", store.clearCalls)
	}
}

func TestStrictUnauthenticatedPassesThrough(t *testing.T) {
	store := &strictFakeStore{loadErr: http.ErrNoCookie}
	rw, req := scopedRequest()
	newStrictLoader(store).ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d", rw.Code)
	}
	if store.clearCalls != 0 {
		t.Fatalf("no-cookie must not clear, got %d", store.clearCalls)
	}
}

// legacyClearStore wraps fakeSessionStore to count clears for the legacy
// behaviour assertion.
type legacyClearStore struct {
	*fakeSessionStore
	clearCalls int
}

func (l *legacyClearStore) Clear(rw http.ResponseWriter, req *http.Request) error {
	l.clearCalls++
	return l.fakeSessionStore.Clear(rw, req)
}

func TestLegacyStoreKeepsClearOnUnknownError(t *testing.T) {
	// A store that does not implement the strictStore interface must keep the
	// historical behaviour: clear the session on any non-ErrNoCookie error.
	store := &legacyClearStore{
		fakeSessionStore: &fakeSessionStore{
			LoadFunc: func(req *http.Request) (*sessionsapi.SessionState, error) {
				return nil, errors.New("some legacy error")
			},
		},
	}
	rw, req := scopedRequest()
	opts := &StoredSessionLoaderOptions{
		SessionStore:    store,
		RefreshSession:  func(_ context.Context, _ *sessionsapi.SessionState) (bool, error) { return false, nil },
		ValidateSession: func(_ context.Context, _ *sessionsapi.SessionState) bool { return true },
	}
	NewStoredSessionLoader(opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d", rw.Code)
	}
	if store.clearCalls != 1 {
		t.Fatalf("legacy path clear calls = %d, want 1 (behaviour preserved)", store.clearCalls)
	}
}
