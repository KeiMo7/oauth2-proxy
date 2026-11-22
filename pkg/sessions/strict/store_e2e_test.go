package strict_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	memorystore "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/memory"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/persistence"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/strict"
)

func testCookieOpts() *options.Cookie {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	return &options.Cookie{
		Name:     "_oauth2_proxy",
		Path:     "/",
		Expire:   time.Hour,
		Refresh:  10 * time.Minute,
		Secure:   false,
		HTTPOnly: true,
		Secret:   base64.URLEncoding.EncodeToString(secret),
	}
}

type e2EHarness struct {
	store       *strict.Store
	mem         *memorystore.SessionStore
	revocations *strict.MemoryRevocationStoreControl
	cookieOpts  *options.Cookie
}

// newE2EStore builds a real persistence.Manager over the in-memory backend
// (identical ticket/cookie path to Redis) wrapped by the strict store. Both
// the session backend and the revocation store are returned with independent
// fault controls.
func newE2EStore(t *testing.T, policy string) e2EHarness {
	t.Helper()
	cookieOpts := testCookieOpts()

	mem := memorystore.NewRawStore()
	manager := persistence.NewManager(mem, cookieOpts)
	rev := strict.NewMemoryRevocationStore()

	cfg := strict.Config{
		UnavailablePolicy: policy,
		OperationTimeout:  200 * time.Millisecond,
		MaxRetries:        3,
		LogoutMaxRetries:  4,
		RevocationEnabled: true,
		RevocationTTL:     time.Hour,
		CookieName:        cookieOpts.Name,
	}
	if policy == options.UnavailablePolicyFailOpenStale {
		cfg.SnapshotTTL = 10 * time.Minute
	}
	store := strict.NewStore(manager, cookieOpts, cfg, rev, nil)
	return e2EHarness{
		store:       store,
		mem:         mem,
		revocations: strict.RevocationControl(rev),
		cookieOpts:  cookieOpts,
	}
}

func saveSessionAndExtractCookie(t *testing.T, store sessions.SessionStore, cookieOpts *options.Cookie) (*http.Cookie, *sessions.SessionState) {
	t.Helper()
	expires := time.Now().Add(time.Hour)
	session := &sessions.SessionState{
		User:      "john.doe",
		Email:     "john.doe@example.com",
		ExpiresOn: &expires,
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	rw := httptest.NewRecorder()
	if err := store.Save(rw, req, session); err != nil {
		t.Fatalf("save: %v", err)
	}
	cookies := rw.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 set-cookie, got %d", len(cookies))
	}
	if cookies[0].Name != cookieOpts.Name {
		t.Fatalf("cookie name = %q", cookies[0].Name)
	}
	return cookies[0], session
}

func requestWithCookie(c *http.Cookie) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.AddCookie(c)
	return req
}

func TestE2ELoadRoundTrip(t *testing.T) {
	h := newE2EStore(t, options.UnavailablePolicyFailClosed)
	cookie, original := saveSessionAndExtractCookie(t, h.store, h.cookieOpts)

	loaded, err := h.store.Load(requestWithCookie(cookie))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.User != original.User {
		t.Fatalf("loaded user = %q, want %q", loaded.User, original.User)
	}
}

func TestE2EStoreOutageIsUnavailableNotSignedOut(t *testing.T) {
	h := newE2EStore(t, options.UnavailablePolicyFailClosed)
	cookie, _ := saveSessionAndExtractCookie(t, h.store, h.cookieOpts)

	h.mem.SetFaultFunc(func(string) error { return sessions.ErrStoreUnavailable })
	h.revocations.SetFaultFunc(func(string) error { return sessions.ErrStoreUnavailable })

	_, err := h.store.Load(requestWithCookie(cookie))
	if !errors.Is(err, sessions.ErrStoreUnavailable) {
		t.Fatalf("err = %v, want ErrStoreUnavailable (not a clear/not-found)", err)
	}

	// After the outage clears, the same session must still work unchanged.
	h.mem.SetFaultFunc(nil)
	h.revocations.SetFaultFunc(nil)
	loaded, err := h.store.Load(requestWithCookie(cookie))
	if err != nil {
		t.Fatalf("load after recovery: %v", err)
	}
	if loaded.User != "john.doe" {
		t.Fatalf("user = %q, session was lost across outage", loaded.User)
	}
}

func TestE2EFailOpenStaleServesSnapshotDuringOutage(t *testing.T) {
	h := newE2EStore(t, options.UnavailablePolicyFailOpenStale)
	cookie, _ := saveSessionAndExtractCookie(t, h.store, h.cookieOpts)

	// Prime the snapshot cache with a successful read.
	if _, err := h.store.Load(requestWithCookie(cookie)); err != nil {
		t.Fatalf("priming load: %v", err)
	}

	h.mem.SetFaultFunc(func(string) error { return sessions.ErrStoreUnavailable })
	h.revocations.SetFaultFunc(func(string) error { return sessions.ErrStoreUnavailable })

	// The store itself returns unavailable; the fail-open-stale policy is
	// applied by the middleware using DegradedSnapshot, which is what we assert
	// here at the store boundary.
	if _, err := h.store.Load(requestWithCookie(cookie)); !errors.Is(err, sessions.ErrStoreUnavailable) {
		t.Fatalf("expected unavailable from store, got %v", err)
	}
	ticketID, err := h.store.TicketID(requestWithCookie(cookie))
	if err != nil {
		t.Fatalf("ticket id: %v", err)
	}
	snapshot, ok := h.store.DegradedSnapshot(ticketID)
	if !ok || snapshot.User != "john.doe" {
		t.Fatalf("degraded snapshot = %+v ok=%v, want john.doe,true", snapshot, ok)
	}
}

func TestE2ELogoutRevokesAndDeletesOnEveryRead(t *testing.T) {
	h := newE2EStore(t, options.UnavailablePolicyFailClosed)
	cookie, _ := saveSessionAndExtractCookie(t, h.store, h.cookieOpts)

	if _, err := h.store.Load(requestWithCookie(cookie)); err != nil {
		t.Fatalf("pre-logout load: %v", err)
	}

	if err := h.store.Clear(httptest.NewRecorder(), requestWithCookie(cookie)); err != nil {
		t.Fatalf("logout clear: %v", err)
	}

	// Every subsequent read must be rejected: the session key is deleted and
	// the revocation record is present as a second line of defence.
	for i := 0; i < 5; i++ {
		_, err := h.store.Load(requestWithCookie(cookie))
		if err == nil {
			t.Fatalf("read %d after logout succeeded; session must be dead on every read", i)
		}
		if !errors.Is(err, sessions.ErrSessionRevoked) && !errors.Is(err, sessions.ErrSessionNotFound) {
			t.Fatalf("read %d err = %v, want revoked or not-found", i, err)
		}
	}
}

func TestE2ELogoutDuringOutageIsNotSilentSuccess(t *testing.T) {
	h := newE2EStore(t, options.UnavailablePolicyFailClosed)
	cookie, _ := saveSessionAndExtractCookie(t, h.store, h.cookieOpts)

	// Fault the whole shared backend: revocation record write must also fail.
	h.mem.SetFaultFunc(func(string) error { return sessions.ErrStoreUnavailable })
	h.revocations.SetFaultFunc(func(string) error { return sessions.ErrStoreUnavailable })

	err := h.store.Clear(httptest.NewRecorder(), requestWithCookie(cookie))
	if err == nil {
		t.Fatal("logout during outage must report failure, never silent success")
	}
	if !errors.Is(err, sessions.ErrStoreUnavailable) {
		t.Fatalf("err = %v, want ErrStoreUnavailable", err)
	}

	// Outage clears: the session must still be alive because logout was never
	// confirmed and the cookie was deliberately retained.
	h.mem.SetFaultFunc(nil)
	h.revocations.SetFaultFunc(nil)
	loaded, err := h.store.Load(requestWithCookie(cookie))
	if err != nil {
		t.Fatalf("session after unconfirmed logout: %v", err)
	}
	if loaded.User != "john.doe" {
		t.Fatalf("user = %q, unconfirmed logout must not kill the session", loaded.User)
	}

	// Retrying logout now succeeds and is immediately effective.
	if err := h.store.Clear(httptest.NewRecorder(), requestWithCookie(cookie)); err != nil {
		t.Fatalf("retry logout: %v", err)
	}
	if _, err := h.store.Load(requestWithCookie(cookie)); err == nil {
		t.Fatal("session still loadable after confirmed logout")
	}
}

func TestE2ECorruptSessionIsDestroyed(t *testing.T) {
	h := newE2EStore(t, options.UnavailablePolicyFailClosed)
	cookie, _ := saveSessionAndExtractCookie(t, h.store, h.cookieOpts)

	h.mem.CorruptAll()

	_, err := h.store.Load(requestWithCookie(cookie))
	if !errors.Is(err, sessions.ErrSessionCorrupt) {
		t.Fatalf("err = %v, want ErrSessionCorrupt", err)
	}
	if h.mem.Len() != 0 {
		t.Fatalf("corrupt session not destroyed, %d entries remain", h.mem.Len())
	}
}

func TestE2ENaturalExpiryIsNotRevocation(t *testing.T) {
	h := newE2EStore(t, options.UnavailablePolicyFailClosed)
	cookie, _ := saveSessionAndExtractCookie(t, h.store, h.cookieOpts)

	h.mem.ExpireAll()
	_, err := h.store.Load(requestWithCookie(cookie))
	if !errors.Is(err, sessions.ErrSessionNotFound) {
		t.Fatalf("err = %v, want ErrSessionNotFound (natural expiry)", err)
	}
}

func TestE2ERevokeMethodBlocksSession(t *testing.T) {
	h := newE2EStore(t, options.UnavailablePolicyFailClosed)
	cookie, session := saveSessionAndExtractCookie(t, h.store, h.cookieOpts)

	if err := h.store.Revoke(requestWithCookie(cookie), session, sessions.ReasonAdminRevoke); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	_, err := h.store.Load(requestWithCookie(cookie))
	var revoked *sessions.RevokedError
	if !errors.As(err, &revoked) {
		t.Fatalf("err = %v, want *RevokedError", err)
	}
	if revoked.Reason != sessions.ReasonAdminRevoke {
		t.Fatalf("reason = %q", revoked.Reason)
	}
}

func TestE2ESaveOutagePreservesLogin(t *testing.T) {
	h := newE2EStore(t, options.UnavailablePolicyFailClosed)
	cookie, _ := saveSessionAndExtractCookie(t, h.store, h.cookieOpts)

	h.mem.SetFaultFunc(func(op string) error {
		if op == "save" {
			return sessions.ErrStoreUnavailable
		}
		return nil
	})
	expires := time.Now().Add(time.Hour)
	err := h.store.Save(httptest.NewRecorder(), requestWithCookie(cookie), &sessions.SessionState{
		User: "john.doe-v2", ExpiresOn: &expires,
	})
	if !errors.Is(err, sessions.ErrStoreUnavailable) {
		t.Fatalf("save err = %v", err)
	}

	h.mem.SetFaultFunc(nil)
	loaded, err := h.store.Load(requestWithCookie(cookie))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.User != "john.doe" {
		t.Fatalf("established login was overwritten/destroyed: user=%q", loaded.User)
	}
}

func TestE2EVerifyConnectionDelegates(t *testing.T) {
	h := newE2EStore(t, options.UnavailablePolicyFailClosed)
	if err := h.store.VerifyConnection(context.Background()); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// newUserInfoHarness builds a strict store with upstream user-info change
// propagation enabled and an injectable validator result.
func newUserInfoHarness(t *testing.T, validator func(context.Context, *sessions.SessionState) (bool, error)) (*strict.Store, *options.Cookie) {
	t.Helper()
	cookieOpts := testCookieOpts()
	mem := memorystore.NewRawStore()
	manager := persistence.NewManager(mem, cookieOpts)
	cfg := strict.Config{
		UnavailablePolicy:   options.UnavailablePolicyFailClosed,
		OperationTimeout:    200 * time.Millisecond,
		MaxRetries:          3,
		LogoutMaxRetries:    4,
		RevocationEnabled:   true,
		RevocationTTL:       time.Hour,
		CookieName:          cookieOpts.Name,
		UserInfoStaleMaxAge: time.Nanosecond, // force re-validation on every load
	}
	store := strict.NewStore(manager, cookieOpts, cfg, strict.NewMemoryRevocationStore(), validator)
	return store, cookieOpts
}

func TestE2EUpstreamRejectionRevokesSession(t *testing.T) {
	store, cookieOpts := newUserInfoHarness(t, func(_ context.Context, _ *sessions.SessionState) (bool, error) {
		// Upstream says the identity (e.g. withdrawn permissions) is no longer valid.
		return false, nil
	})
	cookie, _ := saveSessionAndExtractCookie(t, store, cookieOpts)

	_, err := store.Load(requestWithCookie(cookie))
	var revoked *sessions.RevokedError
	if !errors.As(err, &revoked) {
		t.Fatalf("err = %v, want *RevokedError after upstream rejection", err)
	}
	if revoked.Reason != sessions.ReasonUpstreamUserInfoChanged {
		t.Fatalf("reason = %q, want %q", revoked.Reason, sessions.ReasonUpstreamUserInfoChanged)
	}

	// The revocation must stick: every subsequent load is rejected.
	for i := 0; i < 3; i++ {
		if _, err := store.Load(requestWithCookie(cookie)); !errors.Is(err, sessions.ErrSessionRevoked) {
			t.Fatalf("load %d after revocation err = %v, want ErrSessionRevoked", i, err)
		}
	}
}

func TestE2EUpstreamAcceptanceRefreshesSnapshot(t *testing.T) {
	var calls int
	store, cookieOpts := newUserInfoHarness(t, func(_ context.Context, _ *sessions.SessionState) (bool, error) {
		calls++
		return true, nil
	})
	cookie, _ := saveSessionAndExtractCookie(t, store, cookieOpts)

	loaded, err := store.Load(requestWithCookie(cookie))
	if err != nil {
		t.Fatalf("accepted upstream load: %v", err)
	}
	if loaded.UserInfoSnapshotAt == nil || loaded.UserInfoSnapshotAt.IsZero() {
		t.Fatal("expected UserInfoSnapshotAt to be stamped after a successful re-validation")
	}
	if calls != 1 {
		t.Fatalf("validator calls = %d, want 1", calls)
	}
}

func TestE2EUpstreamCheckErrorDegradesNotRevokes(t *testing.T) {
	injected := errors.New("idp unreachable")
	store, cookieOpts := newUserInfoHarness(t, func(_ context.Context, _ *sessions.SessionState) (bool, error) {
		return false, injected
	})
	cookie, _ := saveSessionAndExtractCookie(t, store, cookieOpts)

	_, err := store.Load(requestWithCookie(cookie))
	if !errors.Is(err, sessions.ErrStoreUnavailable) {
		t.Fatalf("err = %v, want ErrStoreUnavailable (inconclusive check must not revoke)", err)
	}
	// No revocation record should exist for an inconclusive check.
	if _, err := store.Load(requestWithCookie(cookie)); !errors.Is(err, sessions.ErrStoreUnavailable) {
		t.Fatalf("second load err = %v, still want unavailable, not revoked", err)
	}
}
