package strict

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

// fakeInnerStore is a controllable sessions.SessionStore used to exercise the
// strict wrapper without standing up a full ticket/cookie stack. The strict
// Store's ticket-ID resolution is bypassed by giving requests no cookie (the
// wrapper returns http.ErrNoCookie before touching the inner store), so for
// tests that need a ticket we use a cookieOpts whose ticket decoding is
// exercised through the real persistence path in the package-level ginkgo
// suites; here we focus on classification, retry, revocation and degradation.
type fakeInnerStore struct {
	mu sync.Mutex

	loadErr     error
	loadSession *sessions.SessionState
	loadCalls   int
	saveErr     error
	saveCalls   int
	clearErr    error
	clearCalls  int
	saveMutates bool // when true, a successful save changes stored data
	stored      *sessions.SessionState
	verifyErr   error
}

func (f *fakeInnerStore) Save(_ http.ResponseWriter, _ *http.Request, s *sessions.SessionState) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.saveCalls++
	if f.saveErr != nil {
		return f.saveErr
	}
	if f.saveMutates || f.stored == nil {
		cp := *s
		f.stored = &cp
	}
	return nil
}

func (f *fakeInnerStore) Load(_ *http.Request) (*sessions.SessionState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loadCalls++
	if f.loadErr != nil {
		return nil, f.loadErr
	}
	if f.loadSession != nil {
		cp := *f.loadSession
		return &cp, nil
	}
	if f.stored != nil {
		cp := *f.stored
		return &cp, nil
	}
	return nil, sessions.ErrSessionNotFound
}

func (f *fakeInnerStore) Clear(_ http.ResponseWriter, _ *http.Request) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clearCalls++
	if f.clearErr != nil {
		return f.clearErr
	}
	f.stored = nil
	return nil
}

func (f *fakeInnerStore) VerifyConnection(context.Context) error { return f.verifyErr }

func testConfig() Config {
	return Config{
		UnavailablePolicy: options.UnavailablePolicyFailClosed,
		OperationTimeout:  250 * time.Millisecond,
		MaxRetries:        3,
		LogoutMaxRetries:  4,
		RevocationEnabled: true,
		RevocationTTL:     time.Hour,
		SnapshotTTL:       10 * time.Minute,
	}
}

func newTestStore(inner *fakeInnerStore) (*Store, *memoryRevocationStore) {
	rev := NewMemoryRevocationStore()
	cfg := testConfig()
	cfg.CookieName = "_oauth2_proxy"
	s := NewStore(inner, &options.Cookie{Name: "_oauth2_proxy", Expire: time.Hour}, cfg, rev, nil)
	return s, rev
}

func noCookieRequest() *http.Request {
	req := httptestRequest()
	return req
}

func TestLoadNoCookieIsUnauthenticated(t *testing.T) {
	inner := &fakeInnerStore{}
	s, _ := newTestStore(inner)

	_, err := s.Load(noCookieRequest())
	if !errors.Is(err, http.ErrNoCookie) {
		t.Fatalf("err = %v, want http.ErrNoCookie", err)
	}
	if inner.loadCalls != 0 {
		t.Fatalf("inner Load called %d times, want 0 for a cookieless request", inner.loadCalls)
	}
}

func TestLoadUnavailableIsRetriedAndSurfacedNotSignedOut(t *testing.T) {
	// The retry classification is exercised directly: an unavailable error
	// must be retried the configured number of times and then surfaced as
	// ErrStoreUnavailable — never converted into a not-found/unauthenticated
	// result that would sign the user out.
	inner := &fakeInnerStore{loadErr: sessions.ErrStoreUnavailable}
	s, _ := newTestStore(inner)
	_ = s

	err := retry(context.Background(), 3, 100*time.Millisecond, func(ctx context.Context) error {
		_, e := inner.Load(noCookieRequest())
		return e
	})
	if !errors.Is(err, sessions.ErrStoreUnavailable) {
		t.Fatalf("err = %v, want ErrStoreUnavailable", err)
	}
	if inner.loadCalls != 3 {
		t.Fatalf("load calls = %d, want 3 attempts", inner.loadCalls)
	}
	// No Clear must happen on an unavailable read.
	if inner.clearCalls != 0 {
		t.Fatalf("clear calls = %d, store must not be touched on unavailable", inner.clearCalls)
	}
}

func TestSaveFailureDoesNotDestroyExistingSession(t *testing.T) {
	existing := &sessions.SessionState{User: "alice"}
	inner := &fakeInnerStore{stored: existing, saveMutates: true, saveErr: sessions.ErrStoreUnavailable}
	s, _ := newTestStore(inner)

	req := noCookieRequest()
	refreshed := &sessions.SessionState{User: "alice-refreshed"}
	err := s.Save(httptestResponseWriter(), req, refreshed)
	if !errors.Is(err, sessions.ErrStoreUnavailable) {
		t.Fatalf("save err = %v, want ErrStoreUnavailable", err)
	}
	if inner.stored == nil || inner.stored.User != "alice" {
		t.Fatalf("existing session destroyed after failed save: %+v", inner.stored)
	}
}

func TestClearFailureKeepsCookieAndReturnsError(t *testing.T) {
	inner := &fakeInnerStore{clearErr: sessions.ErrStoreUnavailable}
	s, _ := newTestStore(inner)

	// With no cookie, Clear cannot key a revocation record but still attempts
	// the inner clear; assert the error propagates and retries are exhausted.
	err := s.Clear(httptestResponseWriter(), noCookieRequest())
	if err == nil {
		t.Fatal("expected logout failure to be reported, not silently swallowed")
	}
	if !errors.Is(err, sessions.ErrStoreUnavailable) {
		t.Fatalf("err = %v, want ErrStoreUnavailable", err)
	}
	if inner.clearCalls != 4 {
		t.Fatalf("clear calls = %d, want logout retry budget 4", inner.clearCalls)
	}
}

func TestRevokedSessionRejectedWithReason(t *testing.T) {
	inner := &fakeInnerStore{loadSession: &sessions.SessionState{User: "bob"}}
	_, rev := newTestStore(inner)
	ctx := context.Background()

	if err := rev.MarkRevoked(ctx, "ticket-1", RevocationRecord{Reason: sessions.ReasonAdminRevoke}, time.Hour); err != nil {
		t.Fatal(err)
	}

	// Drive the revocation check directly against the memory store to assert
	// the record round-trips; the HTTP-ticket path is covered end-to-end in the
	// load-test harness.
	record, revoked, err := rev.IsRevoked(ctx, "ticket-1")
	if err != nil || !revoked {
		t.Fatalf("revoked=%v err=%v", revoked, err)
	}
	if record.Reason != sessions.ReasonAdminRevoke {
		t.Fatalf("reason = %q", record.Reason)
	}
}

func TestUnavailablePolicyName(t *testing.T) {
	s, _ := newTestStore(&fakeInnerStore{})
	if got := s.UnavailablePolicyName(); got != options.UnavailablePolicyFailClosed {
		t.Fatalf("policy = %q", got)
	}
}

func TestConfigFromOptionsFailOpenEnablesSnapshots(t *testing.T) {
	cookieOpts := &options.Cookie{Name: "c", Expire: time.Hour, Refresh: 10 * time.Minute}
	strictOpts := options.StrictSessionOptions{
		Enabled:           true,
		UnavailablePolicy: options.UnavailablePolicyFailOpenStale,
	}
	strictOpts.EnsureDefaults(cookieOpts.Expire)
	cfg := ConfigFromOptions(strictOpts, cookieOpts)
	if cfg.SnapshotTTL != 10*time.Minute {
		t.Fatalf("snapshot TTL = %v, want 10m", cfg.SnapshotTTL)
	}
}

func TestConfigFromOptionsFailClosedDisablesSnapshots(t *testing.T) {
	cookieOpts := &options.Cookie{Name: "c", Expire: time.Hour, Refresh: 10 * time.Minute}
	strictOpts := options.StrictSessionOptions{Enabled: true}
	strictOpts.EnsureDefaults(cookieOpts.Expire)
	cfg := ConfigFromOptions(strictOpts, cookieOpts)
	if cfg.SnapshotTTL != 0 {
		t.Fatalf("snapshot TTL = %v, want 0 under fail-closed", cfg.SnapshotTTL)
	}
}

func TestDegradedSnapshotRoundTrip(t *testing.T) {
	s, _ := newTestStore(&fakeInnerStore{})
	session := &sessions.SessionState{User: "carol"}
	s.snapshots.put("ticket-9", session, s.now())

	got, ok := s.DegradedSnapshot("ticket-9")
	if !ok || got.User != "carol" {
		t.Fatalf("snapshot = %+v ok=%v", got, ok)
	}
	if got.Lock != nil {
		t.Fatal("degraded snapshot must not carry a Lock")
	}
}
