package persistence

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

// Manager wraps a Store and handles the implementation details of the
// sessions.SessionStore with its use of session tickets
type Manager struct {
	Store   Store
	Options *options.Cookie
}

// NewManager creates a Manager that can wrap a Store and manage the
// sessions.SessionStore implementation details
func NewManager(store Store, cookieOpts *options.Cookie) *Manager {
	return &Manager{
		Store:   store,
		Options: cookieOpts,
	}
}

// Save saves a session in a persistent Store. Save will generate (or reuse an
// existing) ticket which manages unique per session encryption & retrieval
// from the persistent data store.
func (m *Manager) Save(rw http.ResponseWriter, req *http.Request, s *sessions.SessionState) error {
	if s.CreatedAt == nil || s.CreatedAt.IsZero() {
		s.CreatedAtNow()
	}

	tckt, err := decodeTicketFromRequest(req, m.Options)
	if err != nil {
		tckt, err = newTicket(m.Options)
		if err != nil {
			return fmt.Errorf("error creating a session ticket: %v", err)
		}
	}

	err = tckt.saveSession(s, func(key string, val []byte, exp time.Duration) error {
		return m.Store.Save(req.Context(), key, val, exp)
	})
	if err != nil {
		return err
	}

	return tckt.setCookie(rw, req, s)
}

// Load reads sessions.SessionState information from a session store. It will
// use the session ticket from the http.Request's cookie.
func (m *Manager) Load(req *http.Request) (*sessions.SessionState, error) {
	tckt, err := decodeTicketFromRequest(req, m.Options)
	if err != nil {
		return nil, err
	}

	return tckt.loadSession(
		func(key string) ([]byte, error) {
			return m.Store.Load(req.Context(), key)
		},
		m.Store.Lock,
	)
}

// Clear clears any saved session information for a given ticket cookie.
// Then it clears all session data for that ticket in the Store.
func (m *Manager) Clear(rw http.ResponseWriter, req *http.Request) error {
	tckt, err := decodeTicketFromRequest(req, m.Options)
	if err != nil {
		// Always clear the cookie, even when we can't load a cookie from
		// the request
		tckt = &ticket{
			options: m.Options,
		}
		tckt.clearCookie(rw, req)
		// Don't raise an error if we didn't have a Cookie
		if err == http.ErrNoCookie {
			return nil
		}
		return fmt.Errorf("error decoding ticket to clear session: %v", err)
	}

	tckt.clearCookie(rw, req)
	return tckt.clearSession(func(key string) error {
		return m.Store.Clear(req.Context(), key)
	})
}

// ClearStoreBeforeCookie is the reliable-logout variant of Clear: it deletes
// the session from the shared Store FIRST and only removes the cookie once the
// deletion succeeds. If the Store operation fails (e.g. during a Redis
// primary/replica failover) the cookie is deliberately kept so the caller can
// retry the logout instead of reporting a success while the session still
// exists. When no ticket cookie is present the cookie is cleared and nil is
// returned, matching Clear's no-cookie behaviour.
func (m *Manager) ClearStoreBeforeCookie(rw http.ResponseWriter, req *http.Request) error {
	tckt, err := decodeTicketFromRequest(req, m.Options)
	if err != nil {
		if err == http.ErrNoCookie {
			// Nothing to delete server-side; just make sure the cookie is gone.
			(&ticket{options: m.Options}).clearCookie(rw, req)
			return nil
		}
		// Do not clear the cookie on a decode error here: the strict wrapper
		// treats this as corruption and owns the audit/destroy decision.
		return fmt.Errorf("error decoding ticket to clear session: %v", err)
	}

	if err := tckt.clearSession(func(key string) error {
		return m.Store.Clear(req.Context(), key)
	}); err != nil {
		// Keep the cookie: a retry still carries the ticket.
		return err
	}
	tckt.clearCookie(rw, req)
	return nil
}

// VerifyConnection validates the underlying store is ready and connected
func (m *Manager) VerifyConnection(ctx context.Context) error {
	return m.Store.VerifyConnection(ctx)
}
