package middleware

import "context"

// degradedContextKey is the private context key marking a request whose
// session is a last-known-good snapshot because the backing store is
// temporarily unavailable (fail-open-stale policy).
type degradedContextKey struct{}

// withDegraded marks ctx as carrying a degraded session snapshot.
func withDegraded(ctx context.Context) context.Context {
	return context.WithValue(ctx, degradedContextKey{}, true)
}

// isDegraded reports whether ctx carries a degraded session.
func isDegraded(ctx context.Context) bool {
	v, _ := ctx.Value(degradedContextKey{}).(bool)
	return v
}
