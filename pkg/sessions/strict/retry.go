package strict

import (
	"context"
	"errors"
	"math/rand"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

// retry executes op with per-attempt timeouts and exponential backoff with
// jitter. Only ErrStoreUnavailable is retried; every other error (not found,
// corrupt, revoked) is returned immediately because retrying cannot change the
// outcome.
//
// attemptTimeout bounds a single op; the parent ctx bounds the whole retry
// sequence. The returned error is always the last op error (already classified
// by the backend) wrapped with ErrStoreUnavailable when retries are exhausted.
func retry(ctx context.Context, attempts int, attemptTimeout time.Duration, op func(context.Context) error) error {
	var lastErr error
	backoff := 50 * time.Millisecond

	for i := 0; i < attempts; i++ {
		attemptCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
		err := op(attemptCtx)
		cancel()

		if err == nil {
			return nil
		}
		lastErr = err

		// Non-retryable conditions: surface immediately.
		if !errors.Is(err, sessions.ErrStoreUnavailable) {
			return err
		}

		if i == attempts-1 {
			break
		}

		// Full jitter: sleep in [0, backoff) so a fleet-wide blip does not
		// produce a thundering retry herd.
		wait := time.Duration(rand.Int63n(int64(backoff)))
		select {
		case <-ctx.Done():
			return lastErr
		case <-time.After(wait):
		}
		if backoff < time.Second {
			backoff *= 2
		}
	}
	return lastErr
}
