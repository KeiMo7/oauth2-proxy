package strict

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

func TestRetrySucceedsAfterTransientFailures(t *testing.T) {
	var attempts int32
	err := retry(context.Background(), 3, time.Second, func(ctx context.Context) error {
		n := atomic.AddInt32(&attempts, 1)
		if n < 3 {
			return fmt.Errorf("%w: blip", sessions.ErrStoreUnavailable)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("retry returned %v, want nil", err)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
}

func TestRetryDoesNotRetryNotFound(t *testing.T) {
	var attempts int32
	err := retry(context.Background(), 5, time.Second, func(ctx context.Context) error {
		atomic.AddInt32(&attempts, 1)
		return sessions.ErrSessionNotFound
	})
	if !errors.Is(err, sessions.ErrSessionNotFound) {
		t.Fatalf("err = %v, want ErrSessionNotFound", err)
	}
	if attempts != 1 {
		t.Fatalf("not-found was retried %d times, want exactly 1", attempts)
	}
}

func TestRetryExhaustsOnPersistentUnavailable(t *testing.T) {
	var attempts int32
	err := retry(context.Background(), 3, time.Second, func(ctx context.Context) error {
		atomic.AddInt32(&attempts, 1)
		return sessions.ErrStoreUnavailable
	})
	if !errors.Is(err, sessions.ErrStoreUnavailable) {
		t.Fatalf("err = %v, want ErrStoreUnavailable", err)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
}

func TestRetryRespectsAttemptTimeout(t *testing.T) {
	err := retry(context.Background(), 1, 20*time.Millisecond, func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestRetryStopsOnParentCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := retry(ctx, 5, time.Second, func(ctx context.Context) error {
		return sessions.ErrStoreUnavailable
	})
	if err == nil {
		t.Fatal("expected error after parent cancellation")
	}
}
