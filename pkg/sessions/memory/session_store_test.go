package memory

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

func TestSaveLoadClearRoundTrip(t *testing.T) {
	s := &SessionStore{data: map[string]entry{}, nowFunc: time.Now}
	ctx := context.Background()

	if err := s.Save(ctx, "k1", []byte("blob"), time.Minute); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := s.Load(ctx, "k1")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if string(got) != "blob" {
		t.Fatalf("load = %q, want blob", got)
	}

	if err := s.Clear(ctx, "k1"); err != nil {
		t.Fatalf("clear: %v", err)
	}
	_, err = s.Load(ctx, "k1")
	if !errors.Is(err, sessions.ErrSessionNotFound) {
		t.Fatalf("post-clear load err = %v, want ErrSessionNotFound", err)
	}
}

func TestLoadMissingIsNotFoundNotUnavailable(t *testing.T) {
	s := &SessionStore{data: map[string]entry{}, nowFunc: time.Now}
	_, err := s.Load(context.Background(), "missing")
	if !errors.Is(err, sessions.ErrSessionNotFound) {
		t.Fatalf("err = %v, want ErrSessionNotFound", err)
	}
}

func TestExpiredEntryLazilyDeleted(t *testing.T) {
	now := time.Now()
	s := &SessionStore{
		data:    map[string]entry{"k": {data: []byte("x"), expires: now.Add(-time.Second)}},
		nowFunc: func() time.Time { return now },
	}
	_, err := s.Load(context.Background(), "k")
	if !errors.Is(err, sessions.ErrSessionNotFound) {
		t.Fatalf("err = %v, want ErrSessionNotFound", err)
	}
	if _, ok := s.data["k"]; ok {
		t.Fatal("expired entry should have been lazily deleted")
	}
}

func TestSaveFailurePreservesExistingEntry(t *testing.T) {
	s := &SessionStore{data: map[string]entry{}, nowFunc: time.Now}
	ctx := context.Background()
	if err := s.Save(ctx, "k", []byte("original"), time.Minute); err != nil {
		t.Fatal(err)
	}

	injected := errors.New("simulated outage")
	s.SetFaultFunc(func(string) error { return injected })

	if err := s.Save(ctx, "k", []byte("new"), time.Minute); !errors.Is(err, injected) {
		t.Fatalf("failing save err = %v, want injected", err)
	}

	s.SetFaultFunc(nil)
	got, err := s.Load(ctx, "k")
	if err != nil {
		t.Fatalf("load after failed save: %v", err)
	}
	if string(got) != "original" {
		t.Fatalf("existing session was destroyed: got %q, want original", got)
	}
}

func TestLoadFaultClassifiedAsInjectedError(t *testing.T) {
	s := &SessionStore{data: map[string]entry{}, nowFunc: time.Now}
	injected := sessions.ErrStoreUnavailable
	s.SetFaultFunc(func(string) error { return injected })
	if _, err := s.Load(context.Background(), "k"); !errors.Is(err, sessions.ErrStoreUnavailable) {
		t.Fatalf("err = %v, want ErrStoreUnavailable", err)
	}
}

func TestConcurrentAccess(t *testing.T) {
	s := &SessionStore{data: map[string]entry{}, nowFunc: time.Now}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx := context.Background()
			key := "k"
			_ = s.Save(ctx, key, []byte("v"), time.Minute)
			_, _ = s.Load(ctx, key)
		}(i)
	}
	wg.Wait()
}

func TestMemoryLockLifecycle(t *testing.T) {
	s := &SessionStore{data: map[string]entry{}, nowFunc: time.Now}
	lock := s.Lock("k")
	ctx := context.Background()

	if err := lock.Obtain(ctx, time.Second); err != nil {
		t.Fatalf("first obtain: %v", err)
	}
	if err := lock.Obtain(ctx, time.Second); !errors.Is(err, sessions.ErrLockNotObtained) {
		t.Fatalf("second obtain err = %v, want ErrLockNotObtained", err)
	}
	held, err := lock.Peek(ctx)
	if err != nil || !held {
		t.Fatalf("peek = %v,%v want true,nil", held, err)
	}
	if err := lock.Release(ctx); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := lock.Release(ctx); !errors.Is(err, sessions.ErrNotLocked) {
		t.Fatalf("double release err = %v, want ErrNotLocked", err)
	}
}
