package strict

import (
	"context"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

func TestMemoryRevocationMarkAndCheck(t *testing.T) {
	store := NewMemoryRevocationStore()
	ctx := context.Background()

	if _, revoked, err := store.IsRevoked(ctx, "t1"); err != nil || revoked {
		t.Fatalf("fresh ticket: revoked=%v err=%v, want false,nil", revoked, err)
	}

	if err := store.MarkRevoked(ctx, "t1", RevocationRecord{Reason: sessions.ReasonUserLogout}, time.Minute); err != nil {
		t.Fatalf("mark: %v", err)
	}
	record, revoked, err := store.IsRevoked(ctx, "t1")
	if err != nil || !revoked {
		t.Fatalf("post-mark: revoked=%v err=%v, want true,nil", revoked, err)
	}
	if record.Reason != sessions.ReasonUserLogout {
		t.Fatalf("reason = %q, want %q", record.Reason, sessions.ReasonUserLogout)
	}
	if record.At.IsZero() {
		t.Fatal("expected At to be populated automatically")
	}
}

func TestMemoryRevocationIdempotentKeepsFirstReason(t *testing.T) {
	store := NewMemoryRevocationStore()
	ctx := context.Background()

	_ = store.MarkRevoked(ctx, "t", RevocationRecord{Reason: sessions.ReasonUserLogout}, time.Minute)
	_ = store.MarkRevoked(ctx, "t", RevocationRecord{Reason: sessions.ReasonAdminRevoke}, time.Minute)

	record, revoked, err := store.IsRevoked(ctx, "t")
	if err != nil || !revoked {
		t.Fatalf("revoked=%v err=%v", revoked, err)
	}
	if record.Reason != sessions.ReasonUserLogout {
		t.Fatalf("reason changed to %q, first reason must be retained", record.Reason)
	}
}

func TestMemoryRevocationTTLExpiry(t *testing.T) {
	now := time.Unix(1000, 0)
	store := NewMemoryRevocationStore()
	store.now = func() time.Time { return now }
	ctx := context.Background()

	_ = store.MarkRevoked(ctx, "t", RevocationRecord{Reason: sessions.ReasonAdminRevoke}, time.Minute)

	store.now = func() time.Time { return now.Add(61 * time.Second) }
	if _, revoked, err := store.IsRevoked(ctx, "t"); err != nil || revoked {
		t.Fatalf("after TTL: revoked=%v err=%v, want false,nil", revoked, err)
	}
}

func TestSnapshotCachePutGetExpireDelete(t *testing.T) {
	now := time.Unix(2000, 0)
	cache := newSnapshotCache(time.Minute)

	sess := &sessions.SessionState{User: "alice"}
	cache.put("t1", sess, now)

	got, ok := cache.get("t1", now.Add(30*time.Second))
	if !ok || got.User != "alice" {
		t.Fatalf("get = %+v, %v; want alice,true", got, ok)
	}
	if got.Lock != nil {
		t.Fatal("snapshot must not carry a Lock")
	}

	if _, ok := cache.get("t1", now.Add(61*time.Second)); ok {
		t.Fatal("expired snapshot must not be served")
	}

	cache.put("t2", sess, now)
	cache.delete("t2")
	if _, ok := cache.get("t2", now); ok {
		t.Fatal("deleted snapshot still served")
	}
}

func TestSnapshotCacheDisabledByZeroTTL(t *testing.T) {
	cache := newSnapshotCache(0)
	cache.put("t", &sessions.SessionState{User: "a"}, time.Now())
	if _, ok := cache.get("t", time.Now()); ok {
		t.Fatal("cache with zero TTL must always miss")
	}
}
