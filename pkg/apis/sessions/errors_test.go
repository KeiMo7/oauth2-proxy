package sessions

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorKind
	}{
		{"nil", nil, ""},
		{"no cookie", http.ErrNoCookie, KindUnauthenticated},
		{"wrapped no cookie", fmt.Errorf("load: %w", http.ErrNoCookie), KindUnauthenticated},
		{"not found", ErrSessionNotFound, KindNotFound},
		{"wrapped not found", fmt.Errorf("%w: x", ErrSessionNotFound), KindNotFound},
		{"corrupt", ErrSessionCorrupt, KindCorrupt},
		{"unavailable", ErrStoreUnavailable, KindUnavailable},
		{"wrapped unavailable", fmt.Errorf("redis: %w: boom", ErrStoreUnavailable), KindUnavailable},
		{"revoked sentinel", ErrSessionRevoked, KindRevoked},
		{"revoked error struct", &RevokedError{Reason: ReasonUserLogout, At: time.Now()}, KindRevoked},
		{"unknown", errors.New("something else"), KindUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClassifyError(tt.err); got != tt.want {
				t.Fatalf("ClassifyError(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

func TestRevokedErrorWrapsSentinel(t *testing.T) {
	err := &RevokedError{Reason: ReasonAdminRevoke, At: time.Unix(0, 0).UTC()}
	if !errors.Is(err, ErrSessionRevoked) {
		t.Fatal("RevokedError must satisfy errors.Is(..., ErrSessionRevoked)")
	}
	if got := err.Error(); got == "" {
		t.Fatal("expected non-empty error string")
	}
}

func TestRevocationReasonsAreDistinct(t *testing.T) {
	seen := map[RevocationReason]bool{}
	for _, r := range []RevocationReason{
		ReasonUserLogout,
		ReasonAdminRevoke,
		ReasonUpstreamUserInfoChanged,
		ReasonRefreshTokenRevoked,
		ReasonCorruptDestroyed,
	} {
		if seen[r] {
			t.Fatalf("duplicate reason %q", r)
		}
		seen[r] = true
	}
}
