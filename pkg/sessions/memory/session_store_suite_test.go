package memory_test

import (
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	memorystore "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/memory"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/tests"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestMemorySessionStore(t *testing.T) {
	logger.SetOutput(GinkgoWriter)
	logger.SetErrOutput(GinkgoWriter)
	RegisterFailHandler(Fail)
	RunSpecs(t, "Memory Session Store Suite")
}

var _ = Describe("Memory Session Store", func() {
	// The conformance suite builds a fresh store per spec via newSS; keep the
	// raw handle here so the fast-forward hook advances the same instance.
	var raw *memorystore.SessionStore

	tests.RunSessionStoreTests(
		func(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessionsapi.SessionStore, error) {
			opts.Type = options.MemorySessionStoreType
			ss, r, err := memorystore.NewSessionStoreRaw(opts, cookieOpts)
			raw = r
			return ss, err
		},
		func(d time.Duration) error {
			raw.AdvanceClock(d)
			return nil
		},
	)
})
