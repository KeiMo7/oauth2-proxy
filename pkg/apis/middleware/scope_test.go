package middleware_test

import (
	"net/http"

	ipapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/ip"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/ip"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Scope Suite", func() {
	Context("GetRequestScope", func() {
		var request *http.Request

		BeforeEach(func() {
			var err error
			request, err = http.NewRequest("", "http://127.0.0.1/", nil)
			Expect(err).ToNot(HaveOccurred())
		})

		Context("with a scope", func() {
			var scope *middleware.RequestScope

			BeforeEach(func() {
				scope = &middleware.RequestScope{}
				request = middleware.AddRequestScope(request, scope)
			})

			It("returns the scope", func() {
				s := middleware.GetRequestScope(request)
				Expect(s).ToNot(BeNil())
				Expect(s).To(Equal(scope))
			})

			Context("if the scope is then modified", func() {
				BeforeEach(func() {
					Expect(scope.SaveSession).To(BeFalse())
					scope.SaveSession = true
				})

				It("returns the updated session", func() {
					s := middleware.GetRequestScope(request)
					Expect(s).ToNot(BeNil())
					Expect(s).To(Equal(scope))
					Expect(s.SaveSession).To(BeTrue())
				})
			})
		})

		Context("without a scope", func() {
			It("returns nil", func() {
				Expect(middleware.GetRequestScope(request)).To(BeNil())
			})
		})
	})

	Context("ResolveRealClientIP", func() {
		var request *http.Request
		var trustedProxies *ip.NetSet
		var parser ipapi.RealClientIPParser

		BeforeEach(func() {
			var err error
			request, err = http.NewRequest(http.MethodGet, "http://127.0.0.1/", nil)
			Expect(err).ToNot(HaveOccurred())

			trustedProxies, err = ip.ParseNetSet([]string{"192.0.2.0/24"})
			Expect(err).ToNot(HaveOccurred())
			parser, err = ip.GetRealClientIPParser("Forwarded")
			Expect(err).ToNot(HaveOccurred())
		})

		It("uses the standardized header from a trusted proxy", func() {
			request.RemoteAddr = "192.0.2.10:4180"
			request.Header.Add("Forwarded", "for=198.51.100.23, for=192.0.2.20")
			scope := &middleware.RequestScope{ReverseProxy: true, TrustedProxies: trustedProxies}

			clientIP, err := scope.ResolveRealClientIP(parser, request)
			Expect(err).ToNot(HaveOccurred())
			Expect(clientIP.String()).To(Equal("198.51.100.23"))
		})

		It("uses the transport address for an untrusted peer and ignores headers", func() {
			request.RemoteAddr = "198.51.100.5:4180"
			request.Header.Add("Forwarded", "for=10.0.0.5")
			scope := &middleware.RequestScope{ReverseProxy: true, TrustedProxies: trustedProxies}

			clientIP, err := scope.ResolveRealClientIP(parser, request)
			Expect(err).ToNot(HaveOccurred())
			Expect(clientIP.String()).To(Equal("198.51.100.5"))
		})

		It("uses the transport address when reverse-proxy mode is disabled", func() {
			request.RemoteAddr = "192.0.2.10:4180"
			request.Header.Add("Forwarded", "for=10.0.0.5")
			scope := &middleware.RequestScope{TrustedProxies: trustedProxies}

			clientIP, err := scope.ResolveRealClientIP(parser, request)
			Expect(err).ToNot(HaveOccurred())
			Expect(clientIP.String()).To(Equal("192.0.2.10"))
		})

		It("formats auth logs and callback diagnostics identically", func() {
			request.RemoteAddr = "192.0.2.10:4180"
			request.Header.Add("Forwarded", "for=198.51.100.23, for=192.0.2.20")
			request = middleware.AddRequestScope(request, &middleware.RequestScope{
				ReverseProxy:   true,
				TrustedProxies: trustedProxies,
			})

			Expect(middleware.ClientString(request, parser, false)).To(Equal("198.51.100.23"))
			Expect(middleware.ClientString(request, parser, true)).To(Equal("192.0.2.10 (198.51.100.23)"))
		})

		It("degrades to the transport address when the standardized header is malformed", func() {
			request.RemoteAddr = "192.0.2.10:4180"
			request.Header.Add("Forwarded", `for="198.51.100.23`)
			request = middleware.AddRequestScope(request, &middleware.RequestScope{
				ReverseProxy:   true,
				TrustedProxies: trustedProxies,
			})

			Expect(middleware.ClientString(request, parser, false)).To(Equal("192.0.2.10"))
			Expect(middleware.ClientString(request, parser, true)).To(Equal("192.0.2.10"))
		})
	})

	Context("CanTrustForwardedHeaders", func() {
		var request *http.Request
		var scope *middleware.RequestScope

		BeforeEach(func() {
			var err error
			request, err = http.NewRequest("", "http://127.0.0.1/", nil)
			Expect(err).ToNot(HaveOccurred())

			trustedProxies, err := ip.ParseNetSet([]string{"127.0.0.1"})
			Expect(err).ToNot(HaveOccurred())
			scope = &middleware.RequestScope{
				ReverseProxy:   true,
				TrustedProxies: trustedProxies,
			}
		})

		It("returns true for a trusted remote address", func() {
			request.RemoteAddr = "127.0.0.1:4180"
			Expect(scope.CanTrustForwardedHeaders(request)).To(BeTrue())
		})

		It("returns false for an untrusted remote address", func() {
			request.RemoteAddr = "192.0.2.10:4180"
			Expect(scope.CanTrustForwardedHeaders(request)).To(BeFalse())
		})

		It("returns true for unix socket callers", func() {
			request.RemoteAddr = "@"
			Expect(scope.CanTrustForwardedHeaders(request)).To(BeTrue())
		})
	})
})
