package ip

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	ipapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/ip"
)

const (
	xForwardedForHeader = "X-Forwarded-For"
	forwardedHeader     = "Forwarded"
)

var (
	// ErrMalformedForwardedHeader is returned when the standardized Forwarded
	// header does not conform to its grammar (unterminated quotes, missing
	// separators or values, duplicate or unparsable source addresses).
	ErrMalformedForwardedHeader = errors.New("malformed Forwarded header")

	// ErrNoTrustworthyClientIP is returned when a forwarding chain contains no
	// element that may be treated as the client address. This is the case for
	// obfuscated node identifiers and for hops without a source address.
	ErrNoTrustworthyClientIP = errors.New("Forwarded header contains no trustworthy client address")
)

func GetRealClientIPParser(headerKey string) (ipapi.RealClientIPParser, error) {
	headerKey = http.CanonicalHeaderKey(headerKey)

	switch headerKey {
	case http.CanonicalHeaderKey(xForwardedForHeader),
		http.CanonicalHeaderKey("X-Real-IP"),
		http.CanonicalHeaderKey("X-ProxyUser-IP"),
		http.CanonicalHeaderKey("X-Envoy-External-Address"),
		// Cloudflare specific Real-IP header
		http.CanonicalHeaderKey("CF-Connecting-IP"):
		return &xForwardedForClientIPParser{header: headerKey}, nil
	case http.CanonicalHeaderKey(forwardedHeader):
		return &forwardedClientIPParser{header: headerKey}, nil
	}

	return nil, fmt.Errorf("the http header key (%s) is either invalid or unsupported", headerKey)
}

type xForwardedForClientIPParser struct {
	header string
}

// GetRealClientIP obtain the IP address of the end-user (not proxy).
// Parses headers sharing the format as specified by:
// * https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For.
// Returns the `<client>` portion specified in the above document.
// Additionally, is capable of parsing IPs with the port included, for v4 in the format "<ip>:<port>" and for v6 in the
// format "[<ip>]:<port>".  With-port and without-port formats are seamlessly supported concurrently.
func (p xForwardedForClientIPParser) GetRealClientIP(h http.Header) (net.IP, error) {
	var ipStr string
	if realIP := h.Get(p.header); realIP != "" {
		ipStr = realIP
	} else {
		return nil, nil
	}

	// Each successive proxy may append itself, comma separated, to the end of the X-Forwarded-for header.
	// Select only the first IP listed, as it is the client IP recorded by the first proxy.
	if commaIndex := strings.IndexRune(ipStr, ','); commaIndex != -1 {
		ipStr = ipStr[:commaIndex]
	}

	return parseClientIP(ipStr, p.header)
}

// GetClientIPFromTrustedProxy obtains the client IP from a header supplied by
// a caller that has already been verified as a trusted proxy.
//
// The standardized Forwarded header and the traditional X-Forwarded-For header
// share one right-to-left trust walk. When Forwarded is the configured header
// and it is absent or contains no trustworthy node, the traditional header is
// tried under the same trust premise before the caller falls back to the
// transport address. The two headers are never merged into a single chain.
func GetClientIPFromTrustedProxy(p ipapi.RealClientIPParser, req *http.Request, trustedProxies *NetSet) (net.IP, error) {
	if p == nil {
		return nil, fmt.Errorf("real client IP parser is required")
	}

	switch parser := p.(type) {
	case *forwardedClientIPParser:
		if trustedProxies == nil {
			return nil, fmt.Errorf("trusted proxy list is required to parse Forwarded")
		}
		return getForwardedClientIP(req, trustedProxies)
	case *xForwardedForClientIPParser:
		if parser.header != http.CanonicalHeaderKey(xForwardedForHeader) {
			return p.GetRealClientIP(req.Header)
		}
		if trustedProxies == nil {
			return nil, fmt.Errorf("trusted proxy list is required to parse X-Forwarded-For")
		}
		return getXForwardedForClientIP(req, parser.header, trustedProxies)
	default:
		return p.GetRealClientIP(req.Header)
	}
}

// getXForwardedForClientIP walks a traditional X-Forwarded-For chain from right
// to left, combining repeated fields in their received order and skipping
// addresses covered by the trust mask. The first untrusted address is the
// client; entries to its left are never consulted. If the whole chain is
// trusted, the leftmost entry is retained for compatibility.
func getXForwardedForClientIP(req *http.Request, header string, trustedProxies *NetSet) (net.IP, error) {
	xff := strings.Join(req.Header.Values(header), ",")
	if xff == "" {
		return nil, nil
	}

	chain := strings.Split(xff, ",")
	for i := len(chain) - 1; i >= 0; i-- {
		clientIP, err := parseClientIP(chain[i], header)
		if err != nil {
			return nil, err
		}

		if i == 0 || !trustedProxies.Has(clientIP) {
			return clientIP, nil
		}
	}

	return nil, nil
}

func parseClientIP(ipStr string, header string) (net.IP, error) {
	ipStr = strings.TrimSpace(ipStr)
	if ipHost, _, err := net.SplitHostPort(ipStr); err == nil {
		ipStr = ipHost
	}

	clientIP := net.ParseIP(ipStr)
	if clientIP == nil {
		return nil, fmt.Errorf("unable to parse ip (%s) from %s header", ipStr, http.CanonicalHeaderKey(header))
	}

	return clientIP, nil
}

// GetClientIP obtains the perceived end-user IP address from headers if p != nil else from req.RemoteAddr.
func GetClientIP(p ipapi.RealClientIPParser, req *http.Request) (net.IP, error) {
	if p != nil {
		return p.GetRealClientIP(req.Header)
	}
	return getRemoteIP(req)
}

// getRemoteIP obtains the IP of the low-level connected network host
func getRemoteIP(req *http.Request) (net.IP, error) {
	// Unix domain sockets set RemoteAddr to "@" which has no meaningful IP.
	// https://github.com/golang/go/blob/0fa53e41f122b1661d0678a6d36d71b7b5ad031d/src/syscall/syscall_linux.go#L506-L511
	if req.RemoteAddr == "@" {
		return nil, nil
	}

	//revive:disable:indent-error-flow
	if ipStr, _, err := net.SplitHostPort(req.RemoteAddr); err != nil {
		return nil, fmt.Errorf("unable to get ip and port from http.RemoteAddr (%s)", req.RemoteAddr)
	} else if ip := net.ParseIP(ipStr); ip != nil {
		return ip, nil
	} else {
		return nil, fmt.Errorf("unable to parse ip (%s)", ipStr)
	}
	//revive:enable:indent-error-flow
}

// GetRemoteIP obtains the IP of the low-level connected network host.
func GetRemoteIP(req *http.Request) (net.IP, error) {
	return getRemoteIP(req)
}

// GetClientString obtains the human readable string of the remote IP and optionally
// the real client IP. Callers must pass a nil parser unless the peer is trusted.
// Missing or invalid client headers leave only the transport IP in the output.
func GetClientString(p ipapi.RealClientIPParser, req *http.Request, trustedProxies *NetSet, full bool) (s string) {
	var realClientIP net.IP
	if p != nil {
		if parsed, err := GetClientIPFromTrustedProxy(p, req, trustedProxies); err == nil {
			realClientIP = parsed
		}
	}

	remoteIP, _ := getRemoteIP(req)
	return FormatClientString(realClientIP, remoteIP, full)
}

// FormatClientString renders the resolved client address and the transport
// address consistently for auth logs, request logs and callback diagnostics.
// Invalid (nil) addresses are omitted rather than rendered.
func FormatClientString(realClientIP, remoteIP net.IP, full bool) string {
	var realClientIPStr, remoteIPStr string
	if realClientIP != nil {
		realClientIPStr = realClientIP.String()
	}
	if remoteIP != nil {
		remoteIPStr = remoteIP.String()
	}

	if !full && realClientIPStr != "" {
		return realClientIPStr
	}
	if full && realClientIPStr != "" {
		if realClientIPStr == remoteIPStr {
			// The resolved address is the transport peer (for example after the
			// documented fallback to the transport address). Do not render it
			// twice.
			return remoteIPStr
		}
		return fmt.Sprintf("%s (%s)", remoteIPStr, realClientIPStr)
	}
	return remoteIPStr
}
