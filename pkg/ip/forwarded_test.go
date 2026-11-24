package ip

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestForwardedClientIPParserGetRealClientIP(t *testing.T) {
	p := &forwardedClientIPParser{header: http.CanonicalHeaderKey(forwardedHeader)}

	tests := []struct {
		name        string
		headerLines []string
		expectedIP  string
		err         error
	}{
		// Single element, source address only, IPv4 without port.
		{name: "IPv4 without port", headerLines: []string{"for=192.0.2.43"}, expectedIP: "192.0.2.43"},
		{name: "IPv4 with port", headerLines: []string{"for=192.0.2.43:47011"}, expectedIP: "192.0.2.43"},
		{name: "quoted IPv4 with port", headerLines: []string{`for="192.0.2.43:47011"`}, expectedIP: "192.0.2.43"},
		{name: "quoted IPv4 without port", headerLines: []string{`for="192.0.2.43"`}, expectedIP: "192.0.2.43"},

		// IPv6, bracketed and bare, with and without port.
		{name: "bare IPv6", headerLines: []string{"for=2001:db8::1"}, expectedIP: "2001:db8::1"},
		{name: "quoted bracketed IPv6", headerLines: []string{`for="[2001:db8::1]"`}, expectedIP: "2001:db8::1"},
		{name: "quoted bracketed IPv6 with port", headerLines: []string{`for="[2001:db8::1]:4711"`}, expectedIP: "2001:db8::1"},
		{name: "unquoted bracketed IPv6 with port", headerLines: []string{"for=[2001:db8::1]:4711"}, expectedIP: "2001:db8::1"},

		// Multiple elements in arrival order; without a trust boundary the
		// leftmost claimed address is the client.
		{name: "leftmost of several elements", headerLines: []string{"for=10.0.0.5, for=198.51.100.23, for=192.0.2.20"}, expectedIP: "10.0.0.5"},
		{name: "mixed IPv4 and IPv6", headerLines: []string{`for=10.0.0.5, for="[2001:db8::1]:443", for=192.0.2.20`}, expectedIP: "10.0.0.5"},

		// Parameter names are case-insensitive and order independent; partial
		// parameter sets still parse.
		{name: "uppercase parameter name", headerLines: []string{`FOR="192.0.2.43"`}, expectedIP: "192.0.2.43"},
		{name: "mixed case parameter name", headerLines: []string{"For=192.0.2.43"}, expectedIP: "192.0.2.43"},
		{name: "parameters in any order", headerLines: []string{"proto=https;for=192.0.2.43;by=203.0.113.43"}, expectedIP: "192.0.2.43"},
		{name: "source and proxy only", headerLines: []string{"for=192.0.2.43;by=203.0.113.43"}, expectedIP: "192.0.2.43"},
		{name: "source and host only", headerLines: []string{"for=192.0.2.43;host=example.com"}, expectedIP: "192.0.2.43"},
		{name: "source and unquoted host with port", headerLines: []string{"for=192.0.2.43;host=example.com:443"}, expectedIP: "192.0.2.43"},
		{name: "proxy address only element before source", headerLines: []string{"by=203.0.113.43, for=192.0.2.43"}, err: ErrNoTrustworthyClientIP},
		{name: "source and protocol and host", headerLines: []string{"for=192.0.2.43;proto=https;host=example.com:443"}, expectedIP: "192.0.2.43"},
		{name: "whitespace around parameters", headerLines: []string{"  for=192.0.2.43  ;  proto=https  "}, expectedIP: "192.0.2.43"},
		// Unknown parameters are ignored, and repeating a parameter that does
		// not carry the source address is harmless.
		{name: "unknown parameter is ignored", headerLines: []string{"for=192.0.2.43;ext=foo;ext=bar"}, expectedIP: "192.0.2.43"},
		{name: "duplicate non-source parameter is ignored", headerLines: []string{"for=192.0.2.43;proto=http;proto=https"}, expectedIP: "192.0.2.43"},
		{name: "duplicate by parameter is ignored", headerLines: []string{"for=192.0.2.43;by=203.0.113.1;by=203.0.113.2"}, expectedIP: "192.0.2.43"},
		{name: "trailing semicolon is tolerated", headerLines: []string{"for=192.0.2.43;"}, expectedIP: "192.0.2.43"},

		// Quoted values may contain separators, escaped quotes and backslashes.
		{name: "separators inside quotes are not split", headerLines: []string{`for=192.0.2.43;by=";for=6.6.6.6"`}, expectedIP: "192.0.2.43"},
		{name: "comma inside quoted value is not split", headerLines: []string{`for=192.0.2.43;by="[::1]:443,evil"`}, expectedIP: "192.0.2.43"},
		{name: "escaped quote inside quoted value", headerLines: []string{`for=192.0.2.43;by="a\"b"`}, expectedIP: "192.0.2.43"},
		{name: "escaped backslash inside quoted value", headerLines: []string{`for=192.0.2.43;by="a\\b"`}, expectedIP: "192.0.2.43"},
		{name: "colon and brackets inside quotes", headerLines: []string{`for="[2001:db8::1]:4711";by="proxy:443"`}, expectedIP: "2001:db8::1"},

		// Repeated field lines are merged in received order.
		{name: "repeated field lines", headerLines: []string{"for=10.0.0.5", "for=198.51.100.23, for=192.0.2.20"}, expectedIP: "10.0.0.5"},

		// Obfuscated identifiers cannot be adopted as a client address.
		{name: "unknown identifier", headerLines: []string{"for=unknown"}, err: ErrNoTrustworthyClientIP},
		{name: "unknown identifier any case", headerLines: []string{"for=UNKNOWN"}, err: ErrNoTrustworthyClientIP},
		{name: "obfuscated identifier", headerLines: []string{"for=_hidden"}, err: ErrNoTrustworthyClientIP},
		{name: "quoted obfuscated identifier", headerLines: []string{`for="_gazonk"`}, err: ErrNoTrustworthyClientIP},
		{name: "element without source", headerLines: []string{"proto=https"}, err: ErrNoTrustworthyClientIP},
		{name: "first element without source", headerLines: []string{"proto=https, for=192.0.2.43"}, err: ErrNoTrustworthyClientIP},
		{name: "obfuscated leftmost with more elements", headerLines: []string{`for=unknown, for=192.0.2.20`}, err: ErrNoTrustworthyClientIP},

		// Header missing, empty or whitespace only.
		{name: "missing header", headerLines: nil},
		{name: "empty header", headerLines: []string{""}},
		{name: "whitespace only header", headerLines: []string{" \t "}},
		{name: "multiple whitespace only lines", headerLines: []string{"", "   "}},

		// Syntax errors are reported and never produce a partial value.
		{name: "unterminated quoted string", headerLines: []string{`for="192.0.2.43`}, err: ErrMalformedForwardedHeader},
		{name: "unterminated quoted pair", headerLines: []string{`for="192.0.2.43\`}, err: ErrMalformedForwardedHeader},
		{name: "trailing data after quoted value", headerLines: []string{`for="192.0.2.43"x`}, err: ErrMalformedForwardedHeader},
		{name: "pair without equals", headerLines: []string{"for"}, err: ErrMalformedForwardedHeader},
		{name: "empty value", headerLines: []string{"for="}, err: ErrMalformedForwardedHeader},
		{name: "empty first element", headerLines: []string{", for=198.51.100.23"}, err: ErrMalformedForwardedHeader},
		{name: "duplicate for parameter", headerLines: []string{"for=192.0.2.43;for=198.51.100.23"}, err: ErrMalformedForwardedHeader},
		{name: "duplicate for parameter any case", headerLines: []string{"for=192.0.2.43;FOR=198.51.100.23"}, err: ErrMalformedForwardedHeader},
		{name: "unparsable source address", headerLines: []string{"for=10000.10000.10000.10000"}, err: ErrMalformedForwardedHeader},
		{name: "source address with stray token", headerLines: []string{"for=1.2.3.4 5.6.7.8"}, err: ErrMalformedForwardedHeader},
		{name: "invalid parameter name", headerLines: []string{"for=192.0.2.43;bad name=x"}, err: ErrMalformedForwardedHeader},

		// Only the leftmost element is interpreted here, matching how the raw
		// X-Forwarded-For parser reads a single value. Malformed later elements
		// are handled by the trust-aware walk below.
		{name: "trailing comma after valid source", headerLines: []string{"for=192.0.2.43,"}, expectedIP: "192.0.2.43"},
		{name: "malformed value on later element", headerLines: []string{"for=192.0.2.43, for="}, expectedIP: "192.0.2.43"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h := http.Header{}
			for _, line := range test.headerLines {
				h.Add(forwardedHeader, line)
			}

			clientIP, err := p.GetRealClientIP(h)

			if test.err != nil {
				assert.ErrorIs(t, err, test.err)
			} else {
				assert.NoError(t, err)
			}
			if test.expectedIP == "" {
				assert.Nil(t, clientIP)
			} else {
				require.NotNil(t, clientIP)
				assert.True(t, net.ParseIP(test.expectedIP).Equal(clientIP), "got %s", clientIP)
			}
		})
	}
}

func TestGetClientIPFromTrustedProxyForwarded(t *testing.T) {
	parser, err := GetRealClientIPParser("Forwarded")
	require.NoError(t, err)
	trustedProxies, err := ParseNetSet([]string{"192.0.2.0/24", "2001:db8:1::/48"})
	require.NoError(t, err)

	tests := []struct {
		name        string
		remoteAddr  string
		headerLines []string
		expectedIP  string
		err         error
	}{
		// Single element.
		{name: "single IPv4 element", remoteAddr: "192.0.2.10:1234", headerLines: []string{"for=198.51.100.23"}, expectedIP: "198.51.100.23"},
		{name: "single quoted element with port", remoteAddr: "192.0.2.10:1234", headerLines: []string{`for="198.51.100.23:4711"`}, expectedIP: "198.51.100.23"},

		// Right-to-left walk skipping trusted hops.
		{name: "skips trusted intermediate hop", remoteAddr: "192.0.2.10:1234", headerLines: []string{"for=198.51.100.23, for=192.0.2.20"}, expectedIP: "198.51.100.23"},
		{name: "skips two trusted intermediate hops", remoteAddr: "192.0.2.10:1234", headerLines: []string{"for=10.9.9.9, for=203.0.113.9, for=192.0.2.20, for=192.0.2.21"}, expectedIP: "203.0.113.9"},
		{name: "three layer chain two trusted one untrusted", remoteAddr: "192.0.2.10:1234", headerLines: []string{"for=203.0.113.9, for=192.0.2.20, for=192.0.2.21"}, expectedIP: "203.0.113.9"},

		// First untrusted hop from the right wins, everything to its left is
		// ignored even if it looks more like a client.
		{name: "stops at first untrusted hop", remoteAddr: "192.0.2.10:1234", headerLines: []string{"for=10.9.9.9, for=203.0.113.9, for=198.51.100.20"}, expectedIP: "198.51.100.20"},
		{name: "ignores spoofed leftmost entry", remoteAddr: "192.0.2.10:1234", headerLines: []string{"for=10.9.9.9, for=198.51.100.23, for=192.0.2.20, for=192.0.2.21"}, expectedIP: "198.51.100.23"},

		// Entire chain trusted: compatibility leftmost address.
		{name: "entire chain trusted uses leftmost", remoteAddr: "192.0.2.10:1234", headerLines: []string{"for=192.0.2.30, for=192.0.2.20"}, expectedIP: "192.0.2.30"},

		// IPv6 and mixed families.
		{name: "IPv6 client and proxy", remoteAddr: "[2001:db8:1::10]:1234", headerLines: []string{`for="[2001:db8:2::23]:1234", for="[2001:db8:1::20]:443"`}, expectedIP: "2001:db8:2::23"},
		{name: "mixed families in one list", remoteAddr: "192.0.2.10:1234", headerLines: []string{`for=198.51.100.23, for="[2001:db8:1::20]:443", for=192.0.2.20`}, expectedIP: "198.51.100.23"},

		// IPv4-mapped notation resolves into the corresponding IPv4 network.
		{name: "IPv4 mapped matches IPv4 trust mask", remoteAddr: "192.0.2.10:1234", headerLines: []string{"for=::ffff:198.51.100.9, for=::ffff:192.0.2.20"}, expectedIP: "198.51.100.9"},

		// Repeated field lines merge in received order.
		{name: "repeated fields preserve chain order", remoteAddr: "192.0.2.10:1234", headerLines: []string{"for=10.0.0.5", "for=198.51.100.23, for=192.0.2.20", "for=192.0.2.21"}, expectedIP: "198.51.100.23"},

		// Obfuscated boundary and obfuscated hops.
		{name: "obfuscated rightmost hop falls back to transport", remoteAddr: "192.0.2.10:1234", headerLines: []string{"for=192.0.2.20, for=_hidden"}, expectedIP: "192.0.2.10"},
		{name: "obfuscated left of untrusted hop is never consulted", remoteAddr: "192.0.2.10:1234", headerLines: []string{"for=_hidden, for=198.51.100.23, for=192.0.2.20"}, expectedIP: "198.51.100.23"},
		{name: "unknown rightmost hop falls back to transport", remoteAddr: "192.0.2.10:1234", headerLines: []string{"for=192.0.2.20, for=unknown"}, expectedIP: "192.0.2.10"},

		// Missing / empty / whitespace-only header.
		{name: "missing header falls back to transport", remoteAddr: "192.0.2.10:1234", expectedIP: "192.0.2.10"},
		{name: "empty header falls back to transport", remoteAddr: "192.0.2.10:1234", headerLines: []string{""}, expectedIP: "192.0.2.10"},
		{name: "whitespace only header falls back to transport", remoteAddr: "192.0.2.10:1234", headerLines: []string{" \t "}, expectedIP: "192.0.2.10"},

		// Syntax errors are surfaced, not silently downgraded.
		{name: "unterminated quote", remoteAddr: "192.0.2.10:1234", headerLines: []string{`for="198.51.100.23`}, err: ErrMalformedForwardedHeader},
		{name: "duplicate for parameter", remoteAddr: "192.0.2.10:1234", headerLines: []string{"for=198.51.100.23;for=203.0.113.9"}, err: ErrMalformedForwardedHeader},
		{name: "empty element in chain", remoteAddr: "192.0.2.10:1234", headerLines: []string{"for=198.51.100.23, , for=192.0.2.20"}, err: ErrMalformedForwardedHeader},
		{name: "trailing comma in chain", remoteAddr: "192.0.2.10:1234", headerLines: []string{"for=198.51.100.23,"}, err: ErrMalformedForwardedHeader},
		{name: "malformed element left of untrusted hop is ignored", remoteAddr: "192.0.2.10:1234", headerLines: []string{"for=not-an-ip, for=198.51.100.23, for=192.0.2.20"}, expectedIP: "198.51.100.23"},
		{name: "malformed element right of client is an error", remoteAddr: "192.0.2.10:1234", headerLines: []string{"for=198.51.100.23, for=192.0.2.20, for=not-an-ip"}, err: ErrMalformedForwardedHeader},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := &http.Request{Header: http.Header{}, RemoteAddr: test.remoteAddr}
			for _, line := range test.headerLines {
				req.Header.Add("Forwarded", line)
			}

			clientIP, err := GetClientIPFromTrustedProxy(parser, req, trustedProxies)

			if test.err != nil {
				assert.ErrorIs(t, err, test.err)
				assert.Nil(t, clientIP)
				return
			}
			assert.NoError(t, err)
			require.NotNil(t, clientIP)
			assert.True(t, net.ParseIP(test.expectedIP).Equal(clientIP), "got %s", clientIP)
		})
	}
}

func TestGetClientIPFromTrustedProxyForwardedFallback(t *testing.T) {
	forwarded, err := GetRealClientIPParser("Forwarded")
	require.NoError(t, err)
	xff, err := GetRealClientIPParser("X-Forwarded-For")
	require.NoError(t, err)
	trustedProxies, err := ParseNetSet([]string{"192.0.2.0/24"})
	require.NoError(t, err)

	tests := []struct {
		name   string
		parser interface {
			GetRealClientIP(http.Header) (net.IP, error)
		}
		forwarded     []string
		xForwardedFor []string
		remoteAddr    string
		expectedIP    string
		err           error
	}{
		// Standardized header missing or without a trustworthy node: fall back
		// to the traditional header under the same trust premise.
		{name: "absent standardized header uses traditional header", parser: forwarded, xForwardedFor: []string{"10.0.0.5, 198.51.100.23"}, remoteAddr: "192.0.2.10:1234", expectedIP: "198.51.100.23"},
		{name: "whitespace standardized header uses traditional header", parser: forwarded, forwarded: []string{" "}, xForwardedFor: []string{"198.51.100.23, 192.0.2.20"}, remoteAddr: "192.0.2.10:1234", expectedIP: "198.51.100.23"},
		{name: "obfuscated standardized node uses traditional header", parser: forwarded, forwarded: []string{"for=_hidden"}, xForwardedFor: []string{"198.51.100.23, 192.0.2.20"}, remoteAddr: "192.0.2.10:1234", expectedIP: "198.51.100.23"},

		// Both headers missing: transport address is the final fallback.
		{name: "both headers absent uses transport", parser: forwarded, remoteAddr: "192.0.2.10:1234", expectedIP: "192.0.2.10"},
		{name: "standardized obfuscated and traditional absent uses transport", parser: forwarded, forwarded: []string{"for=unknown"}, remoteAddr: "192.0.2.10:1234", expectedIP: "192.0.2.10"},

		// The two headers are never concatenated into one chain.
		{name: "does not merge headers into a chain", parser: forwarded, forwarded: []string{"for=198.51.100.23"}, xForwardedFor: []string{"10.0.0.5"}, remoteAddr: "192.0.2.10:1234", expectedIP: "198.51.100.23"},

		// A syntax error in the primary standardized header is reported instead
		// of being silently replaced by the traditional header.
		{name: "standardized syntax error is reported", parser: forwarded, forwarded: []string{`for="198.51.100.23`}, xForwardedFor: []string{"198.51.100.23"}, remoteAddr: "192.0.2.10:1234", err: ErrMalformedForwardedHeader},

		// Traditional primary never falls back to the standardized header.
		{name: "traditional primary ignores standardized header", parser: xff, forwarded: []string{"for=6.6.6.6"}, xForwardedFor: []string{"10.0.0.5, 198.51.100.23"}, remoteAddr: "192.0.2.10:1234", expectedIP: "198.51.100.23"},
		{name: "traditional primary absent does not use standardized header", parser: xff, forwarded: []string{"for=6.6.6.6"}, remoteAddr: "192.0.2.10:1234", expectedIP: ""},

		// Traditional header parse failure remains an error.
		{name: "traditional fallback syntax error", parser: forwarded, forwarded: []string{"for=_hidden"}, xForwardedFor: []string{"10.0.0.5, invalid"}, remoteAddr: "192.0.2.10:1234"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := &http.Request{Header: http.Header{}, RemoteAddr: test.remoteAddr}
			for _, line := range test.forwarded {
				req.Header.Add("Forwarded", line)
			}
			for _, line := range test.xForwardedFor {
				req.Header.Add("X-Forwarded-For", line)
			}

			clientIP, err := GetClientIPFromTrustedProxy(test.parser, req, trustedProxies)

			if test.name == "traditional fallback syntax error" {
				assert.Error(t, err)
				assert.Nil(t, clientIP)
				return
			}
			if test.err != nil {
				assert.ErrorIs(t, err, test.err)
				assert.Nil(t, clientIP)
				return
			}
			assert.NoError(t, err)
			if test.expectedIP == "" {
				assert.Nil(t, clientIP)
				return
			}
			require.NotNil(t, clientIP)
			assert.True(t, net.ParseIP(test.expectedIP).Equal(clientIP), "got %s", clientIP)
		})
	}
}

func TestForwardedClientIPParserNoLeak(t *testing.T) {
	p := &forwardedClientIPParser{header: http.CanonicalHeaderKey(forwardedHeader)}

	// Values that intentionally fail to parse or are obfuscated must never be
	// echoed back in an error message, and obfuscated identifiers must not be
	// exposed at all.
	for _, headerValue := range []string{
		`for="198.51.100.23`,
		`for=198.51.100.23:abc`,
		`for=evil.example.com`,
		`for=1.2.3.4 5.6.7.8`,
		`for=not-an-ip;proto=https`,
		`for="";by="trailing`,
	} {
		h := http.Header{}
		h.Add(forwardedHeader, headerValue)
		_, err := p.GetRealClientIP(h)
		require.Error(t, err)
		for _, fragment := range []string{
			"198.51.100.23", "evil.example.com", "1.2.3.4 5.6.7.8", "not-an-ip", "trailing",
		} {
			assert.NotContains(t, err.Error(), fragment)
		}
	}

	for _, headerValue := range []string{"for=unknown", "for=_hidden", `for="_gazonk"`} {
		h := http.Header{}
		h.Add(forwardedHeader, headerValue)
		_, err := p.GetRealClientIP(h)
		require.Error(t, err)
		for _, fragment := range []string{"unknown", "_hidden", "_gazonk"} {
			assert.NotContains(t, strings.ToLower(err.Error()), strings.ToLower(fragment))
		}
	}
}

func TestForwardedClientIPParserNormalization(t *testing.T) {
	trustedProxies, err := ParseNetSet([]string{"192.0.2.0/24", "2001:db8:1::/48"})
	require.NoError(t, err)

	// Addresses are normalized before comparison, so the IPv4-mapped form of
	// an address matches the corresponding IPv4 network and the bracketed form
	// of an IPv6 address matches the IPv6 network.
	assert.True(t, trustedProxies.Has(net.ParseIP("::ffff:192.0.2.20")))
	assert.True(t, trustedProxies.Has(net.ParseIP("192.0.2.20")))
	assert.True(t, trustedProxies.Has(net.ParseIP("2001:db8:1::20")))
	assert.False(t, trustedProxies.Has(net.ParseIP("::ffff:198.51.100.9")))
	assert.False(t, trustedProxies.Has(net.ParseIP("2001:db8:2::23")))
}

func TestForwardedThreeLayerChain(t *testing.T) {
	// Build a real three-hop chain: client -> edge proxy -> inner proxy -> peer.
	// Both proxies are trusted, the client is not. A spoofed address prepended
	// by the client must never win.
	parser, err := GetRealClientIPParser("Forwarded")
	require.NoError(t, err)
	trustedProxies, err := ParseNetSet([]string{"192.0.2.0/24", "198.51.100.0/24"})
	require.NoError(t, err)

	req := &http.Request{Header: http.Header{}, RemoteAddr: "192.0.2.10:1234"}
	// The client claims 10.9.9.9; the edge proxy appends the client address it
	// observed, and the inner proxy appends itself.
	req.Header.Add("Forwarded", "for=10.9.9.9")
	req.Header.Add("Forwarded", "for=203.0.113.9, for=198.51.100.20")
	req.Header.Add("Forwarded", "for=192.0.2.21")

	clientIP, err := GetClientIPFromTrustedProxy(parser, req, trustedProxies)
	require.NoError(t, err)
	assert.True(t, net.ParseIP("203.0.113.9").Equal(clientIP), "got %s", clientIP)

	// If the first hop to the right of the client is itself untrusted, the
	// walk must stop there and never consult anything further left.
	req = &http.Request{Header: http.Header{}, RemoteAddr: "192.0.2.10:1234"}
	req.Header.Add("Forwarded", "for=203.0.113.9, for=203.0.113.10, for=192.0.2.21")
	clientIP, err = GetClientIPFromTrustedProxy(parser, req, trustedProxies)
	require.NoError(t, err)
	assert.True(t, net.ParseIP("203.0.113.10").Equal(clientIP), "got %s", clientIP)
}

func TestForwardedResolverBoundary(t *testing.T) {
	trustedProxies, err := ParseNetSet([]string{"192.0.2.0/24"})
	require.NoError(t, err)

	parse := func(values ...string) []string {
		elements, present, err := splitForwardedElements(values)
		require.NoError(t, err)
		require.True(t, present)
		return elements
	}

	// A hop whose address is unknown or obfuscated is an unverifiable boundary:
	// the walk stops instead of trusting anything further left.
	_, err = resolveForwardedChain(parse("for=198.51.100.23, for=_hidden, for=192.0.2.20"), trustedProxies)
	assert.ErrorIs(t, err, ErrNoTrustworthyClientIP)

	// An element without a source address is likewise unverifiable.
	_, err = resolveForwardedChain(parse("for=198.51.100.23, proto=https, for=192.0.2.20"), trustedProxies)
	assert.ErrorIs(t, err, ErrNoTrustworthyClientIP)

	// A malformed element to the left of the first untrusted hop is never
	// parsed, matching traditional header semantics.
	clientIP, err := resolveForwardedChain(parse("for=not-an-ip, for=198.51.100.23, for=192.0.2.20"), trustedProxies)
	require.NoError(t, err)
	assert.True(t, net.ParseIP("198.51.100.23").Equal(clientIP), "got %s", clientIP)
}

func TestForwardedErrorsAreDistinguishable(t *testing.T) {
	malformedChain := errors.Is(ErrMalformedForwardedHeader, ErrMalformedForwardedHeader)
	assert.True(t, malformedChain)
	assert.False(t, errors.Is(ErrMalformedForwardedHeader, ErrNoTrustworthyClientIP))
}
