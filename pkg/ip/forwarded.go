package ip

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// forwardedClientIPParser parses the standardized Forwarded header defined by
// RFC 7239. Each header field line contains a comma separated list of
// forwarded-elements; multiple field lines are concatenated in the order they
// were received, so the rightmost element always belongs to the nearest hop.
type forwardedClientIPParser struct {
	header string
}

// GetRealClientIP returns the address of the end-user as claimed by the
// leftmost Forwarded element. It does not apply a trust decision; callers must
// use GetClientIPFromTrustedProxy when the direct peer is a trusted proxy.
func (p forwardedClientIPParser) GetRealClientIP(h http.Header) (net.IP, error) {
	elements, present, err := splitForwardedElements(h.Values(p.header))
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, nil
	}

	// Without a trust boundary, only the leftmost element can describe the
	// original client. Everything to its right was appended by intermediaries.
	node, err := parseForwardedElement(elements[0])
	if err != nil {
		return nil, err
	}
	if node.obfuscated || node.ip == nil {
		return nil, ErrNoTrustworthyClientIP
	}
	return node.ip, nil
}

// forwardedNode is a single forwarded-element reduced to the address supplied
// by its `for` parameter. Raw header text is intentionally not retained so it
// can never leak into logs or error messages.
type forwardedNode struct {
	ip net.IP
	// obfuscated marks RFC 7239 "unknown" identifiers and identifiers starting
	// with an underscore. Neither can be treated as a trustworthy client.
	obfuscated bool
}

// splitForwardedElements splits every Forwarded field line into raw
// forwarded-elements ordered from left to right. Repeated field lines are
// merged in the order received, so the rightmost element belongs to the nearest
// hop. present reports whether the header contained any element at all; empty
// or whitespace-only headers report present=false so the caller can take the
// documented fallback path.
//
// Only line-level quoting is validated here. Individual elements are parsed
// lazily while walking from the right, so a malformed element to the left of the
// first untrusted hop is never interpreted. This mirrors how the traditional
// X-Forwarded-For chain is handled.
func splitForwardedElements(values []string) (elements []string, present bool, err error) {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}

		// Each field line is an independent list; elements cannot span lines.
		lineElements, err := splitForwarded(value, ',')
		if err != nil {
			return nil, true, err
		}
		elements = append(elements, lineElements...)
	}

	if len(elements) == 0 {
		return nil, false, nil
	}
	return elements, true, nil
}

// parseForwardedElement parses one forwarded-element. Parameter names are
// case-insensitive and may appear in any order. Missing parameters are allowed,
// unknown parameters are ignored, and a repeated `for` parameter is rejected so
// that the source address can never be ambiguous. Repeated values of parameters
// that do not affect the client address are ignored.
func parseForwardedElement(element string) (forwardedNode, error) {
	if strings.TrimSpace(element) == "" {
		return forwardedNode{}, malformed("empty forwarded-element")
	}

	pairs, err := splitForwarded(element, ';')
	if err != nil {
		return forwardedNode{}, err
	}

	seen := make(map[string]struct{}, len(pairs))
	var node forwardedNode
	hasSource := false

	for _, pair := range pairs {
		if strings.TrimSpace(pair) == "" {
			// RFC 7239 permits empty list members produced by a trailing ";".
			continue
		}

		eq := indexOutsideQuotes(pair, '=')
		if eq < 0 {
			return forwardedNode{}, malformed("forwarded-pair without '='")
		}

		name := strings.ToLower(strings.TrimSpace(pair[:eq]))
		if !isForwardedToken(name) {
			return forwardedNode{}, malformed("invalid forwarded-pair name")
		}
		_, duplicate := seen[name]
		seen[name] = struct{}{}

		value, err := parseForwardedValue(pair[eq+1:])
		if err != nil {
			return forwardedNode{}, err
		}

		if name != "for" {
			// Parameters other than "for" (by, proto, host and extensions) do not
			// influence the client address. Their contents are not interpreted so
			// proxies that omit RFC 7239's mandatory quotes still parse, and a
			// repeated value cannot make the source address ambiguous.
			continue
		}
		if duplicate || hasSource {
			// Two source addresses in one element leave the client ambiguous.
			return forwardedNode{}, malformed("duplicate for parameter")
		}
		hasSource = true

		node, err = parseForwardedNode(value)
		if err != nil {
			return forwardedNode{}, err
		}
	}

	if !hasSource {
		// The element describes a hop without disclosing its address. It parses
		// successfully but cannot anchor a trust decision.
		return forwardedNode{}, nil
	}
	return node, nil
}

// parseForwardedNode interprets the value of a `for` parameter. Errors are
// deliberately value-free so raw header content never reaches logs.
func parseForwardedNode(value string) (forwardedNode, error) {
	if value == "" {
		return forwardedNode{}, malformed("empty for parameter")
	}
	if strings.EqualFold(value, "unknown") || strings.HasPrefix(value, "_") {
		return forwardedNode{obfuscated: true}, nil
	}

	clientIP, err := parseForwardedNodeAddress(value)
	if err != nil {
		return forwardedNode{}, err
	}
	return forwardedNode{ip: clientIP}, nil
}

// parseForwardedNodeAddress accepts the node address forms allowed in a `for`
// parameter: an IPv4 or IPv6 address with an optional numeric port, with IPv6
// bracketed when a port follows. Anything else is a syntax error.
func parseForwardedNodeAddress(value string) (net.IP, error) {
	host := value

	if strings.HasPrefix(value, "[") {
		// Bracketed IPv6, optionally followed by :port.
		if !strings.Contains(value, "]") {
			return nil, malformed("unparsable for parameter")
		}
		if splitHost, port, err := net.SplitHostPort(value); err == nil {
			if !isValidPort(port) {
				return nil, malformed("unparsable for parameter")
			}
			host = splitHost
		} else {
			host = strings.TrimSuffix(strings.TrimPrefix(value, "["), "]")
		}
	} else if splitHost, port, err := net.SplitHostPort(value); err == nil {
		if !isValidPort(port) {
			return nil, malformed("unparsable for parameter")
		}
		host = splitHost
	}

	clientIP := net.ParseIP(host)
	if clientIP == nil {
		return nil, malformed("unparsable for parameter")
	}
	return clientIP, nil
}

// isValidPort reports whether port is a 1-5 digit decimal number.
func isValidPort(port string) bool {
	if len(port) == 0 || len(port) > 5 {
		return false
	}
	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return false
		}
	}
	return true
}

// parseForwardedValue validates and unquotes a parameter value. Both tokens and
// quoted-strings are accepted. Quoted values may contain escaped characters,
// colons, brackets and separators; separators inside quotes are not split.
// Unquoted values may not contain embedded whitespace or a stray quote; their
// interpretation (for example whether a `for` value is a valid address) is left
// to the caller.
func parseForwardedValue(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", malformed("empty forwarded-pair value")
	}

	if value[0] != '"' {
		if strings.ContainsRune(value, '"') || strings.ContainsAny(value, " \t\r\n") {
			return "", malformed("invalid forwarded-pair value")
		}
		return value, nil
	}

	var b strings.Builder
	for i := 1; i < len(value); i++ {
		switch value[i] {
		case '\\':
			i++
			if i >= len(value) {
				return "", malformed("unterminated quoted-pair")
			}
			b.WriteByte(value[i])
		case '"':
			if i != len(value)-1 {
				return "", malformed("trailing data after quoted value")
			}
			return b.String(), nil
		default:
			b.WriteByte(value[i])
		}
	}
	return "", malformed("unterminated quoted-string")
}

// splitForwarded splits on sep at the top level, honoring quoted-strings and
// quoted-pairs so separators inside quotes stay part of the value.
func splitForwarded(s string, sep byte) ([]string, error) {
	var parts []string
	start := 0
	inQuotes := false
	escaped := false

	for i := 0; i < len(s); i++ {
		c := s[i]
		if escaped {
			escaped = false
			continue
		}
		switch {
		case inQuotes && c == '\\':
			escaped = true
		case c == '"':
			inQuotes = !inQuotes
		case !inQuotes && c == sep:
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}

	if inQuotes || escaped {
		return nil, malformed("unterminated quoted-string")
	}
	parts = append(parts, s[start:])
	return parts, nil
}

// indexOutsideQuotes returns the index of the first occurrence of c outside a
// quoted-string, or -1.
func indexOutsideQuotes(s string, c byte) int {
	inQuotes := false
	escaped := false
	for i := 0; i < len(s); i++ {
		if escaped {
			escaped = false
			continue
		}
		switch {
		case inQuotes && s[i] == '\\':
			escaped = true
		case s[i] == '"':
			inQuotes = !inQuotes
		case !inQuotes && s[i] == c:
			return i
		}
	}
	return -1
}

// isForwardedToken reports whether s matches RFC 7230's token grammar.
func isForwardedToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

func malformed(reason string) error {
	return fmt.Errorf("%w: %s", ErrMalformedForwardedHeader, reason)
}

// resolveForwardedChain parses the elements from right to left and performs the
// trusted-proxy walk. The caller must only use this when the direct peer is a
// trusted proxy. Addresses covered by the trust mask are skipped; the first
// address outside it is the client. If every address is trusted, the leftmost
// is returned for compatibility.
//
// A hop whose address is obfuscated or missing is an unverifiable boundary:
// nothing further left is considered. Because parsing is lazy, a malformed
// element to the left of the first untrusted hop is never interpreted and
// cannot affect the result.
func resolveForwardedChain(elements []string, trustedProxies *NetSet) (net.IP, error) {
	for i := len(elements) - 1; i >= 0; i-- {
		node, err := parseForwardedElement(elements[i])
		if err != nil {
			return nil, err
		}
		if node.obfuscated || node.ip == nil {
			return nil, ErrNoTrustworthyClientIP
		}

		if i == 0 || !trustedProxies.Has(node.ip) {
			return node.ip, nil
		}
	}

	return nil, ErrNoTrustworthyClientIP
}

// getForwardedClientIP resolves the client address from the standardized
// Forwarded header. When the header is absent or carries no trustworthy node it
// falls back, in this fixed order, to the traditional X-Forwarded-For header
// under the same trust premise and then to the transport address. The two
// headers are never concatenated into a single chain. A Forwarded syntax error
// is surfaced instead of being silently downgraded.
func getForwardedClientIP(req *http.Request, trustedProxies *NetSet) (net.IP, error) {
	elements, present, err := splitForwardedElements(req.Header.Values(forwardedHeader))
	if err != nil {
		return nil, err
	}

	if present {
		clientIP, err := resolveForwardedChain(elements, trustedProxies)
		if err == nil {
			return clientIP, nil
		}
		if !errors.Is(err, ErrNoTrustworthyClientIP) {
			return nil, err
		}
	}

	// Traditional header first, still constrained by the trusted proxy boundary.
	clientIP, err := getXForwardedForClientIP(req, http.CanonicalHeaderKey(xForwardedForHeader), trustedProxies)
	if err != nil {
		return nil, err
	}
	if clientIP != nil {
		return clientIP, nil
	}

	// Final fallback: the transport address, exactly as when forwarded headers
	// cannot be trusted at all.
	return getRemoteIP(req)
}
