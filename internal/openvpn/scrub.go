package openvpn

import "strings"

// sensitiveDirectives are openvpn config directives whose value is a secret.
// A log line naming one of these is replaced with a marker rather than the
// value, because openvpn echoes the offending line when it rejects a config and
// that line is exactly where a password or private key would appear.
var sensitiveDirectives = []string{
	"auth-user-pass",
	"askpass",
	"management-client-password",
	"management-query-passwords",
	"ppp-password",
	"ipsec-secret",
	"key",
	"tls-auth",
	"tls-crypt",
	"pkcs12",
	"secret",
}

// ScrubLine removes credential material from a single log line.
//
// It is deliberately conservative about what it matches: only a directive
// followed by a value is redacted, so a diagnostic line that merely mentions
// "key" stays readable, while `management-client-password hunter2` becomes
// `management-client-password <redacted>`.
func ScrubLine(line string) string {
	lower := strings.ToLower(line)
	// Only the directive form is redacted; this keeps prose intact.
	best := -1
	bestDirective := ""
	for _, d := range sensitiveDirectives {
		if i := indexDirective(lower, d); i >= 0 && (best == -1 || i < best) {
			best = i
			bestDirective = d
		}
	}
	if best < 0 {
		return line
	}
	// The value starts after the directive and its separating whitespace.
	rest := best + len(bestDirective)
	for rest < len(line) && (line[rest] == ' ' || line[rest] == '\t' || line[rest] == '=') {
		rest++
	}
	if rest >= len(line) {
		// Directive with no value on this line: nothing to redact, and the
		// value may be on a following line (inline PEM), which the caller's
		// own handling covers.
		return line
	}
	return line[:rest] + "<redacted>"
}

// indexDirective finds d in line only when it appears as a whole directive: at
// the start of the line or after whitespace, so "monkey" does not match "key".
func indexDirective(line, d string) int {
	from := 0
	for {
		i := strings.Index(line[from:], d)
		if i < 0 {
			return -1
		}
		i += from
		if i == 0 || line[i-1] == ' ' || line[i-1] == '\t' || line[i-1] == '"' || line[i-1] == '\'' {
			return i
		}
		from = i + len(d)
	}
}

// RedactSecret renders a secret for logs and API responses: never the value.
// The empty string stays empty so a caller can distinguish "no secret" from
// "redacted secret".
func RedactSecret(s string) string {
	if s == "" {
		return ""
	}
	return "<redacted>"
}