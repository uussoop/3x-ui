package ikev2

import (
	"regexp"
	"strings"
)

// credentialKeys are the VICI/swanctl keys whose values must never reach a log
// line, an API response or a metric label. A VICI error quotes the offending
// section verbatim, so an unscrubbed message would carry the account password
// straight into the panel's logs.
var credentialKeys = []string{
	"psk", "key", "password", "passwd", "pass", "secret", "eap_password",
	"private_key", "private", "token", "auth_token",
}

var scrubPattern = regexp.MustCompile(
	`(?i)\b(` + strings.Join(credentialKeys, "|") + `)\s*=\s*"[^"]*"`)

// ScrubLine removes credential values from a line before it is logged or
// returned to an operator. It replaces the value rather than the whole line so
// the surrounding diagnostic — which key, which section — survives.
func ScrubLine(line string) string {
	if line == "" {
		return line
	}
	return scrubPattern.ReplaceAllString(line, `${1} = "***"`)
}

// RedactSecret masks a known secret value wherever it appears in a string. Used
// as a backstop for a value charon echoed back outside a key=value form.
func RedactSecret(s, secret string) string {
	if secret == "" {
		return s
	}
	return strings.ReplaceAll(s, secret, "***")
}