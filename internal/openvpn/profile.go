package openvpn

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// The directives below make openvpn execute something, or hand control to
// something outside the tunnel. A .ovpn profile is untrusted input, so a
// profile containing any of them is rejected as a whole rather than filtered
// line by line: partial sanitising would mean guessing which of the remaining
// directives are safe in combination, and the failure mode of guessing wrong is
// code execution as root.
var rejectedProfileDirectives = map[string]string{
	"up":                         "runs an external command",
	"down":                       "runs an external command",
	"route-up":                   "runs an external command",
	"ipchange":                   "runs an external command",
	"client-connect":             "runs an external command",
	"client-disconnect":          "runs an external command",
	"auth-user-pass-verify":      "runs an external command",
	"tls-verify":                 "runs an external command",
	"plugin":                     "loads a shared object",
	"script-security":            "changes the script execution policy",
	"management":                 "opens an unauthenticated control channel of its own",
	"management-client":          "changes management interface behaviour",
	"management-client-user":     "changes management interface behaviour",
	"management-client-password": "changes management interface behaviour",
	"management-external-cert":   "changes management interface behaviour",
	"management-external-key":    "changes management interface behaviour",
	"management-hold":            "changes management interface behaviour",
	"management-query-passwords": "reads credentials",
	"management-signal":          "changes management interface behaviour",
	"management-log-cache":       "changes management interface behaviour",
	"management-up-down":         "runs an external command",
	"management-client-auth":     "changes management interface behaviour",
	"askpass":                    "runs an external command",
	"setenv":                     "can override security-sensitive environment defaults",
	"tmp-dir":                    "escapes the tunnel's private directory",
	"cd":                         "escapes the tunnel's private directory",
	"chroot":                     "escapes the tunnel's private directory",
	"daemon":                     "detaches from the managed process lifecycle",
	"service":                    "detaches from the managed process lifecycle",
	"iproute":                    "runs an external command",
	"ip-win32":                   "runs an external command",
}

// The directives below are the allowlist an imported profile may carry. They
// describe how to reach the server and how to authenticate; they cannot start
// a process, load code, or redirect the tunnel's traffic handling. Anything not
// on this list is dropped rather than passed through, so an unknown or future
// directive fails closed.
type profileParams struct {
	Remote       string
	RemotePort   int
	Proto        string
	CA           string
	Cert         string
	Key          string
	TLSAuth      string
	AuthUserPass bool
	Username     string
	Password     string
	Cipher       string
	Auth         string
	CompLzo      string
	Dev          string
	Verb         int
	RemoteTLS    string
	TLSClient    string
	VerifyX509   string
	Keepalive    string
	Float        bool
	TLSVersion   string
}

// ParseProfile parses an imported .ovpn profile into the small set of
// connection parameters the client adapter is willing to honour.
//
// It returns an error — and never a partially usable profile — when the profile
// contains a directive that executes code, loads a plugin, or takes over
// management, when it carries no usable remote, or when its user/pass
// credentials are not a plain inline pair. The caller surfaces that error to
// the operator; nothing from a rejected profile reaches the generated config.
func ParseProfile(raw string) (profileParams, error) {
	var p profileParams
	if strings.TrimSpace(raw) == "" {
		return p, fmt.Errorf("profile is empty")
	}

	// Inline blocks: <ca>...</ca>, <cert>...</cert>, <key>...</key>,
	// <tls-auth>...</tls-auth>. Collected first so the main pass can treat a
	// certificate arriving either inline or via a file reference uniformly.
	inline := collectInlineBlocks(raw)

	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	for n, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed == "#" || trimmed == ";" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if trimmed == "<ca>" || trimmed == "</ca>" || trimmed == "<cert>" || trimmed == "</cert>" ||
			trimmed == "<key>" || trimmed == "</key>" || trimmed == "<tls-auth>" || trimmed == "</tls-auth>" {
			continue
		}

		key, value := splitDirective(trimmed)
		if key == "" {
			return p, fmt.Errorf("line %d: not a directive: %q", n+1, redactLine(trimmed))
		}
		if reason, bad := rejectedProfileDirectives[key]; bad {
			return p, fmt.Errorf("line %d: directive %q is not allowed in an imported profile: %s", n+1, key, reason)
		}

		switch key {
		case "remote":
			host, port, err := parseRemote(value)
			if err != nil {
				return p, fmt.Errorf("line %d: %w", n+1, err)
			}
			// The first remote wins; a profile listing many fallbacks would
			// otherwise silently pick a different server than the operator
			// saw, and OpenVPN's own failover is not something the panel's
			// health selection can reason about.
			if p.Remote == "" {
				p.Remote = host
				p.RemotePort = port
			}
		case "port":
			// A bare `port` after `remote` overrides that remote's port. It
			// applies to whichever remote was parsed first.
			n, err := strconv.Atoi(value)
			if err != nil || n <= 0 || n > 65535 {
				return p, fmt.Errorf("line %d: invalid port %q", n, value)
			}
			if p.Remote != "" {
				p.RemotePort = n
			}
		case "proto":
			switch strings.ToLower(value) {
			case "udp", "udp4", "udp6":
				p.Proto = "udp"
			case "tcp", "tcp4", "tcp6", "tcp-client", "tcp4-client", "tcp6-client":
				p.Proto = "tcp"
			default:
				return p, fmt.Errorf("line %d: unsupported proto %q", n+1, value)
			}
		case "dev":
			p.Dev = value
		case "auth-user-pass":
			if strings.EqualFold(value, "none") {
				return p, fmt.Errorf("line %d: auth-user-pass must carry inline credentials", n+1)
			}
			p.AuthUserPass = true
			user, pass, err := parseUserPassPair(value)
			if err != nil {
				return p, fmt.Errorf("line %d: %w", n+1, err)
			}
			p.Username, p.Password = user, pass
		case "ca", "cert", "key", "tls-auth":
			// A file reference is only meaningful if the operator also supplied
			// the file's contents, which an .ovpn paste cannot. Accept the
			// inline block collected above, or a value that is itself a PEM.
			body := inline[key]
			if body == "" && strings.ContainsAny(value, "\n") {
				body = value
			}
			if strings.TrimSpace(body) == "" {
				return p, fmt.Errorf("line %d: %s references a file; paste the %s contents into the profile instead", n+1, key, key)
			}
			switch key {
			case "ca":
				p.CA = body
			case "cert":
				p.Cert = body
			case "key":
				p.Key = body
			case "tls-auth":
				p.TLSAuth = body
			}
		case "cipher", "auth", "comp-lzo", "remote-cert-tls", "tls-client", "verify-x509-name", "keepalive", "tls-version-min", "tls-cipher":
			assignString(&p, key, value)
		case "float":
			p.Float = true
		case "verb":
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 || n > 11 {
				return p, fmt.Errorf("line %d: invalid verb %q", n+1, value)
			}
			p.Verb = n
		default:
			// Unknown directive: dropped, not rejected. Rejecting would make
			// real-world profiles unimportable for cosmetic reasons; dropping
			// is safe because the allowlist above is what defines behaviour.
			continue
		}
	}

	// A version the daemon does not recognise is not cosmetic: it is emitted
	// into the generated config verbatim and OpenVPN refuses to start on it,
	// so a typo in a third-party profile would take the exit down instead of
	// being caught where it entered. Validating at import keeps the rendered
	// config a known-good set of values.
	if p.TLSVersion != "" {
		switch p.TLSVersion {
		case "1.0", "1.1", "1.2", "1.3":
		default:
			return p, fmt.Errorf("profile has an unsupported tls-version-min %q", p.TLSVersion)
		}
	}

	// Certificates delivered as inline <ca>/<cert>/<key> blocks never appear as
	// a directive line, so they are folded in here. Without this an ordinary
	// exported profile — which is how providers ship them — would look like it
	// carried no CA at all.
	if strings.TrimSpace(p.CA) == "" {
		p.CA = inline["ca"]
	}
	if strings.TrimSpace(p.Cert) == "" {
		p.Cert = inline["cert"]
	}
	if strings.TrimSpace(p.Key) == "" {
		p.Key = inline["key"]
	}
	if strings.TrimSpace(p.TLSAuth) == "" {
		p.TLSAuth = inline["tls-auth"]
	}

	if p.Remote == "" {
		return p, fmt.Errorf("profile has no usable remote")
	}
	if p.RemotePort == 0 {
		p.RemotePort = 1194
	}
	if p.Proto == "" {
		p.Proto = "udp"
	}
	if p.CA == "" {
		return p, fmt.Errorf("profile has no CA certificate; a tunnel with no pinned CA accepts any server certificate")
	}
	return p, nil
}

func assignString(p *profileParams, key, value string) {
	switch key {
	case "cipher":
		p.Cipher = value
	case "auth":
		p.Auth = value
	case "comp-lzo":
		p.CompLzo = value
	case "remote-cert-tls":
		p.RemoteTLS = value
	case "tls-client":
		p.TLSClient = value
	case "verify-x509-name":
		p.VerifyX509 = value
	case "keepalive":
		p.Keepalive = value
	case "tls-version-min":
		p.TLSVersion = value
	}
}

// splitDirective splits an openvpn config line into its directive and value.
// The directive is the first whitespace-delimited token, lowercased; quotes are
// stripped from the value but a quoted argument may itself contain spaces.
func splitDirective(line string) (string, string) {
	i := strings.IndexAny(line, " \t")
	if i < 0 {
		return strings.ToLower(line), ""
	}
	key := strings.ToLower(strings.TrimSpace(line[:i]))
	return key, strings.TrimSpace(unquote(strings.TrimSpace(line[i:])))
}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

func parseRemote(value string) (string, int, error) {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return "", 0, fmt.Errorf("remote needs an address")
	}
	host := fields[0]
	port := 0
	if len(fields) > 1 {
		n, err := strconv.Atoi(fields[1])
		if err != nil || n <= 0 || n > 65535 {
			return "", 0, fmt.Errorf("invalid remote port %q", fields[1])
		}
		port = n
	}
	if strings.ContainsAny(host, " \t\"'") {
		return "", 0, fmt.Errorf("invalid remote host %q", host)
	}
	return host, port, nil
}

// parseUserPassPair parses the single-line form OpenVPN accepts:
// `auth-user-pass username:password`.
func parseUserPassPair(value string) (string, string, error) {
	user, pass, found := strings.Cut(value, ":")
	if !found || user == "" {
		return "", "", fmt.Errorf("auth-user-pass must be \"username:password\"")
	}
	if strings.ContainsAny(user, "\r\n") || strings.ContainsAny(pass, "\r\n") {
		return "", "", fmt.Errorf("auth-user-pass contains a newline")
	}
	return user, pass, nil
}

// collectInlineBlocks extracts the <tag>…</tag> PEM bodies from a profile.
func collectInlineBlocks(raw string) map[string]string {
	out := map[string]string{}
	for _, tag := range []string{"ca", "cert", "key", "tls-auth"} {
		start := "<" + tag + ">"
		end := "</" + tag + ">"
		i := strings.Index(raw, start)
		if i < 0 {
			continue
		}
		j := strings.Index(raw[i:], end)
		if j < 0 {
			continue
		}
		out[tag] = raw[i+len(start) : i+j]
	}
	return out
}

// redactLine strips anything that looks like credentials from a rejected line
// before it is put in an error message, so a validation failure cannot echo a
// password back into logs or the API response.
func redactLine(line string) string {
	lower := strings.ToLower(line)
	for _, key := range []string{"auth-user-pass", "askpass"} {
		if strings.HasPrefix(lower, key) {
			return key + " <redacted>"
		}
	}
	return line
}

// ValidSubnet reports whether s is an IPv4 or IPv6 network in CIDR form.
func ValidSubnet(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if strings.Contains(s, "/") {
		if _, _, err := net.ParseCIDR(s); err != nil {
			return false
		}
		return true
	}
	ip := net.ParseIP(s)
	return ip != nil
}

// ValidHost reports whether s is a usable hostname or IP literal.
func ValidHost(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if net.ParseIP(s) != nil {
		return true
	}
	if len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, r := range label {
			isAlnum := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
			if !isAlnum && r != '-' {
				return false
			}
		}
	}
	return true
}
