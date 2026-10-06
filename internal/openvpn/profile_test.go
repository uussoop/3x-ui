package openvpn

import (
	"strings"
	"testing"
)

const testCA = `-----BEGIN CERTIFICATE-----
MIIBfake
-----END CERTIFICATE-----`

// A profile that must be accepted: an ordinary exported client config with the
// certificate inline, which is how virtually every provider ships one.
const goodProfile = `client
dev tun
proto udp
remote vpn.example.com 1194
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-GCM
auth SHA512
verb 3
<ca>
` + testCA + `
</ca>
<cert>
-----BEGIN CERTIFICATE-----
MIICfake
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
MIIfake
-----END PRIVATE KEY-----
</key>`

func TestParseProfileAcceptsOrdinaryProfile(t *testing.T) {
	p, err := ParseProfile(goodProfile)
	if err != nil {
		t.Fatalf("ParseProfile: %v", err)
	}
	if p.Remote != "vpn.example.com" {
		t.Errorf("remote = %q, want vpn.example.com", p.Remote)
	}
	if p.RemotePort != 1194 {
		t.Errorf("port = %d, want 1194", p.RemotePort)
	}
	if p.Proto != "udp" {
		t.Errorf("proto = %q, want udp", p.Proto)
	}
	if !strings.Contains(p.CA, "BEGIN CERTIFICATE") {
		t.Errorf("CA not parsed from inline block: %q", p.CA)
	}
	if !strings.Contains(p.Cert, "BEGIN CERTIFICATE") {
		t.Errorf("cert not parsed from inline block")
	}
	if !strings.Contains(p.Key, "BEGIN PRIVATE KEY") {
		t.Errorf("key not parsed from inline block")
	}
}

// The core security property: an imported profile that would execute something
// is rejected outright rather than filtered, because the panel would otherwise
// hand attacker-chosen strings to a privileged process.
func TestParseProfileRejectsExecutionDirectives(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantSub string
	}{
		{"up", "up /tmp/evil.sh", "up"},
		{"down", "down /tmp/evil.sh", "down"},
		{"route-up", "route-up /tmp/evil.sh", "route-up"},
		{"ipchange", "ipchange /tmp/evil.sh", "ipchange"},
		{"client-connect", "client-connect /tmp/evil.sh", "client-connect"},
		{"auth-user-pass-verify", "auth-user-pass-verify /tmp/evil.sh via-file", "auth-user-pass-verify"},
		{"plugin", "plugin /tmp/evil.so", "plugin"},
		{"script-security", "script-security 2", "script-security"},
		{"management", "management 0.0.0.0 7505", "management"},
		{"setenv", "setenv OPENSSL_CONF /tmp/evil.cnf", "setenv"},
		{"daemon", "daemon", "daemon"},
		{"chroot", "chroot /tmp", "chroot"},
		{"iproute", "iproute /tmp/evil.sh", "iproute"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			profile := goodProfile + "\n" + tc.line
			_, err := ParseProfile(profile)
			if err == nil {
				t.Fatalf("ParseProfile accepted %q; it must be rejected", tc.line)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q does not name the offending directive %q", err, tc.wantSub)
			}
		})
	}
}

// Rejection must be case-insensitive: OpenVPN accepts directives in any case,
// so a filter keyed on lowercase only would be trivially bypassed.
func TestParseProfileRejectsUppercaseExecutionDirective(t *testing.T) {
	if _, err := ParseProfile(goodProfile + "\nUP /tmp/evil.sh"); err == nil {
		t.Fatal("uppercase UP was accepted; directive matching is case-sensitive")
	}
}

func TestParseProfileRequiresCA(t *testing.T) {
	// A tunnel with no pinned CA accepts any server certificate, so an exit
	// built from this profile would be interceptable.
	profile := strings.Replace(goodProfile, "<ca>\n"+testCA+"\n</ca>\n", "", 1)
	if _, err := ParseProfile(profile); err == nil {
		t.Fatal("profile without a CA was accepted")
	}
}

func TestParseProfileRequiresRemote(t *testing.T) {
	profile := "client\ndev tun\n<ca>\n" + testCA + "\n</ca>\n"
	if _, err := ParseProfile(profile); err == nil {
		t.Fatal("profile without a remote was accepted")
	}
}

// A profile pointing at a certificate file cannot work, because an .ovpn paste
// does not carry the file's contents. Accepting it would produce a tunnel that
// silently fails to verify its server.
func TestParseProfileRejectsFileReference(t *testing.T) {
	profile := goodProfile + "\nremote-cert-tls server\n"
	profile = strings.Replace(profile, "cipher AES-256-GCM", "cipher AES-256-GCM\nextra-tls-verify /etc/openvpn/extra.pem", 1)
	// extra-tls-verify is not on the allowlist, so it is dropped rather than
	// rejected — the profile still parses. What matters is that a *known*
	// certificate directive referencing a file is refused.
	profile2 := strings.Replace(goodProfile, "<ca>\n"+testCA+"\n</ca>\n", "ca /etc/openvpn/ca.crt\n", 1)
	if _, err := ParseProfile(profile2); err == nil {
		t.Fatal("profile referencing ca by file path was accepted")
	}
	_ = profile
}

func TestParseProfileInlineUserPass(t *testing.T) {
	p, err := ParseProfile(goodProfile + "\nauth-user-pass alice:s3cret")
	if err != nil {
		t.Fatalf("ParseProfile: %v", err)
	}
	if !p.AuthUserPass {
		t.Error("AuthUserPass = false, want true")
	}
	if p.Username != "alice" || p.Password != "s3cret" {
		t.Errorf("credentials = %q/%q, want alice/s3cret", p.Username, p.Password)
	}
}

func TestParseProfileRejectsMalformedUserPass(t *testing.T) {
	if _, err := ParseProfile(goodProfile + "\nauth-user-pass nocolon"); err == nil {
		t.Fatal("auth-user-pass without a colon was accepted")
	}
}

func TestParseProfileRejectsEmpty(t *testing.T) {
	if _, err := ParseProfile("   \n\n  "); err == nil {
		t.Fatal("empty profile was accepted")
	}
}

// A line that is not a directive is dropped, not fatal. The panel generates its
// own config from an allowlist rather than passing a profile through, so a stray
// line cannot reach openvpn — but it must not be able to make a profile that
// lost its endpoint look usable either.
func TestParseProfileDropsNonDirectiveLine(t *testing.T) {
	if _, err := ParseProfile(goodProfile + "\njust some prose"); err != nil {
		t.Fatalf("a stray line made the profile unusable: %v", err)
	}

	// A mistyped endpoint is caught rather than quietly producing a tunnel that
	// has no remote at all.
	typo := strings.Replace(goodProfile, "remote vpn.example.com 1194", "remtoe vpn.example.com 1194", 1)
	if _, err := ParseProfile(typo); err == nil {
		t.Fatal("a profile whose only remote is misspelled was accepted")
	}
}

// A first-remote-wins rule keeps the panel pinned to the server the operator
// chose, rather than silently failing over to a different one.
func TestParseProfileUsesFirstRemote(t *testing.T) {
	profile := "client\nremote first.example.com 1194\nremote second.example.com 443\n<ca>\n" + testCA + "\n</ca>\n"
	p, err := ParseProfile(profile)
	if err != nil {
		t.Fatalf("ParseProfile: %v", err)
	}
	if p.Remote != "first.example.com" || p.RemotePort != 1194 {
		t.Errorf("remote = %s:%d, want first.example.com:1194", p.Remote, p.RemotePort)
	}
}

func TestParseProfilePortOverridesRemote(t *testing.T) {
	profile := "client\nremote vpn.example.com 1194\nport 443\n<ca>\n" + testCA + "\n</ca>\n"
	p, err := ParseProfile(profile)
	if err != nil {
		t.Fatalf("ParseProfile: %v", err)
	}
	if p.RemotePort != 443 {
		t.Errorf("port = %d, want 443", p.RemotePort)
	}
}

func TestParseProfileProtoVariants(t *testing.T) {
	for _, in := range []string{"tcp", "tcp-client", "tcp4", "udp", "udp4"} {
		profile := "client\nremote vpn.example.com 1194\nproto " + in + "\n<ca>\n" + testCA + "\n</ca>\n"
		p, err := ParseProfile(profile)
		if err != nil {
			t.Fatalf("proto %q: %v", in, err)
		}
		if p.Proto != "tcp" && p.Proto != "udp" {
			t.Errorf("proto %q normalised to %q", in, p.Proto)
		}
	}
	if _, err := ParseProfile("client\nremote v.example.com 1\nproto sctp\n<ca>\n" + testCA + "\n</ca>\n"); err == nil {
		t.Fatal("unsupported proto was accepted")
	}
}

// Comments are common in exported profiles and must not be mistaken for
// directives.
func TestParseProfileIgnoresComments(t *testing.T) {
	profile := "# a comment\n; another comment\n" + goodProfile
	if _, err := ParseProfile(profile); err != nil {
		t.Fatalf("ParseProfile with comments: %v", err)
	}
}

// An unknown directive is dropped, not fatal: real-world profiles carry options
// the panel has no opinion about, and refusing them would make them
// unimportable for cosmetic reasons. Dropping is safe because only the
// allowlist affects behaviour.
func TestParseProfileDropsUnknownDirective(t *testing.T) {
	profile := goodProfile + "\nsome-future-option value\nfloat\n"
	p, err := ParseProfile(profile)
	if err != nil {
		t.Fatalf("ParseProfile: %v", err)
	}
	if !p.Float {
		t.Error("allowlisted `float` was not honoured")
	}
}