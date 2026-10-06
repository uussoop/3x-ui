package service

import (
	"strings"
	"testing"
)

// A template with no exits is the normal case for a panel that only runs
// inbounds. Deriving must report "none", not fail — otherwise the reconcile job
// logs a warning every tick on every ordinary install.
func TestVPNExitsFromTemplateWithNoExits(t *testing.T) {
	for _, template := range []string{
		"",
		`{}`,
		`{"outbounds":[]}`,
		`{"outbounds":[{"protocol":"freedom","tag":"direct"},{"protocol":"vless","tag":"proxy"}]}`,
	} {
		if got, err := OpenVPNExitsFromTemplate(template); err != nil || len(got) != 0 {
			t.Errorf("openvpn: template %q gave %v, %v; want no exits and no error", template, got, err)
		}
		if got, err := IKEv2ExitsFromTemplate(template); err != nil || len(got) != 0 {
			t.Errorf("ikev2: template %q gave %v, %v; want no exits and no error", template, got, err)
		}
	}
}

func TestOpenVPNExitsFromTemplateDerivesEachExit(t *testing.T) {
	template := `{"outbounds":[
		{"protocol":"freedom","tag":"direct"},
		{"protocol":"openvpn","tag":"exit-de","settings":{"remote":"vpn.example.com","port":1194,"ca":"CA-PEM","authUserPass":"alice\ns3cret"}},
		{"protocol":"openvpn","tag":"exit-nl","settings":{"remote":"vpn.example.nl","ca":"CA-PEM"}}
	]}`
	exits, err := OpenVPNExitsFromTemplate(template)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(exits) != 2 {
		t.Fatalf("exits = %d, want 2", len(exits))
	}
	// Order is the template's order so a config change that only reorders exits
	// produces a stable reconcile rather than a spurious restart of both.
	if exits[0].Tag != "exit-de" || exits[1].Tag != "exit-nl" {
		t.Errorf("exit order = %q, %q; want the template's order", exits[0].Tag, exits[1].Tag)
	}
	if exits[0].Username != "alice" || exits[0].Password != "s3cret" {
		t.Errorf("exit-de credentials = %q/%q, want alice/s3cret", exits[0].Username, exits[0].Password)
	}
	// Two exits must get two devices, or the second would send its traffic down
	// the first one's tunnel.
	if exits[0].Dev == exits[1].Dev {
		t.Errorf("both exits were given device %q", exits[0].Dev)
	}
}

// An exit the panel cannot run is a configuration error the operator has to see.
// Silently omitting it would leave the outbound in the template with nothing
// behind it — traffic routed to a tag whose tunnel does not exist.
func TestOpenVPNExitsFromTemplateRefusesBrokenExits(t *testing.T) {
	tests := []struct {
		name     string
		template string
		want     string
	}{
		{
			name:     "no tag",
			template: `{"outbounds":[{"protocol":"openvpn","settings":{"remote":"vpn.example.com","ca":"CA"}}]}`,
			want:     "tag",
		},
		{
			name:     "duplicate tag",
			template: `{"outbounds":[{"protocol":"openvpn","tag":"exit-de","settings":{"remote":"vpn.example.com","ca":"CA"}},{"protocol":"openvpn","tag":"exit-de","settings":{"remote":"vpn.example.nl","ca":"CA"}}]}`,
			want:     "twice",
		},
		{
			name:     "no CA",
			template: `{"outbounds":[{"protocol":"openvpn","tag":"exit-de","settings":{"remote":"vpn.example.com"}}]}`,
			want:     "not a usable exit",
		},
		{
			name:     "no remote",
			template: `{"outbounds":[{"protocol":"openvpn","tag":"exit-de","settings":{"ca":"CA"}}]}`,
			want:     "not a usable exit",
		},
		{
			name:     "profile that runs a program",
			template: `{"outbounds":[{"protocol":"openvpn","tag":"exit-de","settings":{"config":"client\nup /tmp/pwn\n"}}]}`,
			want:     "not a usable exit",
		},
		{
			name:     "malformed template",
			template: `{"outbounds":`,
			want:     "unexpected end",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			exits, err := OpenVPNExitsFromTemplate(tc.template)
			if err == nil {
				t.Fatalf("a broken exit was accepted: %+v", exits)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
			// Whatever the reason, no partial set may escape: a half-applied
			// reconcile would tear down tunnels that were working.
			if len(exits) != 0 {
				t.Errorf("a refused template still produced %d exits", len(exits))
			}
		})
	}
}

func TestIKEv2ExitsFromTemplateDerivesEachExit(t *testing.T) {
	template := `{"outbounds":[
		{"protocol":"freedom","tag":"direct"},
		{"protocol":"ikev2","tag":"exit-de","settings":{"remote":"vpn.example.com","username":"alice","password":"s3cret","caCert":"CA-PEM"}}
	]}`
	exits, err := IKEv2ExitsFromTemplate(template)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(exits) != 1 {
		t.Fatalf("exits = %d, want 1", len(exits))
	}
	if exits[0].Tag != "exit-de" || exits[0].Remote != "vpn.example.com" {
		t.Errorf("exit = %+v", exits[0])
	}
	if exits[0].Username != "alice" || exits[0].Password != "s3cret" {
		t.Errorf("exit credentials = %q/%q, want alice/s3cret", exits[0].Username, exits[0].Password)
	}
}

func TestIKEv2ExitsFromTemplateRefusesBrokenExits(t *testing.T) {
	tests := []struct {
		name     string
		template string
		want     string
	}{
		{
			name:     "no tag",
			template: `{"outbounds":[{"protocol":"ikev2","settings":{"remote":"vpn.example.com"}}]}`,
			want:     "tag",
		},
		{
			name:     "duplicate tag",
			template: `{"outbounds":[{"protocol":"ikev2","tag":"exit-de","settings":{"remote":"a.example.com"}},{"protocol":"ikev2","tag":"exit-de","settings":{"remote":"b.example.com"}}]}`,
			want:     "twice",
		},
		{
			name:     "no remote",
			template: `{"outbounds":[{"protocol":"ikev2","tag":"exit-de","settings":{"username":"a","password":"b"}}]}`,
			want:     "not a usable exit",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			exits, err := IKEv2ExitsFromTemplate(tc.template)
			if err == nil {
				t.Fatalf("a broken exit was accepted: %+v", exits)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
			if len(exits) != 0 {
				t.Errorf("a refused template still produced %d exits", len(exits))
			}
		})
	}
}

// Both protocols read the same template, so a template carrying exits of both
// kinds must yield exits of both kinds and neither derivation may claim the
// other's entries.
func TestVPNExitsFromTemplateKeepsTheProtocolsApart(t *testing.T) {
	template := `{"outbounds":[
		{"protocol":"openvpn","tag":"exit-ovpn","settings":{"remote":"a.example.com","ca":"CA"}},
		{"protocol":"ikev2","tag":"exit-ike","settings":{"remote":"b.example.com"}}
	]}`
	ovpn, err := OpenVPNExitsFromTemplate(template)
	if err != nil {
		t.Fatalf("openvpn derive: %v", err)
	}
	ike, err := IKEv2ExitsFromTemplate(template)
	if err != nil {
		t.Fatalf("ikev2 derive: %v", err)
	}
	if len(ovpn) != 1 || ovpn[0].Tag != "exit-ovpn" {
		t.Errorf("openvpn derived %+v, want only exit-ovpn", ovpn)
	}
	if len(ike) != 1 || ike[0].Tag != "exit-ike" {
		t.Errorf("ikev2 derived %+v, want only exit-ike", ike)
	}
	// Distinct id spaces, so the two protocols can key their managers
	// independently even when the same tag appears in both.
	if ovpn[0].ID == ike[0].ID {
		t.Errorf("both exits derived id %d; the id must be protocol-specific", ovpn[0].ID)
	}
}