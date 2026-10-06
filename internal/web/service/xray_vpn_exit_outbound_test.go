package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/ikev2"
	"github.com/mhsanaei/3x-ui/v3/internal/openvpn"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

func parseOutboundsForTest(t *testing.T, cfg *xray.Config) []map[string]any {
	t.Helper()
	var out []map[string]any
	if err := json.Unmarshal(cfg.OutboundConfigs, &out); err != nil {
		t.Fatalf("generated outbounds are not valid JSON: %v", err)
	}
	return out
}

// exitConfig parses a template that mixes managed VPN exits with entries the core
// understands, which is the only shape that matters: the transform has to touch
// the exits and nothing else.
func exitConfig(t *testing.T) *xray.Config {
	t.Helper()
	cfg := &xray.Config{}
	raw := `{"outbounds":[
		{"protocol":"freedom","tag":"direct"},
		{"protocol":"openvpn","tag":"exit-de","settings":{"remote":"vpn.example.com","ca":"CA-PEM","authUserPass":"alice\ns3cret"}},
		{"protocol":"vless","tag":"proxy","settings":{}},
		{"protocol":"ikev2","tag":"exit-nl","settings":{"remote":"vpn.example.org","username":"bob","password":"hunter2"}}
	]}`
	if err := json.Unmarshal([]byte(raw), cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestTransformVPNExitOutboundsReplacesBothExitKinds(t *testing.T) {
	cfg := exitConfig(t)
	if err := transformVPNExitOutbounds(cfg); err != nil {
		t.Fatalf("transform: %v", err)
	}
	outbounds := parseOutboundsForTest(t, cfg)
	if len(outbounds) != 4 {
		t.Fatalf("outbound count = %d, want 4 (no additions or drops)", len(outbounds))
	}

	wantDev := map[string]string{
		"exit-de": openvpn.ExitDev(openvpn.OutboundID("exit-de")),
		"exit-nl": ikev2.ExitDev(ikev2.OutboundID("exit-nl")),
	}
	for _, ob := range outbounds {
		tag, _ := ob["tag"].(string)
		dev, isExit := wantDev[tag]
		if !isExit {
			// Everything the core already understands must survive untouched:
			// rewriting a vless outbound would break the proxy.
			if p, _ := ob["protocol"].(string); p == "freedom" || p == "vless" {
				continue
			}
			t.Errorf("unexpected outbound %+v", ob)
			continue
		}
		if p, _ := ob["protocol"].(string); p != "freedom" {
			t.Errorf("%s: protocol = %q, want freedom; the raw pseudo-protocol would be rejected by the core", tag, p)
		}
		stream, _ := ob["streamSettings"].(map[string]any)
		sockopt, _ := stream["sockopt"].(map[string]any)
		if got, _ := sockopt["interface"].(string); got != dev {
			t.Errorf("%s: sockopt.interface = %q, want %q", tag, got, dev)
		}
	}

	// The credentials and CA that made an exit tunnel work must not end up in
	// the config handed to the core: an unbound freedom outbound has no use for
	// them, and a config file is not a secret store.
	bs, err := json.Marshal(outbounds)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"CA-PEM", "s3cret", "hunter2", "authUserPass"} {
		if strings.Contains(string(bs), secret) {
			t.Errorf("the generated config still carries %q", secret)
		}
	}
}

func TestTransformVPNExitOutboundsLeavesPlainConfigsUntouched(t *testing.T) {
	cfg := &xray.Config{}
	if err := json.Unmarshal([]byte(`{"outbounds":[
		{"protocol":"freedom","tag":"direct"},
		{"protocol":"amneziawg","tag":"awg-hop","settings":{"secretKey":"x"}}
	]}`), cfg); err != nil {
		t.Fatal(err)
	}
	before := string(cfg.OutboundConfigs)
	if err := transformVPNExitOutbounds(cfg); err != nil {
		t.Fatalf("transform: %v", err)
	}
	if string(cfg.OutboundConfigs) != before {
		t.Error("a config with no VPN exits was rewritten")
	}

	// No outbounds at all must be a no-op rather than an error.
	empty := &xray.Config{}
	if err := transformVPNExitOutbounds(empty); err != nil {
		t.Fatalf("an empty config failed the transform: %v", err)
	}
}

// An untagged exit cannot be replaced by something addressable, and skipping it
// would leave the pseudo-protocol in the config for the core to reject. Failing
// generation names the problem; the alternative is a startup crash that says
// nothing about which outbound is at fault.
func TestTransformVPNExitOutboundsFailsOnAnUntaggedExit(t *testing.T) {
	cfg := &xray.Config{}
	if err := json.Unmarshal([]byte(`{"outbounds":[{"protocol":"openvpn","settings":{}}]}`), cfg); err != nil {
		t.Fatal(err)
	}
	err := transformVPNExitOutbounds(cfg)
	if err == nil {
		t.Fatal("an untagged exit was accepted")
	}
	if !strings.Contains(err.Error(), "tag") {
		t.Errorf("the failure does not mention the tag: %v", err)
	}
}

// The core folds the protocol id's case, so a hand-edited template spelling the
// protocol differently must bridge too or the raw entry reaches the core.
func TestTransformVPNExitOutboundsReadsTheProtocolIDLikeTheCore(t *testing.T) {
	for _, protocol := range []string{"openvpn", "OpenVPN", "IKEv2", "ikev2"} {
		t.Run(protocol, func(t *testing.T) {
			cfg := &xray.Config{}
			raw := `{"outbounds":[{"protocol":"` + protocol + `","tag":"exit-x","settings":{"remote":"vpn.example.com"}}]}`
			if err := json.Unmarshal([]byte(raw), cfg); err != nil {
				t.Fatal(err)
			}
			if err := transformVPNExitOutbounds(cfg); err != nil {
				t.Fatalf("transform: %v", err)
			}
			outbounds := parseOutboundsForTest(t, cfg)
			if p, _ := outbounds[0]["protocol"].(string); p != "freedom" {
				t.Fatalf("protocol = %q, want freedom; the bridge never ran", p)
			}
		})
	}
}

func TestVPNExitTagsListsOnlyManagedExits(t *testing.T) {
	// No template at all is not an error; it simply means no exits exist yet.
	if tags, err := VPNExitTags(""); err != nil || len(tags) != 0 {
		t.Fatalf("an empty template gave %v, %v", tags, err)
	}

	template := `{"outbounds":[
		{"protocol":"freedom","tag":"direct"},
		{"protocol":"openvpn","tag":"exit-de","settings":{"remote":"vpn.example.com","ca":"CA"}},
		{"protocol":"ikev2","tag":"exit-nl","settings":{"remote":"vpn.example.org"}},
		{"protocol":"vless","tag":"proxy"}
	]}`
	tags, err := VPNExitTags(template)
	if err != nil {
		t.Fatalf("VPNExitTags: %v", err)
	}
	want := []string{"exit-de", "exit-nl"}
	if len(tags) != len(want) {
		t.Fatalf("tags = %v, want %v", tags, want)
	}
	for i, tag := range want {
		if tags[i] != tag {
			t.Errorf("tag %d = %q, want %q", i, tags[i], tag)
		}
	}
}