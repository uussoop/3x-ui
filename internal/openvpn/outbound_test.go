package openvpn

import (
	"encoding/json"
	"strings"
	"testing"
)

// exitRaw builds a template outbound the way the UI writes one.
func exitRaw(tag string, settings map[string]any) []byte {
	if settings == nil {
		settings = map[string]any{}
	}
	bs, err := json.Marshal(map[string]any{
		"tag":      tag,
		"protocol": "openvpn",
		"settings": settings,
	})
	if err != nil {
		panic(err)
	}
	return bs
}

func TestIsOpenVPNOutboundMatchesOnlyItsOwnProtocol(t *testing.T) {
	if !IsOpenVPNOutbound(exitRaw("exit-de", nil)) {
		t.Error("an openvpn outbound was not recognised")
	}
	// Case-insensitive: the core lowercases protocols, and the panel must not
	// depend on how a hand-edited template happens to be capitalised.
	if !IsOpenVPNOutbound([]byte(`{"tag":"x","protocol":"OpenVPN"}`)) {
		t.Error("protocol matching is case-sensitive")
	}
	for _, raw := range [][]byte{
		[]byte(`{"tag":"x","protocol":"vless"}`),
		[]byte(`{"tag":"x","protocol":"amneziawg"}`),
		[]byte(`{"tag":"x"}`),
		[]byte(`not json`),
	} {
		if IsOpenVPNOutbound(raw) {
			t.Errorf("%s was mistaken for an openvpn outbound", raw)
		}
	}
}

func TestInstanceFromOutboundDerivesAUsableExit(t *testing.T) {
	inst, ok := InstanceFromOutbound("exit-de", exitRaw("exit-de", map[string]any{
		"remote":   "vpn.example.com",
		"port":     1194,
		"proto":    "udp",
		"cipher":   "AES-256-GCM",
		"auth":     "SHA256",
		"ca":       "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
		"cert":     "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----",
		"key":      "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----",
		"verb":     3,
		"authUserPass": "alice\ns3cret",
	}))
	if !ok {
		t.Fatalf("a complete exit was rejected: %v", inst.Validate())
	}
	if inst.Role != "client" {
		t.Errorf("role = %q, want client", inst.Role)
	}
	if inst.Tag != "exit-de" {
		t.Errorf("tag = %q, want exit-de", inst.Tag)
	}
	if inst.Remote != "vpn.example.com" || inst.RemotePort != 1194 {
		t.Errorf("endpoint = %s:%d, want vpn.example.com:1194", inst.Remote, inst.RemotePort)
	}
	// The exit must carry the panel's account, not just the remote endpoint: the
	// credential pair is how the panel keeps one identity per client.
	if inst.Username != "alice" || inst.Password != "s3cret" {
		t.Errorf("credentials = %q/%q, want alice/s3cret", inst.Username, inst.Password)
	}
	if inst.CA == "" || inst.Cert == "" || inst.Key == "" {
		t.Error("the exit lost its certificate material")
	}
	if inst.ID != OutboundID("exit-de") {
		t.Errorf("id = %d, want the id derived from the tag (%d)", inst.ID, OutboundID("exit-de"))
	}
}

func TestInstanceFromOutboundRefusesUnusableExits(t *testing.T) {
	tests := []struct {
		name     string
		tag      string
		settings map[string]any
		raw      []byte
		want     string
	}{
		{
			name: "no remote endpoint",
			tag:  "exit-no-remote",
			// A CA with nothing to connect to would produce a tunnel that can
			// never come up.
			settings: map[string]any{"ca": "CA-PEM"},
			want:     "remote",
		},
		{
			name:     "no CA means any server certificate is accepted",
			tag:      "exit-no-ca",
			settings: map[string]any{"remote": "vpn.example.com", "port": 1194},
			want:     "CA",
		},
		{
			name: "imported profile that runs a program",
			tag:  "exit-evil-profile",
			settings: map[string]any{
				"config": "client\nnobind\nup /tmp/pwn.sh\n",
			},
			want: "up",
		},
		{
			name:     "empty tag",
			tag:      "  ",
			settings: map[string]any{"remote": "vpn.example.com", "ca": "CA-PEM"},
			want:     "",
		},
		{
			name: "remote port out of range",
			tag:  "exit-bad-port",
			settings: map[string]any{
				"remote": "vpn.example.com",
				"port":   70000,
				"ca":     "CA-PEM",
			},
			want: "port",
		},
		{
			name: "probe target is not host:port",
			tag:  "exit-bad-probe",
			settings: map[string]any{
				"remote":      "vpn.example.com",
				"ca":          "CA-PEM",
				"probeTarget": "https://example.com/health",
			},
			want: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := tc.raw
			if raw == nil {
				raw = exitRaw(tc.tag, tc.settings)
			}
			inst, ok := InstanceFromOutbound(tc.tag, raw)
			if ok {
				t.Fatalf("an unusable exit was accepted: %+v", inst)
			}
			if tc.want != "" {
				// The refusal must name the reason; an operator has no way to
				// find a silent skip.
				err := inst.Validate()
				if err == nil {
					t.Fatal("rejected without a reason")
				}
				if tc.name == "imported profile that runs a program" {
					// The profile itself is rejected by the allowlist, not by
					// Validate, so the message comes from parsing.
					if _, perr := ParseProfile(tc.settings["config"].(string)); perr == nil {
						t.Error("a profile with an execution directive was accepted by the allowlist")
					}
					return
				}
				if !strings.Contains(err.Error(), tc.want) {
					t.Errorf("refusal %q does not mention %q", err, tc.want)
				}
			}
		})
	}
}

func TestOutboundIDIsStableBoundedAndNegative(t *testing.T) {
	// The id ends up in a management port, so it has to stay inside the valid
	// port range however large the hash is.
	for _, tag := range []string{"a", "exit-de", "some.very.long.tag.with.dots", strings.Repeat("x", 300)} {
		id := OutboundID(tag)
		if id >= 0 {
			t.Errorf("tag %q produced id %d; exits must not share an inbound's id space", tag, id)
		}
		if id < -50000 {
			t.Errorf("tag %q produced id %d, outside the range the management port derivation supports", tag, id)
		}
		if again := OutboundID(tag); again != id {
			t.Errorf("tag %q produced %d then %d; the id must be stable across restarts", tag, id, again)
		}
		if port := (Instance{ID: id}).managementPort(); port < 1024 || port > 65535 {
			t.Errorf("tag %q derives management port %d, which is not usable", tag, port)
		}
	}
}

func TestOutboundIDUniqueRefusesCollidingTags(t *testing.T) {
	// Distinct tags must normally map to distinct ids, and the whole set is what
	// the reconcile uses, so the ordinary path has to work.
	tags := []string{"exit-de", "exit-nl", "exit-us", "exit-tr"}
	ids, clashes, err := OutboundIDUnique(tags)
	if err != nil {
		t.Fatalf("distinct tags reported a collision: %v", err)
	}
	if len(clashes) != 0 {
		t.Fatalf("distinct tags reported clashes: %v", clashes)
	}
	seen := map[int]string{}
	for _, tag := range tags {
		if other, dup := seen[ids[tag]]; dup {
			t.Errorf("%q and %q share id %d", other, tag, ids[tag])
		}
		seen[ids[tag]] = tag
	}

	// A duplicated tag is itself a collision and must be reported, not silently
	// deduplicated: the same tag twice in a template would make one tunnel's
	// device serve the other.
	if _, _, err := OutboundIDUnique([]string{"exit-de", "exit-de"}); err == nil {
		t.Error("a duplicated tag was accepted")
	}
}

func TestBuildDeviceBridgePinsTheExitToItsTunnelDevice(t *testing.T) {
	raw := exitRaw("exit-de", map[string]any{
		"remote": "vpn.example.com",
		"ca":     "CA-PEM",
	})
	replacement, ok := BuildDeviceBridge("exit-de", raw)
	if !ok {
		t.Fatal("a complete exit was not bridgeable")
	}
	var got struct {
		Tag      string `json:"tag"`
		Protocol string `json:"protocol"`
		Stream   struct {
			Sockopt struct {
				Interface string `json:"interface"`
			} `json:"sockopt"`
		} `json:"streamSettings"`
	}
	if err := json.Unmarshal(replacement, &got); err != nil {
		t.Fatalf("replacement is not valid JSON: %v", err)
	}
	// The tag has to survive: routing rules and balancers name outbounds by tag,
	// so losing it would silently drop the exit out of every rule that used it.
	if got.Tag != "exit-de" {
		t.Errorf("tag = %q, want exit-de", got.Tag)
	}
	if got.Protocol != "freedom" {
		t.Errorf("protocol = %q, want freedom", got.Protocol)
	}
	// The pin is the entire safety argument: an unbound freedom outbound would
	// fall back to the real uplink exactly when the tunnel is down.
	want := ExitDev(OutboundID("exit-de"))
	if got.Stream.Sockopt.Interface != want {
		t.Errorf("sockopt.interface = %q, want the exit's device %q", got.Stream.Sockopt.Interface, want)
	}
	// The bridge must not carry the credentials it replaced them for.
	if strings.Contains(string(replacement), "CA-PEM") || strings.Contains(string(replacement), "authUserPass") {
		t.Errorf("the replacement leaked the exit's settings: %s", replacement)
	}
}

func TestBuildDeviceBridgeHonoursAnExplicitDevice(t *testing.T) {
	// An operator who names the device knows what the host looks like; the panel
	// must not overwrite it with its own name and point at nothing.
	raw := exitRaw("exit-custom", map[string]any{
		"remote": "vpn.example.com",
		"ca":     "CA-PEM",
		"dev":    "vpn0",
	})
	replacement, ok := BuildDeviceBridge("exit-custom", raw)
	if !ok {
		t.Fatal("a complete exit was not bridgeable")
	}
	if !strings.Contains(string(replacement), `"interface":"vpn0"`) {
		t.Errorf("an operator-chosen device was not used: %s", replacement)
	}
}

func TestBuildDeviceBridgeRejectsUntaggedEntries(t *testing.T) {
	// Without a tag the replacement could not be addressed by any routing rule,
	// so the entry cannot be bridged and must not be silently rewritten into an
	// unreachable outbound.
	if _, ok := BuildDeviceBridge("", exitRaw("", nil)); ok {
		t.Error("an untagged exit was bridged")
	}
	if _, ok := BuildDeviceBridge("", []byte(`{"protocol":"openvpn"}`)); ok {
		t.Error("a settings-less exit was bridged")
	}
}

func TestDevNameIsDeterministicAndNotOpenvpnsDefault(t *testing.T) {
	// "tun" means "pick the next free tunN", which nothing can bind to by name.
	// A stored config from before this rule must still resolve to a real name.
	for _, inst := range []Instance{
		{ID: 7, Role: "server"},
		{ID: -4242, Role: "client"},
		{ID: -4242, Role: "client", Dev: "tun"},
		{ID: -4242, Role: "client", Dev: "tap"},
		{ID: -4242, Role: "client", Dev: " tun "},
	} {
		got := inst.devName()
		if got == "tun" || got == "tap" || got == "" {
			t.Errorf("instance %+v resolved to device %q, which cannot be bound by name", inst, got)
		}
	}
	if a, b := (Instance{ID: 7, Role: "server"}).devName(), ServerDev(7); a != b {
		t.Errorf("server device = %q, want %q", a, b)
	}
	if a, b := (Instance{ID: -9, Role: "client"}).devName(), ExitDev(-9); a != b {
		t.Errorf("exit device = %q, want %q", a, b)
	}
	// Two tunnels must never be told to share one device.
	if ServerDev(1) == ExitDev(-1) {
		t.Error("a server and an exit were given the same device name")
	}
	if ServerDev(1) == ServerDev(2) {
		t.Error("two servers were given the same device name")
	}
}

func TestExitAndServerPathsAndPortsCannotCollide(t *testing.T) {
	server := Instance{ID: 3, Role: "server"}
	exit := Instance{ID: -3, Role: "client"}
	if configPathForID(server.ID) == configPathForID(exit.ID) {
		t.Errorf("an inbound and an exit share the config path %q", configPathForID(server.ID))
	}
	if server.managementPort() == exit.managementPort() {
		t.Errorf("an inbound and an exit share management port %d", server.managementPort())
	}
	if server.dir() == exit.dir() {
		t.Errorf("an inbound and an exit share the secrets directory %q", server.dir())
	}
}