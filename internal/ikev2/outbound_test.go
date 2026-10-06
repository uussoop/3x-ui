package ikev2

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/vpn"
)

// ikeExitRaw builds a template outbound the way the UI writes one.
func ikeExitRaw(tag string, settings map[string]any) []byte {
	if settings == nil {
		settings = map[string]any{}
	}
	bs, err := json.Marshal(map[string]any{
		"tag":      tag,
		"protocol": "ikev2",
		"settings": settings,
	})
	if err != nil {
		panic(err)
	}
	return bs
}

func TestIsIKEv2OutboundMatchesOnlyItsOwnProtocol(t *testing.T) {
	if !IsIKEv2Outbound(ikeExitRaw("exit-de", nil)) {
		t.Error("an ikev2 outbound was not recognised")
	}
	if !IsIKEv2Outbound([]byte(`{"tag":"x","protocol":"IKEv2"}`)) {
		t.Error("protocol matching is case-sensitive")
	}
	for _, raw := range [][]byte{
		[]byte(`{"tag":"x","protocol":"openvpn"}`),
		[]byte(`{"tag":"x","protocol":"vless"}`),
		[]byte(`{"tag":"x"}`),
		[]byte(`not json`),
	} {
		if IsIKEv2Outbound(raw) {
			t.Errorf("%s was mistaken for an ikev2 outbound", raw)
		}
	}
}

func TestInstanceFromOutboundDerivesAUsableExit(t *testing.T) {
	inst, ok := InstanceFromOutbound("ike-exit-de", ikeExitRaw("ike-exit-de", map[string]any{
		"remote":     "vpn.example.com",
		"port":       500,
		"username":   "alice",
		"password":   "s3cret",
		"authMethod": "eap-mschapv2",
		"caCert":     "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
	}))
	if !ok {
		t.Fatalf("a complete exit was rejected: %v", inst.Validate())
	}
	if inst.Role != vpn.RoleClient {
		t.Errorf("role = %q, want %q", inst.Role, vpn.RoleClient)
	}
	if inst.Tag != "ike-exit-de" {
		t.Errorf("tag = %q, want ike-exit-de", inst.Tag)
	}
	if inst.Remote != "vpn.example.com" || inst.RemotePort != 500 {
		t.Errorf("endpoint = %s:%d, want vpn.example.com:500", inst.Remote, inst.RemotePort)
	}
	if inst.Username != "alice" || inst.Password != "s3cret" {
		t.Errorf("credentials = %q/%q, want alice/s3cret", inst.Username, inst.Password)
	}
	if inst.CA == "" {
		t.Error("the exit lost its trust anchor")
	}
	// An IKEv2 exit is only distinguishable from another by its kernel identity;
	// a shared one would let one exit's teardown remove the other's policies.
	if inst.Identity == "" {
		t.Error("the exit has no IKE identity")
	}
	if inst.ReqID <= 0 {
		t.Errorf("reqid = %d, want a positive XFRM reqid", inst.ReqID)
	}
	if inst.ID != OutboundID("ike-exit-de") {
		t.Errorf("id = %d, want the id derived from the tag (%d)", inst.ID, OutboundID("ike-exit-de"))
	}
	// The probe must be pinned to this exit's own interface, otherwise the
	// measurement could be satisfied by the real uplink.
	if got := inst.probeDevice(); got != ExitDev(inst.ID) {
		t.Errorf("probe device = %q, want %q", got, ExitDev(inst.ID))
	}
}

func TestInstanceFromOutboundRefusesUnusableExits(t *testing.T) {
	tests := []struct {
		name     string
		tag      string
		settings map[string]any
	}{
		{"no remote endpoint", "ike-exit-none", map[string]any{"username": "a", "password": "b"}},
		{"remote port out of range", "ike-exit-port", map[string]any{
			"remote": "vpn.example.com", "port": 70000, "username": "a", "password": "b",
		}},
		{"probe target is not host:port", "ike-exit-probe", map[string]any{
			"remote": "vpn.example.com", "username": "a", "password": "b",
			"probeTarget": "https://example.com/health",
		}},
		{"empty tag", "   ", map[string]any{
			"remote": "vpn.example.com", "username": "a", "password": "b",
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if inst, ok := InstanceFromOutbound(tc.tag, ikeExitRaw(tc.tag, tc.settings)); ok {
				t.Fatalf("an unusable exit was accepted: %+v", inst)
			}
		})
	}
}

func TestOutboundIDIsStableBoundedAndNegative(t *testing.T) {
	for _, tag := range []string{"a", "ike-exit-de", strings.Repeat("x", 300)} {
		id := OutboundID(tag)
		if id >= 0 {
			t.Errorf("tag %q produced id %d; exits must not share an inbound's id space", tag, id)
		}
		if id < -50000 {
			t.Errorf("tag %q produced id %d, outside the supported band", tag, id)
		}
		if again := OutboundID(tag); again != id {
			t.Errorf("tag %q produced %d then %d; the id must be stable across restarts", tag, id, again)
		}
	}
	if _, _, err := OutboundIDUnique([]string{"a", "a"}); err == nil {
		t.Error("a duplicated tag was accepted; two entries with one tag would share a kernel interface")
	}
	if _, clashes, err := OutboundIDUnique([]string{"ike-exit-de", "ike-exit-nl", "ike-exit-us"}); err != nil || len(clashes) != 0 {
		t.Errorf("distinct tags were reported as colliding: %v %v", clashes, err)
	}
}

func TestExitReqIDsCannotCollideWithInboundsOrEachOther(t *testing.T) {
	// Inbound and exit reqid bands must be disjoint: sharing one would let an
	// inbound's policies be matched against an exit's packets and torn down with
	// it.
	for id := 1; id <= 40; id++ {
		inbound := Instance{ID: id, Role: vpn.RoleServer}
		exit := Instance{ID: -id, Role: vpn.RoleClient}
		if reqID(inbound) == reqID(exit) {
			t.Fatalf("inbound %d and exit %d both use reqid %d", id, id, reqID(inbound))
		}
	}
	if reqIDFor(-5) == reqIDFor(5) {
		t.Fatalf("mirrored ids share reqid %d", reqIDFor(5))
	}
}

func TestBuildDeviceBridgePinsTheExitToItsInterface(t *testing.T) {
	raw := ikeExitRaw("ike-exit-de", map[string]any{
		"remote": "vpn.example.com",
	})
	replacement, ok := BuildDeviceBridge("ike-exit-de", raw)
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
	if got.Tag != "ike-exit-de" {
		t.Errorf("tag = %q, want ike-exit-de", got.Tag)
	}
	if got.Protocol != "freedom" {
		t.Errorf("protocol = %q, want freedom", got.Protocol)
	}
	want := ExitDev(OutboundID("ike-exit-de"))
	if got.Stream.Sockopt.Interface != want {
		t.Errorf("sockopt.interface = %q, want the exit's interface %q", got.Stream.Sockopt.Interface, want)
	}
	if strings.Contains(string(replacement), "vpn.example.com") || strings.Contains(string(replacement), "password") {
		t.Errorf("the replacement leaked the exit's settings: %s", replacement)
	}
	if _, ok := BuildDeviceBridge("", ikeExitRaw("", nil)); ok {
		t.Error("an untagged exit was bridged")
	}
}

func TestDevNameIsDeterministicAndPerTunnel(t *testing.T) {
	if got := (Instance{ID: 4, Role: vpn.RoleServer}).devName(); got != ServerDev(4) {
		t.Errorf("server interface = %q, want %q", got, ServerDev(4))
	}
	if got := (Instance{ID: -4, Role: vpn.RoleClient}).devName(); got != ExitDev(-4) {
		t.Errorf("exit interface = %q, want %q", got, ExitDev(-4))
	}
	// charon's default ipsecN is not something the panel can bind Xray to by
	// name, so the name must never be one the daemon picks itself.
	for _, dev := range []string{ServerDev(1), ExitDev(-1), ServerDev(2)} {
		if dev == "ipsec0" || dev == "" || dev == "tun0" {
			t.Errorf("interface %q is not a name the panel controls", dev)
		}
	}
}

func TestInstanceNameAndMarkerNameAreStableForExits(t *testing.T) {
	// An exit's connection name and on-disk marker must be derived the same way
	// across restarts: Start is idempotent precisely because the marker written
	// by an earlier panel process is still recognised by the next one.
	exit := Instance{ID: OutboundID("ike-exit-de"), Role: vpn.RoleClient}
	if a, b := exit.instanceName(), exit.instanceName(); a != b || a == "" {
		t.Errorf("connection name is not stable: %q vs %q", a, b)
	}
	if p, q := connConfPath(exit), connConfPath(exit); p != q || p == "" {
		t.Errorf("config path is not stable: %q vs %q", p, q)
	}
	if markerPath(exit) == connConfPath(exit) {
		t.Error("the idempotence marker and the config file are the same path, so writing the config would fake a loaded state")
	}
	server := Instance{ID: exit.ID * -1, Role: vpn.RoleServer}
	if connConfPath(exit) == connConfPath(server) {
		t.Error("an exit and an inbound share a config path")
	}
}