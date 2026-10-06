package openvpn

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// leakExit builds a complete exit the way the outbound transform does, so the
// config under test is the one the panel would actually run.
func leakExit(t *testing.T) Instance {
	t.Helper()
	inst, ok := InstanceFromOutbound("exit-leak", exitRaw("exit-leak", map[string]any{
		"remote":       "vpn.example.com",
		"port":         1194,
		"proto":        "udp",
		"ca":           "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
		"authUserPass": "alice\ns3cret",
	}))
	if !ok {
		t.Fatalf("a complete exit was rejected: %v", inst.Validate())
	}
	return inst
}

// TestExitConfigLeavesNoAddressFamilyUnrouted is the leak test for the
// client-side tunnel. A tunnel that carries one half of the address space and
// ignores the other is a tunnel that leaks the ignored half: dual-stack hosts
// resolve and connect over whatever path still works, which for a privacy exit
// is exactly the wrong one.
func TestExitConfigLeavesNoAddressFamilyUnrouted(t *testing.T) {
	cfg := RenderClientConfig(leakExit(t), profileParams{})

	for _, want := range []string{
		// def1 installs 0.0.0.0/1 and 128.0.0.0/1, which between them cover
		// every IPv4 destination including the exit's own peer.
		"redirect-gateway def1",
		// block-ipv6 sends IPv6 into the tunnel and answers it with "no route
		// to host" there, rather than leaving a dual-stack host a working path
		// out its own interface. The panel cannot promise the peer carries
		// IPv6, so refusing is the correct outcome; sending it elsewhere is
		// not.
		"block-ipv6",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("exit config has no %q, so that traffic has no in-tunnel path:\n%s", want, cfg)
		}
	}

	// Any exception carved through the redirect is a destination traffic can
	// take instead of the tunnel. The generated config never asks for one, so
	// one appearing later would be a hole nobody intended.
	for _, hole := range []string{
		"\nroute ",
		"\nroute-ipv6 ",
		"\nroute-nopull",
		"pull-filter ignore \"redirect-gateway\"",
	} {
		if strings.Contains(cfg, hole) {
			t.Errorf("exit config carves out %q, which traffic could take instead of the tunnel:\n%s", hole, cfg)
		}
	}

	// The panel does not choose a resolver for the exit. Proxied domains are
	// resolved remotely by the core (routing keeps domainStrategy AsIs, so no
	// local query happens) and everything else the host resolves is carried by
	// the redirect above. Pointing the exit at a resolver would name a third
	// party the operator never selected, and a query that outlived the tunnel
	// would be a leak.
	for _, line := range strings.Split(cfg, "\n") {
		if strings.HasPrefix(line, "dhcp-option") ||
			strings.HasPrefix(line, "dns ") ||
			strings.HasPrefix(line, "dns-search ") {
			t.Errorf("exit config chooses a resolver (%q); the panel must not pick one:\n%s", line, cfg)
		}
	}
}

// TestServerPushesGatewayAndDNSInsideTheTunnel is the inbound-side half. What a
// connecting client receives has to arrive as a push — something the client
// can decline — and the panel must not invent a resolver it was never told
// about.
func TestServerPushesGatewayAndDNSInsideTheTunnel(t *testing.T) {
	srv := serverInstance()
	srv.DNSServer = "10.8.0.1"
	cfg := RenderServerConfig(srv)

	if !strings.Contains(cfg, `push "redirect-gateway def1"`) {
		t.Errorf("server does not redirect client traffic into the tunnel:\n%s", cfg)
	}
	if !strings.Contains(cfg, `push "dhcp-option DNS 10.8.0.1"`) {
		t.Errorf("server does not push the operator's DNS server:\n%s", cfg)
	}
	// A resolver directive that was not a push would rewrite the client's DNS
	// behind its back rather than offering it.
	for _, line := range strings.Split(cfg, "\n") {
		if strings.Contains(line, "dhcp-option") && !strings.HasPrefix(line, `push "`) {
			t.Errorf("server sets a resolver outside a push (%q):\n%s", line, cfg)
		}
	}

	// With no DNS server configured the panel pushes nothing instead of
	// choosing one of its own.
	if plain := RenderServerConfig(serverInstance()); strings.Contains(plain, "dhcp-option DNS") {
		t.Errorf("server invented a DNS server:\n%s", plain)
	}
}

// TestConfigFieldsCannotSmuggleDirectives covers the mechanism the two tests
// above depend on. A generated config is a list of directives, so a newline
// inside a value is an extra directive: a device name, a remote or a DNS
// server is exactly as good a place to hide `plugin` or `up` as a username is
// a place to hide an account. Validation is the gate — it runs before anything
// is rendered or spawned — so the refusal has to happen there, with a message
// that names the field.
func TestConfigFieldsCannotSmuggleDirectives(t *testing.T) {
	cleanServer := func() Instance {
		s := serverInstance()
		s.ID = 7001
		return s
	}
	cleanExit := func() Instance { return leakExit(t) }

	cases := []struct {
		name   string
		base   func() Instance
		mutate func(*Instance)
		want   string
	}{
		{"device", cleanServer, func(i *Instance) { i.Dev = "tun0\nup /bin/evil" }, "device"},
		{"dns server", cleanServer, func(i *Instance) { i.DNSServer = "10.8.0.1\nplugin /tmp/evil.so" }, "dns server"},
		{"remote", cleanExit, func(i *Instance) { i.Remote = "vpn.example.com\nup /bin/evil" }, "remote"},
		{"exit username", cleanExit, func(i *Instance) { i.Username = "alice\nmallory" }, "exit credentials"},
		{"exit password", cleanExit, func(i *Instance) { i.Password = "pw\nsecond-line" }, "exit credentials"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			procs := useFakeProcess(t)

			if err := tc.base().Validate(); err != nil {
				t.Fatalf("the untouched instance is already invalid: %v", err)
			}
			inst := tc.base()
			tc.mutate(&inst)

			err := inst.Validate()
			if err == nil {
				t.Fatalf("a %s carrying a newline was accepted; it would add a line to the generated files", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to name the %s", err, tc.want)
			}

			m := &Manager{adapters: map[int]*adapter{}}
			if err := m.Ensure(inst); err == nil {
				t.Error("Ensure accepted an instance whose config would carry an extra directive")
			}
			if got := procs.starts(); got != 0 {
				t.Errorf("%d start attempts reached the daemon for a refused configuration", got)
			}
			// Nothing may be on disk either: a config or credential file left
			// behind by a refused instance would be picked up by the next
			// daemon start, long after the refusal was forgotten.
			for _, path := range []string{
				configPathForID(inst.ID),
				inst.authFile(),
				filepath.Join(inst.clientDir(), "auth.txt"),
			} {
				if _, statErr := os.Stat(path); statErr == nil {
					t.Errorf("the refused instance still wrote %s", path)
				}
			}
		})
	}
}
