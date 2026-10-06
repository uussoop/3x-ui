package ikev2

import (
	"strings"
	"testing"
)

// TestConnectionPayloadCannotBeSplicedByANewline is the injection test for the
// VICI wire format. The payload is INI-shaped, so a newline inside a value
// would end the line and start a directive of its own: charon would then read
// something the panel never wrote — at best a syntax error, at worst a
// connection that behaves differently from the one the panel believes it
// loaded. Values are quoted and escaped for exactly this reason, and the test
// checks the structure rather than one field so a future field added without
// escaping is caught too.
func TestConnectionPayloadCannotBeSplicedByANewline(t *testing.T) {
	inst := testExitInstance()
	inst.Remote = "vpn.example.com\nmode = transport"

	payload := encode(RenderConnection(inst))

	if !strings.Contains(payload, `vpn.example.com\nmode = transport`) {
		t.Errorf("the injected newline was not escaped, so it terminates the line:\n%s", payload)
	}
	if strings.Contains(payload, "\nmode = transport") {
		t.Errorf("the injected text became a directive of its own:\n%s", payload)
	}

	for _, line := range strings.Split(payload, "\n") {
		if line == "" || line == "}" {
			continue
		}
		_, value, found := strings.Cut(line, " = ")
		if !found {
			t.Errorf("line %q has no key/value separator, so a value escaped its line:\n%s", line, payload)
			continue
		}
		if strings.HasSuffix(line, " = {") {
			continue // section header
		}
		if len(value) < 2 || !strings.HasPrefix(value, `"`) || !strings.HasSuffix(value, `"`) {
			t.Errorf("line %q does not carry a quoted value, so a value escaped its line:\n%s", line, payload)
		}
	}
}

// TestExitCarriesBothFamiliesSoNoLookupCanLeave is the leak test for the exit
// side. A name lookup is ordinary traffic to some resolver's address, so if
// the child's policies cover every destination in both families there is no
// address a query can reach that the tunnel does not: not a LAN resolver, not
// a public one, and no IPv6 path out the real interface either. Anything less
// — a pool-sized policy, or IPv4 only — leaves a working route around the exit.
func TestExitCarriesBothFamiliesSoNoLookupCanLeave(t *testing.T) {
	child := childSAConfig(testExitInstance())[0]
	for _, key := range []string{"local_addrs", "remote_addrs"} {
		if got := child.get(key); got != "0.0.0.0/0,::/0" {
			t.Errorf("exit child %s = %q, want every destination in both families", key, got)
		}
	}
}

// TestInboundOffersNoResolverItWasNotGiven is the responder-side half: a
// resolver is offered to connecting clients only when the operator configured
// one. Inventing one would send every client's lookups to a third party the
// operator never chose, and there would be no record anywhere of having done
// so.
func TestInboundOffersNoResolverItWasNotGiven(t *testing.T) {
	srv := testServerInstance()
	srv.DNSServer = ""
	child := childSAConfig(srv)[0]
	for _, key := range []string{"dns", "right_dns_hosts"} {
		if got := child.get(key); got != "" {
			t.Errorf("responder offers %s = %q without being told to", key, got)
		}
	}

	srv.DNSServer = "10.10.0.1"
	if got := childSAConfig(srv)[0].get("right_dns_hosts"); got != "10.10.0.1" {
		t.Errorf("right_dns_hosts = %q, want the configured resolver", got)
	}
}
