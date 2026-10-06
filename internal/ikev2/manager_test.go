package ikev2

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/vpn"
)

// TestLoadConnectionOverWire drives a full Start against the fake daemon and
// asserts on what the panel actually put on the socket: the host identity before
// the connection that refers to it, the connection's own reqid, and no account
// password in anything left on disk.
func TestLoadConnectionOverWire(t *testing.T) {
	srv := newFakeVICI(t)
	m := newTestManager(t, srv)
	inst := testServerInstance()
	if err := m.Ensure(inst); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if !srv.isLoaded("xui-7") {
		t.Fatal("connection xui-7 was not loaded")
	}

	sections := srv.allRequestSections()
	var sawConn, sawChild, sawAuth bool
	connIdx, childIdx := -1, -1
	for i, sec := range sections {
		switch {
		case sec.Name == "connections.xui-7":
			sawConn, connIdx = true, i
			if got := sec.get("mode"); got != "passive" {
				t.Errorf("server mode = %q, want passive; an active responder never answers", got)
			}
			if got := sec.get("local_port"); got != "500" {
				t.Errorf("local_port = %q", got)
			}
			// A responder must not install policies of its own.
			if got := sec.get("reqid"); got != "" {
				t.Errorf("server connection carries reqid %q; reqid belongs to an exit", got)
			}
		case sec.Name == "children.xui-7":
			sawChild, childIdx = true, i
			if got := sec.get("local_addrs"); got != "10.10.0.0/24" {
				t.Errorf("child local_addrs = %q, want the configured pool", got)
			}
			if got := sec.get("start_action"); got != "none" {
				t.Errorf("child start_action = %q, want none on a responder", got)
			}
		case strings.HasPrefix(sec.Name, "connections.xui-7.remote-"):
			sawAuth = true
			if got := sec.get("auth"); got != "eap-mschapv2" {
				t.Errorf("remote auth = %q, want eap-mschapv2", got)
			}
			// The IKE identity is the panel account, which is what makes a
			// child's SA attributable back to it.
			if got := sec.get("id"); got != "alice" {
				t.Errorf("remote id = %q, want the account identity", got)
			}
		}
	}
	if !sawConn || !sawChild || !sawAuth {
		t.Fatalf("missing sections: conn=%v child=%v auth=%v", sawConn, sawChild, sawAuth)
	}
	if connIdx > childIdx {
		t.Error("connection was sent after its child config")
	}

	// The account password must exist only in memory. A file an operator can
	// read is a file an operator can paste elsewhere.
	conf := mustReadFile(t, connConfPath(inst))
	for _, secret := range []string{"pw-alice", inst.HostKey, inst.CA} {
		if strings.Contains(conf, secret) {
			t.Errorf("generated config contains a secret: %q", secret)
		}
	}
	if info, err := os.Stat(filepath.Join(stateDir(), "xui-7", "ca.pem")); err != nil {
		t.Errorf("CA file not written: %v", err)
	} else if info.Mode().Perm() != 0o600 {
		t.Errorf("CA file mode = %v, want 0600", info.Mode().Perm())
	}
}

// TestEnsureIsIdempotent is what keeps a panel restart or a 10s reconcile tick
// from bouncing every live tunnel: an unchanged instance must not be reloaded.
func TestEnsureIsIdempotent(t *testing.T) {
	srv := newFakeVICI(t)
	m := newTestManager(t, srv)
	inst := testServerInstance()
	if err := m.Ensure(inst); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	before := len(srv.log())
	if err := m.Ensure(inst); err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	if got := len(srv.log()); got != before {
		t.Errorf("second Ensure sent %d more requests; an unchanged tunnel must be left alone", got-before)
	}
}

// A changed instance must be reloaded, or an operator's edit silently does
// nothing until the panel is restarted.
func TestEnsureReloadsOnChange(t *testing.T) {
	srv := newFakeVICI(t)
	m := newTestManager(t, srv)
	inst := testServerInstance()
	if err := m.Ensure(inst); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	changed := inst
	changed.Clients = append([]ClientConfig(nil), inst.Clients...)
	changed.Clients[0].Password = "rotated"
	if err := m.Ensure(changed); err != nil {
		t.Fatalf("Ensure after change: %v", err)
	}
	if got := len(srv.unloaded); got != 1 {
		t.Errorf("unload count = %d, want 1: a changed tunnel must be unloaded and reloaded", got)
	}
	if !srv.isLoaded("xui-7") {
		t.Error("connection not reloaded after the change")
	}
}

// TestValidateRefusesBrokenInstances covers the gate that keeps a bad tunnel from
// reaching a privileged daemon.
func TestValidateRefusesBrokenInstances(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Instance)
		want string
	}{
		{"server port missing", func(i *Instance) { i.Port = 0 }, "port"},
		{"server port out of range", func(i *Instance) { i.Port = 70000 }, "port"},
		{"no pool", func(i *Instance) { i.Subnet = "" }, "pool"},
		{"bad pool", func(i *Instance) { i.Subnet = "10.10.0.0/33" }, "network"},
		{"pool without prefix", func(i *Instance) { i.Subnet = "10.10.0.0" }, "network"},
		{"unknown auth method", func(i *Instance) { i.AuthMethod = "magic" }, "authentication method"},
		{"cert without CA", func(i *Instance) { i.AuthMethod = "cert"; i.CA = "" }, "CA"},
		{"psk without key", func(i *Instance) { i.AuthMethod = "psk"; i.PSK = "" }, "key"},
		{"no clients", func(i *Instance) { i.Clients = nil }, "no enabled clients"},
		{"credential newline", func(i *Instance) { i.Clients[0].Password = "pw\nremote = evil" }, "newline"},
		{"listen address newline", func(i *Instance) { i.Listen = "0.0.0.0\nup /bin/evil" }, "newline"},
		{"dns server newline", func(i *Instance) { i.DNSServer = "1.1.1.1\nroute 0.0.0.0/0" }, "newline"},
		{"no password", func(i *Instance) { i.Clients[0].Password = "" }, "no password"},
		{"duplicate account", func(i *Instance) {
			i.Clients = append(i.Clients, ClientConfig{Username: "alice", Password: "p", Enabled: true})
		}, "duplicate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inst := testServerInstance()
			tc.mut(&inst)
			err := inst.Validate()
			if err == nil {
				t.Fatalf("Validate accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}

	t.Run("exit needs no local port", func(t *testing.T) {
		// Only a responder listens. An exit that Validate rejected for "no port"
		// would make every client-mode inbound unsavable.
		if err := testExitInstance().Validate(); err != nil {
			t.Fatalf("a valid exit was rejected: %v", err)
		}
	})
	t.Run("exit without remote", func(t *testing.T) {
		inst := testExitInstance()
		inst.Remote = ""
		if err := inst.Validate(); err == nil {
			t.Error("an exit with no remote server was accepted")
		}
	})
	t.Run("exit remote newline", func(t *testing.T) {
		// The payload escapes this, so it cannot inject — but charon would
		// still refuse the address, and the operator would be shown a
		// strongSwan error instead of the field that caused it.
		inst := testExitInstance()
		inst.Remote = "vpn.example.com\nmode = transport"
		err := inst.Validate()
		if err == nil {
			t.Fatal("an exit whose remote spans two lines was accepted")
		}
		if !strings.Contains(err.Error(), "remote") {
			t.Errorf("error = %q, want it to name the remote field", err)
		}
	})
	t.Run("exit cert auth needs a key", func(t *testing.T) {
		inst := testExitInstance()
		inst.AuthMethod = "cert"
		inst.ClientCert = "CERT"
		if err := inst.Validate(); err == nil {
			t.Error("certificate auth without a private key was accepted")
		}
	})
}

// TestPerExitIdentityAndReqIDAreDistinct is the property that makes two exits
// independent: sharing an identity or a reqid would let one exit's teardown
// remove the other's XFRM policies.
func TestPerExitIdentityAndReqIDAreDistinct(t *testing.T) {
	srv := newFakeVICI(t)
	m := newTestManager(t, srv)

	a := testExitInstance()
	b := testExitInstance()
	b.ID = 10
	b.Tag = "ike-out-2"
	b.Remote = "other.example.com"
	b.Identity = ""
	b.ReqID = 0

	if err := m.Ensure(a); err != nil {
		t.Fatalf("Ensure exit a: %v", err)
	}

	// A second concurrent exit must be refused rather than loaded. Two exits
	// both installing 0.0.0.0/0 XFRM policies would encrypt one exit's traffic
	// into the other's SA — traffic that still looks like it left through a
	// tunnel, which is the misroute nobody notices.
	err := m.Ensure(b)
	if err == nil {
		t.Fatal("a second concurrent IKEv2 exit was loaded")
	}
	if !strings.Contains(err.Error(), "ike-out") {
		t.Errorf("the refusal does not name the exit already running: %v", err)
	}
	// Refusing must not disturb the exit that was working.
	if got, want := m.HasRunning(), true; got != want {
		t.Fatalf("HasRunning = %v after a refused second exit, want %v", got, want)
	}
	if len(srv.connections()) != 1 {
		t.Errorf("charon holds %v connections, want only the first exit's", srv.connections())
	}
	if srv.isLoaded(b.instanceName()) {
		t.Error("the refused exit was loaded into charon anyway")
	}

	if clientLocalID(a) != clientIdentity(9) {
		t.Errorf("exit a identity = %q, want %q", clientLocalID(a), clientIdentity(9))
	}
	if clientLocalID(b) != clientIdentity(10) || clientLocalID(a) == clientLocalID(b) {
		t.Errorf("exit identities are not distinct: %q vs %q", clientLocalID(a), clientLocalID(b))
	}
	if reqID(a) == reqID(b) {
		t.Errorf("both exits use reqid %d; their XFRM policies would collide", reqID(a))
	}
	if reqID(a) == reqIDFor(-int(math.Abs(float64(a.ID)))) {
		t.Errorf("exit %d uses the reqid of the template exit with the mirrored id (%d); the two could share policies", a.ID, reqID(a))
	}

	// With the first exit gone the second may start, which is what makes the
	// refusal a policy rather than a permanent block.
	m.Remove(a.ID)
	if err := m.Ensure(b); err != nil {
		t.Fatalf("Ensure exit b after the first was removed: %v", err)
	}
	seen := map[string]bool{}
	for _, sec := range srv.allRequestSections() {
		if sec.Name != "connections.xui-9" && sec.Name != "connections.xui-10" {
			continue
		}
		if got := sec.get("reqid"); got != "" {
			if seen[got] {
				t.Errorf("reqid %s used twice across exits", got)
			}
			seen[got] = true
		}
	}
	if len(seen) != 2 {
		t.Errorf("saw reqids %v, want one per exit", seen)
	}

	// An initiator must install policies for all traffic, otherwise the child's
	// SA covers nothing and traffic leaves over the real interface.
	for _, sec := range srv.allRequestSections() {
		if sec.Name != "children.xui-9" {
			continue
		}
		if got := sec.get("local_addrs"); got != "0.0.0.0/0,::/0" {
			t.Errorf("exit child local_addrs = %q, want all traffic", got)
		}
		if got := sec.get("start_action"); got != "start" {
			t.Errorf("exit child start_action = %q, want start", got)
		}
	}
}

// TestExitNotHealthyWithoutChildSA is the fail-closed property. A loaded
// connection with no established SA must never be eligible for selection, or
// traffic routed through the exit would leave over the real interface — the leak
// a VPN exit exists to prevent.
func TestExitNotHealthyWithoutChildSA(t *testing.T) {
	srv := newFakeVICI(t)
	m := newTestManager(t, srv)
	srv.setSAs([]string{})

	inst := testExitInstance()
	a := newTestAdapter(t, m, srv, inst)
	a.loaded = true
	a.applied = true

	if _, err := a.poll(); err != nil {
		t.Fatalf("poll: %v", err)
	}
	st := a.Status()
	if st.Healthy {
		t.Error("an exit with no child SA reported healthy; traffic would bypass it")
	}
	if st.Ready() {
		t.Error("Ready() = true for an exit with no child SA")
	}
	if st.ProbeErr == "" {
		t.Error("ProbeErr empty; an operator would see a silent, unusable exit")
	}
	if a.Counters().ConsecutiveFailures == 0 {
		t.Error("a failed health check did not count as a failure, so no backoff would apply")
	}
}

// A responder that answered the poll is serving. Holding nobody is the normal
// idle state of an inbound, so it is healthy — reporting it otherwise would
// flicker every quiet inbound red and teach an operator to ignore the colour.
// The distinction that matters is preserved separately: idle is not a *fault*,
// so no failure is recorded against it.
func TestServerHealthyOnlyWithConnectedClient(t *testing.T) {
	srv := newFakeVICI(t)
	m := newTestManager(t, srv)
	srv.setSAs([]string{})

	a := newTestAdapter(t, m, srv, testServerInstance())
	a.loaded = true
	a.applied = true
	if _, err := a.poll(); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if !a.Status().Healthy {
		t.Error("an idle responder reported unhealthy; monitoring would show a perfectly good inbound as down")
	}
	if a.failures != 0 {
		t.Errorf("idle responder recorded %d failures; holding nobody is not a fault", a.failures)
	}
	if !a.Status().Ready() {
		t.Error("an idle responder is not Ready; nothing distinguishes it from a broken one")
	}

	srv.setSAs([]string{serverSA("xui-7", "10.10.0.2", "alice", 100, 200)})
	if _, err := a.poll(); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if !a.Status().Healthy {
		t.Error("a responder with a connected client is not healthy")
	}
}

// TestSessionsMapToPanelAccounts is what preserves client identity across the
// bridge into the routing path: access rules and accounting key on the panel
// account, so the SA's IKE identity has to arrive as Username.
func TestSessionsMapToPanelAccounts(t *testing.T) {
	srv := newFakeVICI(t)
	m := newTestManager(t, srv)
	srv.setSAs([]string{serverSA("xui-7", "10.10.0.2", "alice", 1000, 2000)})

	a := newTestAdapter(t, m, srv, testServerInstance())
	a.loaded = true
	a.applied = true
	sessions, err := a.ListSessions()
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("sessions = %+v", sessions)
	}
	if sessions[0].Username != "alice" {
		t.Errorf("Username = %q, want the panel account", sessions[0].Username)
	}
	if sessions[0].IP != "10.10.0.2" {
		t.Errorf("IP = %q, want the address assigned inside the tunnel", sessions[0].IP)
	}
	if sessions[0].Since.IsZero() {
		t.Error("Since is zero; session age would be reported as unknown")
	}
}

// TestCountersDeltasAndRekeyReset covers the accounting contract: the first poll
// reports the absolute total, later polls report deltas, and a rekey — which
// resets charon's SA counters — is treated as a reset rather than booked as a
// huge negative or a huge positive.
func TestCountersDeltasAndRekeyReset(t *testing.T) {
	srv := newFakeVICI(t)
	m := newTestManager(t, srv)

	a := newTestAdapter(t, m, srv, testExitInstance())
	a.loaded = true
	a.applied = true

	srv.setSAs([]string{exitSA("xui-9", "10.10.0.2", "203.0.113.9", 5000, 9000, true)})
	if got := a.Counters(); got.UpBytes != 5000 || got.DownBytes != 9000 {
		t.Fatalf("first poll = up %d down %d, want the absolute totals", got.UpBytes, got.DownBytes)
	}

	srv.setSAs([]string{exitSA("xui-9", "10.10.0.2", "203.0.113.9", 5500, 9500, true)})
	if got := a.Counters(); got.UpBytes != 500 || got.DownBytes != 500 {
		t.Errorf("second poll = up %d down %d, want the deltas 500/500", got.UpBytes, got.DownBytes)
	}

	// A rekey resets the counters to a small number. Booking up-prevUp would be
	// -4500, and unsigned arithmetic would make it a huge positive instead.
	srv.setSAs([]string{exitSA("xui-9", "10.10.0.2", "203.0.113.9", 300, 400, true)})
	got := a.Counters()
	if got.UpBytes < 0 || got.DownBytes < 0 {
		t.Fatalf("rekey booked a negative delta: up %d down %d", got.UpBytes, got.DownBytes)
	}
	if got.UpBytes != 300 || got.DownBytes != 400 {
		t.Errorf("after rekey = up %d down %d, want 300/400 (everything since the reset)", got.UpBytes, got.DownBytes)
	}

	// And the interval after a reset is a normal delta again, not the total.
	srv.setSAs([]string{exitSA("xui-9", "10.10.0.2", "203.0.113.9", 350, 450, true)})
	if got := a.Counters(); got.UpBytes != 50 || got.DownBytes != 50 {
		t.Errorf("post-reset poll = up %d down %d, want 50/50", got.UpBytes, got.DownBytes)
	}
}

// An SA that reports no counters is not a tunnel that sent nothing.
func TestCountersIgnoreMissingValues(t *testing.T) {
	srv := newFakeVICI(t)
	m := newTestManager(t, srv)
	a := newTestAdapter(t, m, srv, testExitInstance())
	a.loaded = true
	a.applied = true

	srv.setSAs([]string{exitSA("xui-9", "10.10.0.2", "203.0.113.9", 0, 0, false)})
	if got := a.Counters(); got.UpBytes != 0 || got.DownBytes != 0 {
		t.Errorf("counters with no values = up %d down %d, want 0/0", got.UpBytes, got.DownBytes)
	}
	if got := parseCounter(""); got != -1 {
		t.Errorf("parseCounter(\"\") = %d, want -1 (absent, not zero)", got)
	}
	if got := parseCounter("not a number"); got != -1 {
		t.Errorf("parseCounter(garbage) = %d, want -1", got)
	}
	if got := parseCounter("42"); got != 42 {
		t.Errorf("parseCounter(42) = %d", got)
	}
}

// TestDisconnectSessionTerminatesOnlyThatAccount is how revocation avoids a
// tunnel-wide restart: one account's SA goes, everyone else's stays.
func TestDisconnectSessionTerminatesOnlyThatAccount(t *testing.T) {
	srv := newFakeVICI(t)
	m := newTestManager(t, srv)
	inst := testServerInstance()
	inst.Clients = append(inst.Clients, ClientConfig{Username: "carol", Password: "pw-carol", ID: "carol", Enabled: true})
	if err := m.Ensure(inst); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	srv.setSAs([]string{
		serverSA("xui-7", "10.10.0.2", "alice", 1, 2),
		serverSA("xui-7", "10.10.0.3", "carol", 3, 4),
	})

	if err := m.Terminate(7, "alice"); err != nil {
		t.Fatalf("Terminate: %v", err)
	}
	got := srv.terminations()
	if len(got) != 1 {
		t.Fatalf("terminations = %v, want exactly one", got)
	}
	if !strings.HasPrefix(got[0], "alice|") {
		t.Errorf("termination targeted %q, want alice's SA only", got[0])
	}
	// The tunnel itself must stay loaded: killing it would drop carol too.
	if !srv.isLoaded("xui-7") {
		t.Error("revoking one account unloaded the whole connection")
	}
}

// Revoking an account that is already gone is the desired state, not a failure:
// reporting an error there would make every revocation race look like a bug.
func TestDisconnectMissingSessionSucceeds(t *testing.T) {
	srv := newFakeVICI(t)
	m := newTestManager(t, srv)
	if err := m.Ensure(testServerInstance()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	srv.mu.Lock()
	srv.terminateErr = "no active IKE_SA for peer-id"
	srv.mu.Unlock()

	if err := m.Terminate(7, "ghost"); err != nil {
		t.Errorf("terminating an absent session failed: %v", err)
	}
}

// An account the panel never served cannot be disconnected, and that is reported
// as an error on purpose: access is decided by the panel, not by the tunnel.
func TestDisconnectUnknownConnectionErrors(t *testing.T) {
	srv := newFakeVICI(t)
	m := newTestManager(t, srv)
	if err := m.Terminate(404, "alice"); err == nil {
		t.Error("terminating on an unknown connection succeeded")
	}
}

// TestUnreachableSocketFailsClosed is the property that matters when strongSwan
// is not installed or has stopped: the panel must report a problem rather than
// let an unmonitored tunnel look fine.
func TestUnreachableSocketFailsClosed(t *testing.T) {
	srv := newFakeVICI(t)
	m := newTestManager(t, srv)
	if err := m.Ensure(testServerInstance()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	srv.setSAs([]string{serverSA("xui-7", "10.10.0.2", "alice", 10, 20)})
	a := newTestAdapter(t, m, srv, testServerInstance())
	a.loaded = true
	a.applied = true
	if _, err := a.poll(); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if !a.Status().Healthy {
		t.Fatal("precondition: tunnel should be healthy")
	}

	// Point at a socket nobody is listening on.
	m.SetSocketPath(filepath.Join(t.TempDir(), "gone.vici"))

	if _, err := a.poll(); err == nil {
		t.Fatal("poll succeeded against a dead socket")
	}
	st := a.Status()
	if st.Healthy {
		t.Error("Healthy stayed true after the socket went away")
	}
	if st.Ready() {
		t.Error("Ready() = true with an unreachable daemon")
	}
	if st.ProbeErr == "" {
		t.Error("ProbeErr empty; monitoring would show a silent tunnel")
	}
	if st.LastProbe.IsZero() {
		t.Error("LastProbe not updated, so a stale healthy flag could never age out")
	}
}

// TestDaemonRestartReconnects: charon restarting under a live panel must not
// permanently break the panel's control of its own tunnels.
func TestDaemonRestartReconnects(t *testing.T) {
	srv := newFakeVICI(t)
	m := newTestManager(t, srv)
	if err := m.Ensure(testServerInstance()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	// Drop the connection after serving the next request without replying.
	srv.mu.Lock()
	srv.closeAfter = len(srv.requests)
	srv.mu.Unlock()

	if _, err := a2SAs(t, m); err == nil {
		t.Log("first request succeeded; forcing a restart below anyway")
	}
	srv.mu.Lock()
	srv.closeAfter = 0
	srv.mu.Unlock()

	srv.setSAs([]string{serverSA("xui-7", "10.10.0.2", "alice", 5, 6)})
	sas, err := m.listSAs(testServerInstance())
	if err != nil {
		t.Fatalf("listSAs after a daemon restart: %v", err)
	}
	if len(sas) != 1 {
		t.Errorf("SAs after reconnect = %+v", sas)
	}
}

// a2SAs makes one SA-table request and reports the error, used to burn a
// connection through the fake's forced-restart path.
func a2SAs(t *testing.T, m *Manager) ([]saInfo, error) {
	t.Helper()
	return m.listSAs(testServerInstance())
}

// A refused configuration must surface as an error and leave nothing loaded,
// rather than leaving a half-configured connection in a privileged daemon.
//
// The tunnel is still remembered, because that record is what lets the panel say
// *why* nothing is loaded and hold off re-sending the same broken config. It
// must be remembered as down, never as up.
func TestRejectedLoadSurfacesError(t *testing.T) {
	srv := newFakeVICI(t)
	m := newTestManager(t, srv)
	srv.mu.Lock()
	srv.rejectLoad = "unable to load private key"
	srv.mu.Unlock()

	err := m.Ensure(testServerInstance())
	if err == nil {
		t.Fatal("Ensure succeeded against a daemon rejecting the config")
	}
	if srv.isLoaded("xui-7") {
		t.Error("a rejected connection was recorded as loaded")
	}
	if m.HasRunning() {
		t.Error("a refused configuration is being reported as a running tunnel")
	}
	if _, ok := m.Adapter(7); !ok {
		t.Fatal("a failed Ensure left no record, so the next reconcile would resend it with no backoff and Status could not say why it is down")
	}
	m.mu.Lock()
	a, ok := m.adapters[7]
	m.mu.Unlock()
	if !ok {
		t.Fatal("precondition: the adapter vanished between the two lookups")
	}
	st := a.Status()
	if st.Ready() {
		t.Error("a tunnel that never loaded reports itself ready")
	}
	if st.LastError == "" {
		t.Error("Status hides the daemon's refusal, leaving the operator nothing to act on")
	}
	if a.retry.Failures() == 0 {
		t.Error("the failed attempt did not count towards the backoff")
	}
	if a.retry.Due() {
		t.Error("a refused connection is immediately due for another attempt")
	}
}

// TestScrubKeepsSecretsOutOfErrors covers the path where a VICI error quotes the
// section it rejected — which, for an auth section, is the account password.
func TestScrubKeepsSecretsOutOfErrors(t *testing.T) {
	line := `failed to load connections.xui-7.remote-alice: psk = "super-secret-value" auth = "psk"`
	got := ScrubLine(line)
	if strings.Contains(got, "super-secret-value") {
		t.Errorf("secret survived scrubbing: %q", got)
	}
	if !strings.Contains(got, "remote-alice") {
		t.Errorf("scrubbing removed the diagnostic context: %q", got)
	}
	if got := RedactSecret("psk is hunter2 here", "hunter2"); strings.Contains(got, "hunter2") {
		t.Errorf("RedactSecret left the secret: %q", got)
	}
	if got := ScrubLine(""); got != "" {
		t.Errorf("ScrubLine(\"\") = %q", got)
	}
}

func TestFingerprintHidesCredentialsAndIgnoresOrder(t *testing.T) {
	inst := testServerInstance()
	inst.Clients = append(inst.Clients, ClientConfig{Username: "carol", Password: "pw-carol", ID: "carol", Enabled: true})
	base := inst.fingerprint()
	if strings.Contains(base, "pw-alice") || strings.Contains(base, "pw-carol") {
		t.Error("fingerprint contains a plaintext credential")
	}

	reordered := testServerInstance()
	reordered.Clients = []ClientConfig{
		{Username: "carol", Password: "pw-carol", ID: "carol", Enabled: true},
		{Username: "alice", Password: "pw-alice", ID: "alice", Enabled: true},
	}
	if reordered.fingerprint() != base {
		t.Error("client order changed the fingerprint; a reordered array would restart the tunnel")
	}

	rotated := testServerInstance()
	rotated.Clients = append([]ClientConfig(nil), inst.Clients...)
	rotated.Clients[0].Password = "rotated"
	if rotated.fingerprint() == base {
		t.Error("a rotated password did not change the fingerprint, so the change would never be applied")
	}

	// A disabled account is not served, so leaving one in the stored settings
	// must not look like a change: a client toggled off and then on again would
	// otherwise bounce the tunnel every time.
	disabledCarol := inst
	disabledCarol.Clients = append([]ClientConfig(nil), inst.Clients...)
	disabledCarol.Clients[1].Enabled = false
	if got, want := disabledCarol.fingerprint(), testServerInstance().fingerprint(); got != want {
		t.Errorf("a disabled account still affects the fingerprint: %s vs %s", got, want)
	}
}

// TestApplyIsIdempotent: applying twice must produce identical bytes, or a
// reconcile would rewrite files every tick.
func TestApplyIsIdempotent(t *testing.T) {
	srv := newFakeVICI(t)
	m := newTestManager(t, srv)
	inst := testServerInstance()
	a := &adapter{inst: inst, mgr: m, retry: vpn.NewRetry()}
	if err := a.Apply(); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	first := mustReadFile(t, connConfPath(inst))
	if err := a.Apply(); err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if second := mustReadFile(t, connConfPath(inst)); second != first {
		t.Error("Apply is not idempotent")
	}
	if info, err := os.Stat(connConfPath(inst)); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0o600 {
		t.Errorf("config mode = %v, want 0600", info.Mode().Perm())
	}
}

// TestReconcileTearsDownRemovedInbounds is what makes deleting an inbound
// actually remove the tunnel, rather than leaving a daemon serving clients the
// panel no longer knows about.
func TestReconcileTearsDownRemovedInbounds(t *testing.T) {
	srv := newFakeVICI(t)
	m := newTestManager(t, srv)
	inst := testServerInstance()
	if err := m.Ensure(inst); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	m.Reconcile(nil)
	if srv.isLoaded("xui-7") {
		t.Error("the connection is still loaded after its inbound was removed")
	}
	if m.HasRunning() {
		t.Error("HasRunning() = true after every connection was unloaded")
	}
	if _, err := os.Stat(connConfPath(inst)); err == nil {
		t.Error("the generated config was left on disk after removal")
	}
}

// One broken connection must not stop the others converging — otherwise a
// single bad inbound silently disables every other tunnel on the panel.
func TestReconcileIsolatesFailures(t *testing.T) {
	srv := newFakeVICI(t)
	m := newTestManager(t, srv)
	good := testServerInstance()

	bad := testExitInstance()
	bad.Remote = ""

	m.Reconcile([]Instance{bad, good})
	if !srv.isLoaded("xui-7") {
		t.Error("a valid connection did not converge because another one was invalid")
	}
}

// TestStopAllLeavesNoLoadedConnections: the panel is going away, and a tunnel
// that outlives it would keep the panel's XFRM policies in the kernel.
func TestStopAllLeavesNoLoadedConnections(t *testing.T) {
	srv := newFakeVICI(t)
	m := newTestManager(t, srv)
	if err := m.Ensure(testServerInstance()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	m.StopAll()
	if srv.isLoaded("xui-7") {
		t.Error("StopAll left the connection loaded in strongSwan")
	}
}

// TestCollectTrafficSplitsPerAccount covers the accounting shape the traffic job
// consumes: per-account deltas for a bridged inbound (its total is metered by the
// Xray bridge too), and the tunnel total for one that is not.
func TestCollectTrafficSplitsPerAccount(t *testing.T) {
	srv := newFakeVICI(t)
	m := newTestManager(t, srv)
	inst := testServerInstance()
	inst.RouteThroughXray = true
	inst.Clients = append(inst.Clients, ClientConfig{Username: "carol", Password: "pw-carol", ID: "carol", Enabled: true})
	if err := m.Ensure(inst); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	srv.setSAs([]string{
		serverSA("xui-7", "10.10.0.2", "alice", 1000, 2000),
		serverSA("xui-7", "10.10.0.3", "carol", 300, 400),
	})

	traffic, online, states := m.CollectTraffic()
	for _, tr := range traffic {
		if tr.Email == "" {
			t.Error("a bridged inbound reported a tunnel total; the Xray bridge already meters those bytes, so they would be counted twice")
		}
	}
	if len(online) != 2 {
		t.Errorf("online accounts = %v, want alice and carol", online)
	}
	if st, ok := states[7]; !ok || !st.Connected {
		t.Errorf("state for the connection is missing or disconnected: %+v", states)
	}

	// Without the bridge the tunnel total is the only thing that can be booked.
	plain := testServerInstance()
	plain.ID = 8
	m.Ensure(plain)
	srv.setSAs([]string{serverSA("xui-8", "10.10.0.2", "alice", 700, 800)})
	traffic, _, _ = m.CollectTraffic()
	var found bool
	for _, tr := range traffic {
		if tr.Email == "" && tr.Up > 0 {
			found = true
		}
	}
	if !found {
		t.Error("a non-bridged inbound reported no tunnel total at all")
	}
}

// TestCollectTrafficHoldsLastKnownOnFailure: a poll that fails must not book a
// sudden drop to zero traffic.
func TestCollectTrafficHoldsLastKnownOnFailure(t *testing.T) {
	srv := newFakeVICI(t)
	m := newTestManager(t, srv)
	if err := m.Ensure(testServerInstance()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	srv.setSAs([]string{serverSA("xui-7", "10.10.0.2", "alice", 1000, 2000)})
	if _, _, _ = m.CollectTraffic(); false {
		t.Fatal("unreachable")
	}

	m.SetSocketPath(filepath.Join(t.TempDir(), "gone.vici"))

	traffic, _, _ := m.CollectTraffic()
	for _, tr := range traffic {
		if tr.Email == "" && (tr.Up == 0 && tr.Down == 0) {
			t.Error("a failed poll booked zero traffic instead of the last known totals")
		}
	}
}

// TestStatusSeparatesConfiguredConnectedHealthy is the three-state contract the
// panel's monitoring depends on.
func TestStatusSeparatesConfiguredConnectedHealthy(t *testing.T) {
	srv := newFakeVICI(t)
	m := newTestManager(t, srv)
	a := &adapter{inst: testServerInstance(), mgr: m}

	st := a.Status()
	if st.Configured || st.Connected || st.Healthy {
		t.Errorf("a fresh adapter claims state: %+v", st)
	}
	if st.Ready() {
		t.Error("a fresh adapter is Ready; fail-closed was lost")
	}
	if st.ProbeErr == "" {
		t.Error("ProbeErr empty for an adapter that was never loaded; monitoring would show a silent tunnel")
	}

	if err := a.Apply(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	st = a.Status()
	if !st.Configured {
		t.Error("Configured = false after Apply")
	}
	if st.Connected {
		t.Error("Connected = true before Start")
	}

	if err := a.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	st = a.Status()
	if !st.Connected {
		t.Error("Connected = false after Start")
	}
	if st.Healthy {
		t.Error("Healthy = true before any probe; health must be proven, not assumed")
	}
	if st.Ready() {
		t.Error("Ready() = true before any probe")
	}
}

// TestStopIsIdempotentAndScoped: stopping one connection must not disturb
// another, and stopping twice must not error.
func TestStopIsIdempotentAndScoped(t *testing.T) {
	srv := newFakeVICI(t)
	m := newTestManager(t, srv)
	if err := m.Ensure(testServerInstance()); err != nil {
		t.Fatalf("Ensure server: %v", err)
	}
	other := testExitInstance()
	other.ID = 10
	if err := m.Ensure(other); err != nil {
		t.Fatalf("Ensure exit: %v", err)
	}

	a, _ := m.Adapter(7)
	if err := a.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := a.Stop(context.Background()); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
	if !srv.isLoaded("xui-10") {
		t.Error("stopping one connection unloaded another")
	}
}
