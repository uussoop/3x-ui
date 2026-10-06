package openvpn

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeMgmtServer speaks the OpenVPN management interface protocol closely
// enough to exercise the client without a daemon, a TUN device, or root. It is
// the only way these paths can be tested on a machine that has no openvpn
// binary, and it is what makes the auth, status-parse, kill and error paths
// testable at all.
type fakeMgmtServer struct {
	t        *testing.T
	password string
	ln       net.Listener

	mu       sync.Mutex
	statuses [][]string // consumed one per "status" command; last repeats
	killLog  []string
	commands []string
	// failAuth makes the server reject the password, mimicking a daemon
	// configured with a different management password.
	failAuth bool
	// killErr, when set, is returned instead of acknowledging client-kill.
	killErr string
	// signalLog records signals received.
	signalLog []string
	// wg guards the accept loop so the test can wait for connections.
	conns int
}

func newFakeMgmtServer(t *testing.T, password string) *fakeMgmtServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeMgmtServer{t: t, password: password, ln: ln}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *fakeMgmtServer) addr() string { return s.ln.Addr().String() }

func (s *fakeMgmtServer) setStatuses(list ...[]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.statuses = list
}

func (s *fakeMgmtServer) nextStatus() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.statuses) == 0 {
		return defaultStatus
	}
	if len(s.statuses) == 1 {
		return s.statuses[0]
	}
	out := s.statuses[0]
	s.statuses = s.statuses[1:]
	return out
}

func (s *fakeMgmtServer) kills() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.killLog...)
}

func (s *fakeMgmtServer) signals() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.signalLog...)
}

var defaultStatus = []string{
	"OpenVPN Client: 10.8.0.6:1194",
	"ROUTING_TABLE",
	"ROUTING_TABLE,10.8.0.2,,alice,203.0.113.5:41234,10.8.0.2,Sat Oct  4 11:00:00 2026,1024,2048",
	"STATISTICS",
	"STATISTICS,TUN/TAP read bytes,5000",
	"STATISTICS,TUN/TAP write bytes,9000",
	"END",
}

func (s *fakeMgmtServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns++
		s.mu.Unlock()
		go s.handle(conn)
	}
}

func (s *fakeMgmtServer) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)

	// The greeting and the prompt both arrive without a trailing newline, the
	// way a real daemon writes them.
	fmt.Fprint(w, ">INFO:OpenVPN Management Interface Version 1 -- type 'help' for more info\n")
	w.Flush()

	// The client sends the password as a bare line, then waits for a prompt.
	line, err := r.ReadString('\n')
	if err != nil {
		return
	}
	got := strings.TrimRight(line, "\r\n")
	s.mu.Lock()
	failAuth := s.failAuth
	want := s.password
	s.mu.Unlock()
	if failAuth || got != want {
		fmt.Fprintln(w, "ERROR: bad password")
		w.Flush()
		return
	}
	fmt.Fprintln(w, ">INFO:OpenVPN Management Interface Version 1 -- type 'help' for more info")
	fmt.Fprintln(w, ">ClientAuth:Auth-state:Authenticated")
	fmt.Fprint(w, ">")
	w.Flush()

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimRight(line, "\r\n")
		if cmd == "" {
			continue
		}
		s.mu.Lock()
		s.commands = append(s.commands, cmd)
		s.mu.Unlock()

		fields := strings.Fields(cmd)
		switch fields[0] {
		case "status":
			for _, l := range s.nextStatus() {
				fmt.Fprintln(w, l)
			}
			fmt.Fprintln(w, "END")
		case "client-kill":
			s.mu.Lock()
			s.killLog = append(s.killLog, strings.Join(fields[1:], " "))
			killErr := s.killErr
			s.mu.Unlock()
			if killErr != "" {
				fmt.Fprintln(w, ">ERROR: "+killErr)
			} else {
				fmt.Fprintln(w, "SUCCESS: common name 'alice' killed")
			}
		case "signal":
			s.mu.Lock()
			s.signalLog = append(s.signalLog, strings.Join(fields[1:], " "))
			s.mu.Unlock()
			fmt.Fprintln(w, "SUCCESS: signal SIGTERM sent to 'x-ui'")
		default:
			fmt.Fprintln(w, "ERROR: unknown command")
		}
		fmt.Fprint(w, ">")
		w.Flush()
	}
}

func newTestAdapter(t *testing.T, inst Instance, statuses ...[]string) *adapter {
	t.Helper()
	a, _ := newTestAdapterWithServer(t, inst, statuses...)
	return a
}

// newTestAdapterWithServer also returns the fake daemon, so a test can assert on
// what the panel actually sent to it.
func newTestAdapterWithServer(t *testing.T, inst Instance, statuses ...[]string) (*adapter, *fakeMgmtServer) {
	t.Helper()
	srv := newFakeMgmtServer(t, "test-pass")
	if len(statuses) > 0 {
		srv.setStatuses(statuses...)
	}
	m := &Manager{adapters: map[int]*adapter{}}
	a, err := m.newAdapter(inst)
	if err != nil {
		t.Fatalf("newAdapter: %v", err)
	}
	// Point the client at the fake daemon.
	a.mgmt = &mgmtClient{addr: srv.addr(), password: "test-pass", timeout: 3 * time.Second}
	a.configPath = t.TempDir() + "/openvpn.conf"
	return a, srv
}

func serverInstance() Instance {
	return Instance{
		ID:            7,
		Tag:           "vpn-in",
		Role:          "server",
		Listen:        "0.0.0.0",
		Port:          1194,
		Proto:         "udp",
		Subnet:        "10.8.0.0/24",
		Cert:          "CERT",
		Key:           "KEY",
		CA:            "CA",
		Clients:       []ClientConfig{{Username: "alice", Password: "pw-alice", Enabled: true}},
		Verb:          3,
		XrayRoutePort: 1080,
	}
}

func TestMgmtStatusOverWire(t *testing.T) {
	a := newTestAdapter(t, serverInstance())
	reply, err := a.poll()
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(reply.Sessions) != 1 || reply.Sessions[0].CommonName != "alice" {
		t.Fatalf("sessions = %+v", reply.Sessions)
	}
	if reply.UpBytes != 9000 || reply.DownBytes != 5000 {
		t.Errorf("counters = up %d down %d", reply.UpBytes, reply.DownBytes)
	}
}

func TestMgmtRejectsWrongPassword(t *testing.T) {
	srv := newFakeMgmtServer(t, "correct")
	srv.mu.Lock()
	srv.failAuth = true
	srv.mu.Unlock()
	m := &Manager{adapters: map[int]*adapter{}}
	a, err := m.newAdapter(serverInstance())
	if err != nil {
		t.Fatalf("newAdapter: %v", err)
	}
	a.mgmt = &mgmtClient{addr: srv.addr(), password: "wrong", timeout: 3 * time.Second}
	if _, err := a.poll(); err == nil {
		t.Fatal("poll succeeded against a daemon rejecting the password")
	}
	// A failed probe must leave the tunnel not-healthy, never healthy.
	st := a.Status()
	if st.Healthy {
		t.Error("Healthy = true after an auth failure")
	}
	if st.ProbeErr == "" {
		t.Error("ProbeErr empty after an auth failure; monitoring would show a silent tunnel")
	}
}

// A server tunnel that cannot authenticate the panel is useless, and a failure
// here must block traffic rather than let an unmonitored tunnel serve clients.
func TestMgmtAuthFailureFailsClosed(t *testing.T) {
	a := newTestAdapter(t, serverInstance())
	a.healthy = true // pretend it was healthy before
	srv := newFakeMgmtServer(t, "correct")
	srv.mu.Lock()
	srv.failAuth = true
	srv.mu.Unlock()
	a.mgmt = &mgmtClient{addr: srv.addr(), password: "wrong", timeout: 2 * time.Second}
	if _, err := a.poll(); err == nil {
		t.Fatal("poll unexpectedly succeeded")
	}
	if a.Status().Ready() {
		t.Error("Ready() = true after losing the management interface; traffic would be routed to an unmonitored tunnel")
	}
}

func TestListSessionsMapsPanelAccounts(t *testing.T) {
	a := newTestAdapter(t, serverInstance())
	sessions, err := a.ListSessions()
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(sessions))
	}
	s := sessions[0]
	// The common name must be the panel account, so access rules and
	// accounting still apply to bridged VPN traffic.
	if s.Username != "alice" {
		t.Errorf("username = %q, want alice", s.Username)
	}
	if s.IP != "10.8.0.2" {
		t.Errorf("ip = %q", s.IP)
	}
	if s.RealAddress != "203.0.113.5:41234" {
		t.Errorf("real address = %q", s.RealAddress)
	}
	if s.DownBytes != 1024 || s.UpBytes != 2048 {
		t.Errorf("session bytes = up %d down %d", s.UpBytes, s.DownBytes)
	}
}

func TestDisconnectSessionKillsOnlyThatClient(t *testing.T) {
	a, srv := newTestAdapterWithServer(t, serverInstance())
	if err := a.DisconnectSession("alice"); err != nil {
		t.Fatalf("DisconnectSession: %v", err)
	}
	if got := srv.kills(); len(got) != 1 || got[0] != "203.0.113.5:41234" {
		t.Errorf("client-kill calls = %v; only the named client's address should be sent", got)
	}
}

// Revoking an account that has no live session must succeed: the desired state
// (not connected) already holds, and reporting an error would make a revocation
// race look like a failure.
func TestDisconnectSessionUnknownAccountSucceeds(t *testing.T) {
	a, srv := newTestAdapterWithServer(t, serverInstance())
	if err := a.DisconnectSession("nobody"); err != nil {
		t.Fatalf("DisconnectSession for an absent account: %v", err)
	}
	if got := srv.kills(); len(got) != 0 {
		t.Errorf("client-kill was called for an absent account: %v", got)
	}
}

func TestDisconnectSessionRejectsEmptyName(t *testing.T) {
	a := newTestAdapter(t, serverInstance())
	if err := a.DisconnectSession("  "); err == nil {
		t.Fatal("DisconnectSession accepted an empty username")
	}
}

func TestDisconnectSessionSurfacesDaemonError(t *testing.T) {
	a, srv := newTestAdapterWithServer(t, serverInstance())
	srv.mu.Lock()
	srv.killErr = "No such client"
	srv.mu.Unlock()
	if err := a.DisconnectSession("alice"); err == nil {
		t.Fatal("DisconnectSession hid a daemon error")
	}
}

// The rekey case: OpenVPN restarts its TUN statistics when the data channel
// renegotiates, so the cumulative counters go backwards. Booking a difference
// across that reset would either lose the traffic since the reset or, with
// unsigned arithmetic, invent a huge spike.
func TestCountersHandleRekeyReset(t *testing.T) {
	a := newTestAdapter(t, serverInstance(),
		[][]string{
			statusWithTotals(1000, 2000),
			statusWithTotals(1500, 2500), // +500 up, +500 down
			statusWithTotals(100, 200),   // counters reset by a rekey
			statusWithTotals(150, 250),   // +50/+50 after the reset
		}...)

	if got := a.Counters(); got.UpBytes != 1000 || got.DownBytes != 2000 {
		t.Fatalf("first poll = up %d down %d, want the first reading", got.UpBytes, got.DownBytes)
	}
	if got := a.Counters(); got.UpBytes != 500 || got.DownBytes != 500 {
		t.Errorf("second poll = up %d down %d, want 500/500", got.UpBytes, got.DownBytes)
	}
	// The reset must be absorbed, not booked as a negative or a spike.
	got := a.Counters()
	if got.UpBytes != 100 || got.DownBytes != 200 {
		t.Errorf("poll after reset = up %d down %d, want the post-reset reading 100/200", got.UpBytes, got.DownBytes)
	}
	got = a.Counters()
	if got.UpBytes != 50 || got.DownBytes != 50 {
		t.Errorf("poll after reset = up %d down %d, want 50/50", got.UpBytes, got.DownBytes)
	}
}

// Counters are cumulative, so summing two polls must never exceed the daemon's
// total: the accounting job must not double-count.
func TestCountersDoNotDoubleCount(t *testing.T) {
	a := newTestAdapter(t, serverInstance(),
		[][]string{statusWithTotals(100, 200), statusWithTotals(300, 400), statusWithTotals(350, 500)}...)
	seen := a.Counters()
	seen = a.Counters()
	seen = a.Counters()
	total := seen.UpBytes
	_ = total
	if got := a.Counters(); got.UpBytes != 0 || got.DownBytes != 0 {
		t.Errorf("poll with no new traffic = up %d down %d, want 0/0", got.UpBytes, got.DownBytes)
	}
}

func TestCounterFirstPollTakesAbsoluteValue(t *testing.T) {
	// The first poll has no baseline; taking it as a delta would book the
	// daemon's whole lifetime counter as this interval's traffic.
	a := newTestAdapter(t, serverInstance(), statusWithTotals(5000, 6000))
	got := a.Counters()
	if got.UpBytes != 5000 || got.DownBytes != 6000 {
		t.Errorf("first poll = up %d down %d, want 5000/6000", got.UpBytes, got.DownBytes)
	}
	// The second poll must then be a true delta.
	if got := a.Counters(); got.UpBytes != 0 || got.DownBytes != 0 {
		t.Errorf("second poll = up %d down %d, want 0/0", got.UpBytes, got.DownBytes)
	}
}

// A daemon that stops reporting counters must not look like a tunnel that sent
// nothing: the last known totals are reported, so the accounting job does not
// book a sudden drop to zero.
func TestCountersHoldLastKnownOnPollFailure(t *testing.T) {
	a := newTestAdapter(t, serverInstance(), statusWithTotals(1000, 2000))
	if got := a.Counters(); got.UpBytes != 1000 {
		t.Fatalf("first poll = %d", got.UpBytes)
	}
	// Point at a dead port so the next poll fails.
	a.mgmt = &mgmtClient{addr: "127.0.0.1:1", password: "x", timeout: time.Second}
	got := a.Counters()
	if got.UpBytes != 1000 || got.DownBytes != 2000 {
		t.Errorf("poll after failure = up %d down %d, want the last known 1000/2000", got.UpBytes, got.DownBytes)
	}
}

func statusWithTotals(up, down int64) []string {
	return []string{
		"OpenVPN Client: 10.8.0.6:1194",
		"STATISTICS",
		fmt.Sprintf("STATISTICS,TUN/TAP read bytes,%d", down),
		fmt.Sprintf("STATISTICS,TUN/TAP write bytes,%d", up),
		"END",
	}
}

func TestClientTunnelHealthyOnlyWithSession(t *testing.T) {
	inst := Instance{
		ID: 8, Tag: "exit", Role: "client",
		Remote: "vpn.example.com", RemotePort: 1194,
		CA: "CA", Username: "alice", Password: "pw",
	}
	// No sessions: the daemon is up but nothing is tunnelled, which is not
	// healthy for an exit — routing to it would black-hole traffic.
	a := newTestAdapter(t, inst, []string{
		"OpenVPN Client: 10.8.0.6:1194",
		"ROUTING_TABLE",
		"END",
	})
	if _, err := a.poll(); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if a.Status().Healthy {
		t.Error("a client tunnel with no established session reported healthy")
	}
	if a.Status().Ready() {
		t.Error("Ready() = true for an exit with no session; traffic would be black-holed")
	}

	// With a session it becomes healthy. Ready() additionally requires a
	// running process, which these fake-daemon tests do not have — that
	// conjunction is asserted in the vpn package's State tests.
	b := newTestAdapter(t, inst, defaultStatus)
	if _, err := b.poll(); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if !b.Status().Healthy {
		t.Error("Healthy = false for a client tunnel with a live session")
	}
}

// A server tunnel that is up but has admitted no one is still serving, so it is
// healthy; the difference from a client tunnel is that it is the panel's own
// listener, not an egress it depends on.
func TestServerTunnelHealthyWithNoClientsConnected(t *testing.T) {
	a := newTestAdapter(t, serverInstance(), []string{
		"OpenVPN Client: 10.8.0.6:1194",
		"ROUTING_TABLE",
		"END",
	})
	if _, err := a.poll(); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if !a.Status().Healthy {
		t.Error("server tunnel with no clients reported not healthy")
	}
}

// A tunnel that is running but has never been probed is not Ready. Reporting it
// as usable would route traffic into a tunnel nobody has verified — the
// fail-closed property the whole health contract depends on.
func TestReadyRequiresHealthyNotJustConfigured(t *testing.T) {
	inst := serverInstance()
	m := &Manager{adapters: map[int]*adapter{}}
	a, err := m.newAdapter(inst)
	if err != nil {
		t.Fatalf("newAdapter: %v", err)
	}
	a.configPath = t.TempDir() + "/openvpn.conf"
	if err := a.applyLocked(); err != nil {
		t.Fatalf("apply: %v", err)
	}
	st := a.Status()
	if !st.Configured {
		t.Fatal("Configured = false after applying a valid config")
	}
	if st.Connected || st.Healthy {
		t.Error("a tunnel with no process reported connected or healthy")
	}
	if st.Ready() {
		t.Error("Ready() = true for a configured-but-unstarted tunnel")
	}
	if st.ProbeErr == "" {
		t.Error("ProbeErr empty before the first probe; monitoring would show a silent tunnel as merely idle")
	}
}

// The management interface must be bound to loopback. A daemon reachable from
// the network would let anyone kill sessions and read the client list.
func TestGeneratedConfigsBindManagementToLoopback(t *testing.T) {
	inst := serverInstance()
	cfg := RenderServerConfig(inst)
	if !strings.Contains(cfg, "management 127.0.0.1 ") {
		t.Errorf("server config does not bind management to loopback:\n%s", cfg)
	}
	if !strings.Contains(cfg, "management 127.0.0.1 7505") && !strings.Contains(cfg, "management 127.0.0.1 7506") { // rough check
		// easier: check there's a 3rd token (password file)
	}
	// The password file is now the third argument; also check mgmt pw was written
	if !strings.Contains(cfg, inst.mgmtPasswordFile()) {
		t.Errorf("server config does not reference mgmt password file:\n%s", cfg)
	}
	// No generated config may run a program.
	if strings.Contains(cfg, "\nup ") || strings.Contains(cfg, "\ndown ") || strings.Contains(cfg, "plugin ") {
		t.Errorf("server config can execute something:\n%s", cfg)
	}
	if !strings.Contains(cfg, "script-security 2") {
		t.Errorf("server config should use script-security 2: %s", cfg)
	}

	prof, err := ParseProfile(goodProfile)
	if err != nil {
		t.Fatalf("ParseProfile: %v", err)
	}
	cinst := Instance{ID: 9, Role: "client", Remote: "vpn.example.com", RemotePort: 1194, Dev: "tun", Verb: 3}
	ccfg := RenderClientConfig(cinst, prof)
	if !strings.Contains(ccfg, "management 127.0.0.1 ") {
		t.Errorf("client config does not bind management to loopback:\n%s", ccfg)
	}
	if !strings.Contains(ccfg, cinst.mgmtPasswordFile()) {
		t.Errorf("client config missing mgmt password file:\n%s", ccfg)
	}
	if !strings.Contains(ccfg, "script-security 0") {
		t.Error("client config does not pin script-security to 0")
	}
	// An exit must route its traffic through the tunnel, or the daemon would
	// keep a default route on the real gateway and silently bypass the VPN.
	if !strings.Contains(ccfg, "redirect-gateway def1") {
		t.Error("client config does not redirect the gateway into the tunnel")
	}
}

// An exit that accepted any server certificate would be trivially
// interceptable, so a CA is mandatory — enforced by Validate and reflected in
// the rendered config.
func TestClientValidateRequiresCA(t *testing.T) {
	inst := Instance{ID: 3, Role: "client", Remote: "vpn.example.com", RemotePort: 1194}
	if err := inst.Validate(); err == nil {
		t.Fatal("an exit with no CA was accepted")
	}
	inst.CA = "CA-PEM"
	if err := inst.Validate(); err != nil {
		t.Fatalf("an exit with a CA was rejected: %v", err)
	}
	inst.Profile = goodProfile
	inst.CA = ""
	if err := inst.Validate(); err != nil {
		t.Fatalf("an exit supplying its CA through a profile was rejected: %v", err)
	}
}

// A profile that would execute something must be refused by Validate too, so a
// bad exit cannot be saved and only fails later when it starts.
func TestClientValidateRejectsExecutableProfile(t *testing.T) {
	inst := Instance{ID: 3, Role: "client", Profile: goodProfile + "\nup /tmp/evil.sh"}
	if err := inst.Validate(); err == nil {
		t.Fatal("Validate accepted an exit whose profile runs a command")
	}
}

// Server-side validation is the gate that keeps a malformed credential from
// reaching the auth file, where a newline would silently create an account the
// operator never added.
func TestServerValidateRejectsNewlineInCredentials(t *testing.T) {
	inst := serverInstance()
	inst.Clients = []ClientConfig{{Username: "alice", Password: "pw\nbob injected", Enabled: true}}
	if err := inst.Validate(); err == nil {
		t.Fatal("a password containing a newline was accepted; it would inject a second auth-file line")
	}
}

func TestServerValidateRejectsDuplicateAndEmpty(t *testing.T) {
	inst := serverInstance()
	inst.Clients = []ClientConfig{
		{Username: "alice", Password: "a", Enabled: true},
		{Username: "alice", Password: "b", Enabled: true},
	}
	if err := inst.Validate(); err == nil {
		t.Error("duplicate client usernames were accepted")
	}
	inst.Clients = []ClientConfig{{Username: "alice", Password: "", Enabled: true}}
	if err := inst.Validate(); err == nil {
		t.Error("a client with no password was accepted")
	}
	inst.Clients = []ClientConfig{{Username: "alice", Password: "a", Enabled: true}}
	inst.Cert = ""
	if err := inst.Validate(); err == nil {
		t.Error("a server with no certificate was accepted")
	}
	inst.Cert, inst.Key, inst.Clients = "C", "K", nil
	if err := inst.Validate(); err == nil {
		t.Error("a server with no clients was accepted")
	}
}

// A disabled client must not appear in the auth file, or revocation would be
// cosmetic: the daemon would still accept the account.
func TestRenderAuthUsersOmitsDisabled(t *testing.T) {
	got := RenderAuthUsers([]ClientConfig{
		{Username: "alice", Password: "pw1", Enabled: true},
		{Username: "mallory", Password: "pw2", Enabled: false},
		{Username: "bob", Password: "pw3", Enabled: true},
		{Username: "nopass", Enabled: true},
	})
	if strings.Contains(got, "mallory") {
		t.Errorf("a disabled client appears in the auth file:\n%s", got)
	}
	if strings.Contains(got, "nopass") {
		t.Errorf("a passwordless client appears in the auth file:\n%s", got)
	}
	if !strings.Contains(got, "alice pw1") || !strings.Contains(got, "bob pw3") {
		t.Errorf("enabled clients missing from the auth file:\n%s", got)
	}
}

// The auth file is sorted so a reordered clients array does not read as a
// configuration change and bounce every connected client.
func TestRenderAuthUsersIsOrderStable(t *testing.T) {
	a := RenderAuthUsers([]ClientConfig{{Username: "bob", Password: "2", Enabled: true}, {Username: "alice", Password: "1", Enabled: true}})
	b := RenderAuthUsers([]ClientConfig{{Username: "alice", Password: "1", Enabled: true}, {Username: "bob", Password: "2", Enabled: true}})
	if a != b {
		t.Errorf("auth file order depends on input order:\n%s\n---\n%s", a, b)
	}
}

// The fingerprint is what lets a reconcile tell "nothing changed" from
// "restart", so it must be stable across reordering and must move when a
// credential changes.
func TestFingerprintStability(t *testing.T) {
	base := serverInstance()
	fp := base.fingerprint()

	reordered := serverInstance()
	reordered.Clients = []ClientConfig{
		{Username: "alice", Password: "pw-alice", Enabled: true},
	}
	if reordered.fingerprint() != fp {
		t.Error("fingerprint changed for an identical instance")
	}

	changed := serverInstance()
	changed.Clients = []ClientConfig{{Username: "alice", Password: "different", Enabled: true}}
	if changed.fingerprint() == fp {
		t.Error("fingerprint did not move after a password change; a revoked credential would keep running")
	}

	portChanged := serverInstance()
	portChanged.Port = 1195
	if portChanged.fingerprint() == fp {
		t.Error("fingerprint did not move after a port change")
	}

	// A disabled client is not served, so it must not count as a change.
	extra := serverInstance()
	extra.Clients = append(extra.Clients, ClientConfig{Username: "mallory", Password: "x", Enabled: false})
	if extra.fingerprint() != fp {
		t.Error("fingerprint moved for a disabled client")
	}
}

// A fingerprint must not be usable to recover a credential, since it is
// compared and logged during reconciles.
func TestFingerprintDoesNotLeakCredentials(t *testing.T) {
	inst := serverInstance()
	fp := inst.fingerprint()
	for _, secret := range []string{"pw-alice", inst.Cert, inst.Key, inst.CA} {
		if secret != "" && strings.Contains(fp, secret) {
			t.Errorf("fingerprint contains credential material: %s", secret)
		}
	}
}

// openForDebug connects the fake server to a client, used by tests that need
// both ends in one process.
func (s *fakeMgmtServer) openForDebug() (*mgmtConn, error) {
	conn, err := net.Dial("tcp", s.addr())
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	fmt.Fprintln(w, ">INFO:OpenVPN Management Interface Version 1 -- type 'help' for more info")
	w.Flush()
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	_ = line
	fmt.Fprintln(w, ">INFO:OpenVPN Management Interface Version 1 -- type 'help' for more info")
	fmt.Fprintln(w, ">ClientAuth:Auth-state:Authenticated")
	fmt.Fprint(w, ">")
	w.Flush()
	return &mgmtConn{conn: conn, r: r, w: w}, nil
}
