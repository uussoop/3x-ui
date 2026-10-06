package ikev2

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/vpn"
)

// fakeVICI is an in-process strongSwan stand-in speaking the real VICI wire
// protocol over a real UNIX socket: 12-byte header (length, type, flags, two
// reserved bytes, group, version, command id) followed by the INI payload.
//
// Testing against a fake rather than a live charon is deliberate. charon is a
// system daemon that needs root, XFRM state and a network path to establish a
// real SA; what actually needs testing here is the panel's side: that it sends
// the right sections, reads the SA table correctly, treats a rekey counter reset
// as a reset, and fails closed when the socket is unreachable. All of that is
// reachable over a socket.
type fakeVICI struct {
	t  *testing.T
	ln net.Listener
	// dir is the socket's parent; on macOS a UNIX socket path is limited to
	// ~104 bytes, so a temp dir is used rather than the test name.
	dir string

	mu       sync.Mutex
	requests [][]Section
	// sas is returned by list-sas, one queued table per call; the last repeats.
	sas [][]string
	// rejectLoad makes load-conn fail, mimicking a config strongSwan refuses.
	rejectLoad string
	// rejectSection makes load-conn fail only when the request carries that
	// section, which is what a daemon refusing one bad part of a connection looks
	// like. It is the only way to exercise a rollback: a blanket refusal would
	// also refuse the reloading of the previous configuration, so a rollback
	// could never be shown to work.
	rejectSection string
	// terminateErr, when set, is returned instead of acknowledging terminate.
	terminateErr string
	loaded       map[string]bool
	initiated    []string
	terminated   []string
	unloaded     []string
	conns        int
	// closeAfter drops the connection after serving this many requests, which is
	// how a charon restart under the panel is reproduced.
	closeAfter int
}

func newFakeVICI(t *testing.T) *fakeVICI {
	t.Helper()
	// darwin caps a UNIX socket path at ~104 bytes and t.TempDir() embeds the
	// (long) test name, so a socket there cannot be bound. A short directory in
	// the system temp dir is the only way to get a usable path here.
	dir, err := os.MkdirTemp("", "ik")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ln, err := net.Listen("unix", filepath.Join(dir, "c.vici"))
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	s := &fakeVICI{t: t, ln: ln, dir: dir, loaded: map[string]bool{}}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *fakeVICI) path() string { return s.ln.Addr().String() }

// setSAs queues the SA-table replies, one per list-sas call. A single argument
// repeats forever, which is what a steady-state tunnel wants.
func (s *fakeVICI) setSAs(replies ...[]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sas = replies
}

// setSAsOnce queues exactly one SA-table reply and then returns an empty table,
// modelling a tunnel that comes up and then loses its peer.
func (s *fakeVICI) setSAsOnce(replies ...[]string) {
	s.setSAs(append(replies, nil)...)
}

func (s *fakeVICI) nextSAs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sas) == 0 {
		return nil
	}
	if len(s.sas) == 1 {
		return s.sas[0]
	}
	out := s.sas[0]
	s.sas = s.sas[1:]
	return out
}

func (s *fakeVICI) log() [][]Section {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]Section(nil), s.requests...)
}

// commandSections returns only the request sections whose name matches, i.e. the
// actual commands rather than the configuration sections sent alongside them.
func (s *fakeVICI) commandSections(name string) []Section {
	var out []Section
	for _, req := range s.log() {
		for _, sec := range req {
			if sec.Name == name {
				out = append(out, sec)
			}
		}
	}
	return out
}

func (s *fakeVICI) allRequestSections() []Section {
	var out []Section
	for _, req := range s.log() {
		out = append(out, req...)
	}
	return out
}

// loadAttempts counts how many times the panel tried to load a connection.
//
// The command name is a VICI message name rather than a payload section, so the
// count has to come from the configuration sections a load carries. This matters
// for the retry tests: what is being counted is attempts, not outcomes.
func (s *fakeVICI) loadAttempts(conn string) int {
	prefix := "connections." + conn
	n := 0
	for _, req := range s.log() {
		for _, sec := range req {
			if sec.Name == prefix {
				n++
				break
			}
		}
	}
	return n
}

// connections lists the connection names charon currently holds, so a test can
// assert that a refused load did not reach the daemon.
func (s *fakeVICI) connections() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.loaded))
	for name := range s.loaded {
		// Only top-level connections: load-conn also registers per-account
		// subsections, and those are not separate connections.
		if !strings.HasPrefix(name, "xui-") || strings.Contains(name, ".") {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func (s *fakeVICI) isLoaded(conn string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loaded[conn]
}

func (s *fakeVICI) terminations() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.terminated...)
}

func (s *fakeVICI) serve() {
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

func (s *fakeVICI) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	served := 0
	for {
		payload, err := readVICIMessage(conn)
		if err != nil {
			return
		}
		s.mu.Lock()
		s.requests = append(s.requests, parseSections(payload))
		closeAfter := s.closeAfter
		s.mu.Unlock()
		served++
		if closeAfter > 0 && served > closeAfter {
			// charon restarted: drop the socket without a reply.
			return
		}
		s.reply(conn, parseSections(payload))
	}
}

// reply answers one whole message with a single reply, which is how charon
// behaves: a request message can carry several configuration sections and is
// acknowledged once. Replying per section instead would leave unsolicited
// replies on the socket and desynchronise every request after the first.
func (s *fakeVICI) reply(conn net.Conn, sections []Section) {
	if len(sections) == 0 {
		writeVICIMessage(conn, viciTypeResponse, "")
		return
	}
	switch sections[0].Name {
	case "list-sas":
		var b strings.Builder
		for _, sa := range s.nextSAs() {
			b.WriteString(sa)
		}
		writeVICIMessage(conn, viciTypeResponse, b.String())
		return
	case "unload-conn":
		s.mu.Lock()
		delete(s.loaded, sections[0].get("name"))
		s.unloaded = append(s.unloaded, sections[0].get("name"))
		s.mu.Unlock()
		writeVICIMessage(conn, viciTypeResponse, "")
		return
	case "terminate":
		s.mu.Lock()
		s.terminated = append(s.terminated, sections[0].get("peer-id")+"|"+sections[0].get("ike"))
		errMsg := s.terminateErr
		s.mu.Unlock()
		writeVICIMessage(conn, viciTypeResponse, errorMessage(errMsg))
		return
	case "initiate":
		s.mu.Lock()
		s.initiated = append(s.initiated, sections[0].get("child"))
		s.mu.Unlock()
		writeVICIMessage(conn, viciTypeResponse, "")
		return
	}

	s.mu.Lock()
	reject := s.rejectLoad
	if reject == "" && s.rejectSection != "" {
		for _, sec := range sections {
			if sec.Name == s.rejectSection {
				reject = s.rejectSection + ": refused by test"
				break
			}
		}
	}
	if reject == "" {
		for _, sec := range sections {
			// A connection section is what makes charon consider the connection
			// loaded; the name is the section's own suffix, which is exactly what
			// unload-conn later refers to.
			if strings.HasPrefix(sec.Name, "connections.") {
				s.loaded[strings.TrimPrefix(sec.Name, "connections.")] = true
			}
		}
	}
	s.mu.Unlock()
	if reject != "" {
		writeVICIMessage(conn, viciTypeResponse, errorMessage(reject))
		return
	}
	writeVICIMessage(conn, viciTypeResponse, "")
}

// errorMessage renders a VICI error section, or an empty payload for success.
func errorMessage(msg string) string {
	if msg == "" {
		return ""
	}
	return "error = {\nkind = " + quoteValue(errorKind(msg)) + "\nmessage = " + quoteValue(msg) + "\n}\n"
}

func errorKind(msg string) string {
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "no such"), strings.Contains(low, "not found"):
		return "NO_CONN"
	case strings.Contains(low, "no active"):
		return "NO_CHILD_SA"
	default:
		return "GENERIC_ERROR"
	}
}

func readVICIMessage(r io.Reader) (string, error) {
	var hdr [12]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return "", err
	}
	length := binary.BigEndian.Uint32(hdr[0:4])
	if length < uint32(len(hdr)) {
		return "", fmt.Errorf("short header")
	}
	buf := make([]byte, length-uint32(len(hdr)))
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func writeVICIMessage(w io.Writer, typ byte, payload string) {
	body := []byte(payload)
	total := 12 + len(body)
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint32(hdr[0:4], uint32(total))
	hdr[4] = typ
	// group/version/command-id stay zero: the panel ignores them and a real
	// daemon would only use them to pair replies with requests.
	_, _ = w.Write(append(hdr, body...))
}

// newTestManager returns a Manager pointed at a fresh fake daemon, with the
// state directory redirected into the test's temp dir so no test writes into the
// repository's bin folder.
func newTestManager(t *testing.T, srv *fakeVICI) *Manager {
	t.Helper()
	t.Setenv("XUI_BIN_FOLDER", t.TempDir())
	m := &Manager{adapters: map[int]*adapter{}, path: srv.path()}
	return m
}

func testServerInstance() Instance {
	return Instance{
		ID:            7,
		Tag:           "ike-in",
		Role:          "server",
		Listen:        "0.0.0.0",
		Port:          500,
		Subnet:        "10.10.0.0/24",
		DNSServer:     "1.1.1.1",
		HostCert:      "HOST CERT",
		HostKey:       "HOST KEY",
		CA:            "CA CERT",
		UniqueIDs:     true,
		Clients:       []ClientConfig{{Username: "alice", Password: "pw-alice", ID: "alice", Enabled: true}},
		XrayRoutePort: 1080,
	}
}

func testExitInstance() Instance {
	return Instance{
		ID:           9,
		Tag:          "ike-out",
		Role:         "client",
		Remote:       "vpn.example.com",
		RemotePort:   500,
		Username:     "bob",
		Password:     "pw-bob",
		Identity:     "xui-exit-9",
		ReqID:        4009,
		IKEVersion:   2,
		NATTraversal: true,
	}
}

func newTestAdapter(t *testing.T, m *Manager, srv *fakeVICI, inst Instance) *adapter {
	t.Helper()
	a := &adapter{inst: inst, mgr: m, fingerprint: inst.fingerprint(), retry: vpn.NewRetry()}
	m.adapters[inst.ID] = a
	return a
}

// exitSA is one established child SA on an exit, in strongSwan's own shape.
// conn is the connection name the SA belongs to, which is what the panel filters
// on to keep one exit's traffic out of another's totals.
func exitSA(conn, inner, peer string, in, out int64, counters bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "ike-sa = {\nuniqueid = 1\nname = %s\nremote-host = %s\n", conn, peer)
	fmt.Fprintf(&b, "child-sa = {\nname = %s\nchild-remote-addrs = %s\n", conn, inner)
	if counters {
		fmt.Fprintf(&b, "bytes-in = %d\nbytes-out = %d\n", in, out)
	}
	b.WriteString("peer-id = bob\n}\n}\n")
	return b.String()
}

// serverSA is one established child SA on the responder, attributed to a panel
// account.
func serverSA(conn, inner, email string, in, out int64) string {
	var b strings.Builder
	fmt.Fprintf(&b, "ike-sa = {\nuniqueid = 2\nname = %s\n", conn)
	fmt.Fprintf(&b, "child-sa = {\nname = %s\nchild-remote-addrs = %s\n", conn, inner)
	fmt.Fprintf(&b, "bytes-in = %d\nbytes-out = %d\npeer-id = %s\n}\n}\n", in, out, email)
	return b.String()
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
