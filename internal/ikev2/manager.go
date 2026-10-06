package ikev2

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/config"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/vpn"
)

// stateDir is where charon's own state (the swanctl.conf the panel generated,
// and the secrets it references) lives. It is separate from the openvpn package's
// directory so neither adapter can read or clobber the other's files.
func stateDir() string { return config.GetBinFolderPath() + "/ikev2" }

// connConfPath is the swanctl.conf fragment for one instance. charon reads the
// panel's own generated file rather than being handed configuration only in
// memory, so a restarted charon recovers the panel's tunnels without the panel
// having to be running.
func connConfPath(inst Instance) string {
	return filepath.Join(stateDir(), fmt.Sprintf("%s.conf", inst.instanceName()))
}

// markerPath records that an instance's configuration has been loaded into the
// running charon. Its presence is what makes Start idempotent across panel
// restarts: the connection is already live in a daemon that outlived us.
func markerPath(inst Instance) string {
	return filepath.Join(stateDir(), fmt.Sprintf("%s.loaded", inst.instanceName()))
}

// Validate checks an instance without touching the daemon. It is the gate that
// keeps a broken tunnel from being loaded into a privileged daemon.
func (inst Instance) Validate() error {
	// An empty probe target is legitimate — the tunnel is then judged on whether
	// it holds a child SA. A non-empty one is checked here rather than at the
	// point of use, so a typo is refused when it is entered instead of showing up
	// later as a tunnel that reports a probe failure for unrelated reasons.
	if target := strings.TrimSpace(inst.ProbeTarget); target != "" {
		if err := vpn.ValidateProbeTarget(target); err != nil {
			return err
		}
	}
	// Every value charon reads as a single line has to be one. The payload
	// escapes a newline, so this cannot splice a section in — but charon would
	// still refuse the address, and the operator would be handed a strongSwan
	// error with nothing to connect it to the field that produced it. Cert
	// material is deliberately absent from this list: PEM blocks are
	// multi-line by nature.
	for _, f := range []struct{ name, value string }{
		{"remote", inst.Remote},
		{"listen address", inst.Listen},
		{"dns server", inst.DNSServer},
		{"remote identity", inst.RemoteID},
		{"local address", inst.LocalAddr},
	} {
		if strings.ContainsAny(f.value, "\r\n") {
			return fmt.Errorf("%s contains a newline", f.name)
		}
	}
	if !inst.isServer() {
		host := strings.TrimSpace(inst.Remote)
		if host == "" {
			return fmt.Errorf("exit tunnel has no remote server")
		}
		if inst.RemotePort < 0 || inst.RemotePort > 65535 {
			return fmt.Errorf("remote port %d is out of range", inst.RemotePort)
		}
		if strings.ContainsAny(inst.Username, "\r\n") || strings.ContainsAny(inst.Password, "\r\n") {
			return fmt.Errorf("exit credentials contain a newline")
		}
		if inst.authMethod() == "cert" && (inst.ClientCert == "" || inst.ClientKey == "") {
			return fmt.Errorf("certificate authentication needs both a client certificate and key")
		}
		if inst.ReqID < 0 {
			return fmt.Errorf("reqid %d is out of range", inst.ReqID)
		}
		return nil
	}

	// Only a responder listens, so only it has a port to validate; an exit
	// carries no local port.
	if inst.Port <= 0 || inst.Port > 65535 {
		return fmt.Errorf("port %d is out of range", inst.Port)
	}
	if inst.Subnet == "" {
		return fmt.Errorf("server tunnel has no address pool for clients")
	}
	if !validSubnet(inst.Subnet) {
		return fmt.Errorf("subnet %q is not a valid network", inst.Subnet)
	}
	switch inst.authMethod() {
	case "eap-mschapv2", "cert", "psk":
	default:
		return fmt.Errorf("unknown authentication method %q", inst.AuthMethod)
	}
	if inst.authMethod() == "cert" && strings.TrimSpace(inst.CA) == "" {
		// Without a trust anchor a client's certificate is accepted from anyone,
		// which is strictly worse than password auth.
		return fmt.Errorf("certificate authentication needs a CA certificate")
	}
	if inst.authMethod() == "psk" && strings.TrimSpace(inst.PSK) == "" {
		return fmt.Errorf("pre-shared key authentication needs a key")
	}
	// A responder with no accounts would still answer IKE_SA_INIT and then fail
	// every authentication, which reads as a broken tunnel rather than as "no
	// one is allowed".
	if len(inst.Clients) == 0 {
		return fmt.Errorf("server tunnel has no enabled clients")
	}
	seen := map[string]struct{}{}
	for _, c := range inst.Clients {
		if !c.Enabled {
			continue
		}
		user := strings.TrimSpace(c.Username)
		if user == "" {
			return fmt.Errorf("a client has no username")
		}
		// A newline would inject a second section into the VICI payload,
		// silently creating an account the operator never added.
		if strings.ContainsAny(c.Username, "\r\n") || strings.ContainsAny(c.Password, "\r\n") {
			return fmt.Errorf("client %q has a credential containing a newline", user)
		}
		if c.Password == "" {
			return fmt.Errorf("client %q has no password", user)
		}
		if _, dup := seen[user]; dup {
			return fmt.Errorf("duplicate client username %q", user)
		}
		seen[user] = struct{}{}
	}
	return nil
}

// validSubnet is a deliberately narrow CIDR check. It accepts what a tunnel pool
// needs and rejects the malformed strings that would otherwise be handed to
// charon, where the failure surfaces as an unrelated daemon error.
func validSubnet(s string) bool {
	ip, bits, ok := strings.Cut(strings.TrimSpace(s), "/")
	if !ok || bits == "" {
		return false
	}
	n, err := strconv.Atoi(bits)
	if err != nil {
		return false
	}
	switch {
	case strings.Contains(ip, "."):
		if n < 0 || n > 32 {
			return false
		}
	case strings.Contains(ip, ":"):
		if n < 0 || n > 128 {
			return false
		}
	default:
		return false
	}
	return true
}

// adapter is the per-tunnel vpn.Adapter. One exists per managed tunnel; the
// Manager owns them. Unlike OpenVPN there is no per-tunnel process: charon is
// shared, so this adapter's "connected" state is whether charon loaded the
// connection, and "healthy" is whether it currently holds an established IKE_SA.
type adapter struct {
	inst Instance
	mgr  *Manager

	mu          sync.Mutex
	fingerprint string
	loaded      bool
	applied     bool
	// retry is this connection's own load backoff, so a broken exit cannot
	// throttle a healthy inbound.
	retry *vpn.Retry

	// last* is the previous counters snapshot. charon's SA byte counters reset
	// on every rekey, so a raw difference across a rekey would book a huge
	// negative (or, unsigned, huge positive) delta.
	lastUp          int64
	lastDown        int64
	lastHadCounters bool

	sessions     map[string]saInfo
	firstSeen    map[string]time.Time
	lastProbe    time.Time
	probeLatency time.Duration
	// probePinned records that the last latency measurement's socket was bound
	// to the tunnel device. Unpinned means the measurement followed the routing
	// table, which is weaker evidence and is reported as such rather than
	// presented as proof the traffic stayed in the tunnel.
	probePinned bool
	healthy     bool
	failures    int
	lastPollErr string
	lastError   string
}

// Validate implements vpn.Adapter.
func (a *adapter) Validate() error { return a.inst.Validate() }

// Apply renders the instance's swanctl.conf. It is idempotent: the rendered
// bytes depend only on the instance, so applying twice produces the same file.
//
// Secrets are written 0600 in their own files and referenced from the config
// rather than inlined, because a file an operator can read is a file an operator
// can also paste elsewhere. Where a value genuinely cannot be referenced from
// disk — an account password, which charon reads from the message or a secrets
// file — it is kept out of the config entirely and passed at load time.
func (a *adapter) Apply() error {
	if err := a.inst.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir(), 0o750); err != nil {
		return err
	}
	if err := a.inst.writeSecretFiles(); err != nil {
		return err
	}
	rendered := renderConf(a.inst)
	if err := os.WriteFile(connConfPath(a.inst), []byte(rendered), 0o600); err != nil {
		return err
	}
	a.mu.Lock()
	a.applied = true
	a.mu.Unlock()
	return nil
}

func (a *adapter) applyLocked() error {
	if err := a.inst.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir(), 0o750); err != nil {
		return err
	}
	if err := a.inst.writeSecretFiles(); err != nil {
		return err
	}
	if err := os.WriteFile(connConfPath(a.inst), []byte(renderConf(a.inst)), 0o600); err != nil {
		return err
	}
	a.applied = true
	return nil
}

// Start loads the connection into charon and, for an exit, initiates the IKE_SA.
// It is idempotent: a tunnel already loaded with the same fingerprint is left
// alone, so a panel restart does not tear down tunnels that are fine.
// Start loads the connection into charon, or initiates the tunnel for an exit.
//
// It is idempotent: a connection already loaded with the same configuration is
// left alone, which is what makes a panel restart harmless — the connection
// survived in a daemon that outlived the panel.
func (a *adapter) Start(ctx context.Context) error {
	err := a.start(ctx)
	if err != nil {
		// Every failed attempt counts towards this connection's own backoff.
		// Without this a configuration charon keeps refusing would be re-sent on
		// every reconcile tick — load, log noise, and nothing gained.
		a.retry.Fail()
		return err
	}
	// A connection that came up must be eligible for the next change
	// immediately, not after a delay its previous failure earned.
	a.retry.OK()
	return nil
}

func (a *adapter) start(ctx context.Context) error {
	if err := a.inst.Validate(); err != nil {
		return err
	}
	if err := a.mgr.dial(); err != nil {
		a.setError(err)
		return err
	}
	a.mu.Lock()
	already := a.loaded && a.fingerprint == a.inst.fingerprint()
	a.mu.Unlock()
	if already {
		return nil
	}
	if err := a.applyLocked(); err != nil {
		a.setError(err)
		return err
	}
	if err := a.mgr.loadConnection(a.inst); err != nil {
		a.setError(err)
		return err
	}
	// A new daemon's counters start over, so the previous snapshot must not be
	// carried across or the first poll would report a huge negative delta.
	a.mu.Lock()
	a.loaded = true
	a.fingerprint = a.inst.fingerprint()
	a.lastUp, a.lastDown, a.lastHadCounters = 0, 0, false
	a.healthy = false
	a.failures = 0
	a.mu.Unlock()
	if err := touchMarker(a.inst); err != nil {
		logger.Warningf("ikev2: marking tunnel %d loaded failed: %v", a.inst.ID, err)
	}
	logger.Infof("ikev2: loaded %s connection %s", a.inst.role(), a.inst.instanceName())
	if !a.inst.isServer() {
		if err := a.mgr.initiate(a.inst); err != nil {
			// The connection is loaded and charon will retry the SA on its own
			// schedule; a failed initiation is a health problem, not a load
			// failure, so it does not unwind the load.
			a.setError(err)
			logger.Warningf("ikev2: initiating exit %d failed: %v", a.inst.ID, err)
		}
	}
	return nil
}

// Stop unloads the connection and, for an exit, terminates its IKE_SA. Other
// tunnels keep theirs: each is a separate connection with its own reqid, so
// unloading one cannot disturb another.
func (a *adapter) Stop(_ context.Context) error {
	a.mu.Lock()
	loaded := a.loaded
	a.mu.Unlock()
	if !loaded {
		return nil
	}
	var firstErr error
	if err := a.mgr.dial(); err != nil {
		firstErr = err
	} else {
		if !a.inst.isServer() {
			if err := a.mgr.terminate(a.inst, ""); err != nil && !isNoSuchConn(err) {
				firstErr = err
			}
		}
		if err := a.mgr.unloadConnection(a.inst); err != nil && !isNoSuchConn(err) {
			firstErr = err
		}
	}
	_ = os.Remove(markerPath(a.inst))
	a.mu.Lock()
	a.loaded = false
	a.healthy = false
	a.sessions = nil
	a.mu.Unlock()
	if firstErr != nil {
		a.setError(firstErr)
		return firstErr
	}
	logger.Infof("ikev2: unloaded %s connection %s", a.inst.role(), a.inst.instanceName())
	return nil
}

func isNoSuchConn(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such") || strings.Contains(msg, "not found") ||
		strings.Contains(msg, "unable to find") || strings.Contains(msg, "does not exist")
}

// Status returns the configured/connected/healthy split. For an exit, only an
// established child SA plus a passing probe proves the tunnel works, so healthy
// is never inferred from "the config was accepted"; for a responder it means
// charon is loaded and answering, since an idle inbound has nothing else it can
// be asked.
func (a *adapter) Status() vpn.State {
	a.mu.Lock()
	healthy := a.healthy
	latency := a.probeLatency
	lastProbe := a.lastProbe
	probeErr := a.lastPollErr
	lastErr := a.lastError
	failures := a.failures
	applied := a.applied
	loaded := a.loaded
	sessions := len(a.sessions)
	pinned := a.probePinned
	a.mu.Unlock()

	st := vpn.State{
		Role:        a.inst.role(),
		Configured:  applied && configExists(a.inst),
		Connected:   loaded,
		Healthy:     healthy,
		Latency:     latency,
		LastProbe:   lastProbe,
		ProbeErr:    probeErr,
		ProbePinned: pinned,
		LastError:   lastErr,
	}
	_ = failures
	_ = sessions
	if !st.Healthy && st.ProbeErr == "" {
		switch {
		case !st.Connected:
			st.ProbeErr = "connection is not loaded in strongSwan"
		default:
			st.ProbeErr = "no established IKE_SA yet"
		}
	}
	return st
}

func configExists(inst Instance) bool {
	_, err := os.Stat(connConfPath(inst))
	return err == nil
}

// ListSessions returns the established child SAs mapped onto panel accounts.
func (a *adapter) ListSessions() ([]vpn.Session, error) {
	sas, err := a.poll()
	if err != nil {
		return nil, err
	}
	out := make([]vpn.Session, 0, len(sas))
	for _, s := range sas {
		sess := vpn.Session{
			Username:    s.Username,
			IP:          s.InnerIP,
			RealAddress: s.RemoteIP,
			UpBytes:     s.BytesIn,
			DownBytes:   s.BytesOut,
			Since:       s.Since,
		}
		out = append(out, sess)
	}
	return out, nil
}

// DisconnectSession terminates one account's IKE_SA. Only that SA is torn down;
// every other client keeps its session, which is why this is preferred over
// reloading the whole connection to revoke access.
func (a *adapter) DisconnectSession(username string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return fmt.Errorf("no username given")
	}
	if err := a.mgr.dial(); err != nil {
		return err
	}
	// A session that is already gone is not an error: the desired state (this
	// account has no tunnel) is already satisfied, and reporting a failure would
	// make a revocation race look like a bug.
	err := a.mgr.terminate(a.inst, username)
	if err != nil && (isNoSuchConn(err) || strings.Contains(strings.ToLower(err.Error()), "no active")) {
		return nil
	}
	return err
}

// probeThrough measures a tunnel's data plane. It is a variable so the health
// policy that consumes it — which exit is reported usable, and why — can be
// tested on a machine with no tunnel device. The probe itself is tested on its
// own terms in package vpn; what is stubbed here is the call site, never the
// measurement a real tunnel gets.
var probeThrough = vpn.TCPProbe

// probe measures an exit's data plane through the tunnel.
//
// An exit with no operator-chosen target is not probed: inventing a target
// would send the panel's own traffic to a third party the operator never
// chose. A responder is never probed either — the panel has no traffic of its
// own to send into an inbound, so there is no probe it could honestly make.
func (a *adapter) probe(haveSA bool) (vpn.ProbeResult, bool) {
	target := strings.TrimSpace(a.inst.ProbeTarget)
	if a.inst.isServer() || target == "" || !haveSA {
		return vpn.ProbeResult{}, false
	}
	res, pinned, _ := probeThrough(context.Background(), target, a.inst.probeDevice(), vpn.DefaultProbeTimeout)
	return res, pinned
}

// poll reads the daemon's child SA table and updates health and counter state.
// This is the only place that talks to charon, so health and counters can never
// disagree about what the daemon actually reports.
func (a *adapter) poll() ([]saInfo, error) {
	sas, err := a.mgr.listSAs(a.inst)
	if err != nil {
		a.mu.Lock()
		defer a.mu.Unlock()
		a.lastProbe = time.Now()
		a.healthy = false
		a.failures++
		a.lastPollErr = sanitizeErr(err)
		a.sessions = nil
		return nil, err
	}

	// The tunnel's own latency comes from a probe through it, measured outside
	// the lock because it dials. A VICI round trip must not stand in for it:
	// that measures the daemon over a local socket, and reporting it as tunnel
	// latency would have an operator reading a local IPC timing as VPN
	// performance.
	measured, pinned := a.probe(len(sas) > 0)

	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastProbe = time.Now()
	a.lastPollErr = ""
	a.probeLatency = measured.Latency
	a.probePinned = pinned

	if a.inst.isServer() {
		// A responder whose poll succeeded is serving: it is loaded, charon
		// answered, and holding nobody is the normal idle state of an inbound.
		// Reporting an idle inbound as unhealthy would flicker every quiet
		// inbound red and teach an operator to ignore the colour.
		a.healthy = true
	} else {
		// An exit is only usable once it actually holds a child SA. Reporting
		// healthy on a loaded-but-unestablished connection would let an
		// unreachable tunnel into the selector and leak traffic past the exit —
		// and a child SA alone is not enough when the operator asked for a
		// probe, because the SA can be up while the tunnel's routing is broken.
		switch {
		case len(sas) == 0:
			a.healthy = false
			a.failures++
			a.lastPollErr = "exit has no established child SA"
		case a.inst.ProbeTarget != "" && !measured.OK:
			a.healthy = false
			a.failures++
			a.lastPollErr = "probe through the tunnel failed: " + measured.Err
		default:
			a.healthy = true
			a.lastPollErr = ""
		}
	}
	if a.healthy {
		a.failures = 0
	}

	a.sessions = make(map[string]saInfo, len(sas))
	now := time.Now()
	// Indexed, not ranged: the session age is filled in here and has to reach
	// the slice the caller receives, not just this loop's copy.
	for i := range sas {
		s := &sas[i]
		if s.Username == "" {
			continue
		}
		// strongSwan's "installed" is a monotonic offset, not a wall clock, so
		// the age shown for a session is when the panel first saw it — the only
		// time the panel can actually vouch for. A build that does report a real
		// timestamp wins, since then the panel is not guessing.
		if s.Since.IsZero() {
			seen, ok := a.firstSeen[s.Username]
			if !ok {
				seen = now
				if a.firstSeen == nil {
					a.firstSeen = map[string]time.Time{}
				}
				a.firstSeen[s.Username] = seen
			}
			s.Since = seen
		}
		a.sessions[s.Username] = *s
	}
	// An SA that is gone must not keep its remembered age: reusing it for the
	// next session of the same account would report a session that had been up
	// since the previous one.
	for name := range a.firstSeen {
		if _, ok := a.sessions[name]; !ok {
			delete(a.firstSeen, name)
		}
	}
	return sas, nil
}

// countTraffic is Counters plus the per-session breakdown. The vpn.Adapter
// contract only exposes the tunnel totals; accounting additionally needs to know
// which account the bytes belong to, so the richer form stays package-internal
// and Counters adapts it to the contract.
type countTraffic struct {
	counters vpn.Counters
	byUser   map[string]vpn.Session
}

// countTraffic polls charon and returns the tunnel totals and per-account bytes
// as accounting deltas.
//
// The daemon's counters are cumulative and reset on every rekey, which happens
// routinely on a long-lived SA. Taking a raw difference across such a reset
// would book a huge negative delta. So a decrease is treated as a counter reset:
// the new value becomes this interval's delta, which is correct because
// everything before the reset was already booked.
func (a *adapter) countTraffic() countTraffic {
	sas, err := a.poll()
	if err != nil {
		// A failed poll reports the last known totals rather than zeroes: the
		// accounting job must not book a sudden drop in traffic because the VICI
		// socket was briefly unreachable.
		a.mu.Lock()
		up, down := a.lastUp, a.lastDown
		a.mu.Unlock()
		return countTraffic{counters: vpn.Counters{UpBytes: max64(up, 0), DownBytes: max64(down, 0)}}
	}

	// Only an SA with an inner address is carrying traffic. A half-configured SA
	// reports no counters, and including it would show the tunnel as idle when it
	// is in fact moving bytes.
	up, down := int64(0), int64(0)
	has := false
	for _, s := range sas {
		if s.InnerIP == "" {
			continue
		}
		// A counter of -1 means charon reported none, not zero bytes; summing it
		// would cancel out a real counter on the same tunnel.
		if s.BytesIn >= 0 {
			up += s.BytesIn
		}
		if s.BytesOut >= 0 {
			down += s.BytesOut
		}
		has = true
	}

	a.mu.Lock()
	prevUp, prevDown := a.lastUp, a.lastDown
	deltaUp, deltaDown := up, down
	if a.lastHadCounters && has && up >= prevUp && down >= prevDown {
		deltaUp, deltaDown = up-prevUp, down-prevDown
	}
	a.lastUp, a.lastDown, a.lastHadCounters = up, down, has
	failures := a.failures
	a.mu.Unlock()

	byUser := make(map[string]vpn.Session, len(sas))
	for _, s := range sas {
		if s.Username == "" {
			continue
		}
		byUser[s.Username] = vpn.Session{
			Username:    s.Username,
			IP:          s.InnerIP,
			RealAddress: s.RemoteIP,
			UpBytes:     s.BytesIn,
			DownBytes:   s.BytesOut,
			Since:       s.Since,
		}
	}
	return countTraffic{
		counters: vpn.Counters{
			UpBytes:             deltaUp,
			DownBytes:           deltaDown,
			Sessions:            len(sas),
			ConsecutiveFailures: failures,
		},
		byUser: byUser,
	}
}

// Counters returns the tunnel's byte delta since the previous poll.
func (a *adapter) Counters() vpn.Counters { return a.countTraffic().counters }

func (a *adapter) setError(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err == nil {
		a.lastError = ""
		return
	}
	a.lastError = sanitizeErr(err)
}

// Manager owns the set of connections loaded into charon, keyed by inbound id.
//
// Connections are loaded into one shared daemon rather than one daemon per
// tunnel, which is what makes a separate XFRM identity per exit possible: each
// exit is a distinct connection object with its own reqid/ID pair, so two exits
// never collide in kernel state.
type Manager struct {
	mu       sync.Mutex
	adapters map[int]*adapter

	// connMu serialises VICI access. The socket carries an asynchronous event
	// stream, so two concurrent requests would otherwise interleave and read each
	// other's replies. It is separate from mu because Ensure holds mu while
	// loading a connection, and a request is issued in the middle of that.
	connMu sync.Mutex
	conn   *VICI
	// pathMu guards path only, so the socket path can be read without taking
	// either of the other two.
	pathMu sync.Mutex
	path   string
}

var (
	managerOnce sync.Once
	manager     *Manager
)

// GetManager returns the process-wide IKEv2 manager singleton.
func GetManager() *Manager {
	managerOnce.Do(func() {
		manager = &Manager{adapters: map[int]*adapter{}, path: DefaultSocketPath()}
	})
	return manager
}

// SetSocketPath points the manager at a specific VICI socket. Used by tests and
// by an operator whose strongSwan is not on the default path.
func (m *Manager) SetSocketPath(path string) {
	m.pathMu.Lock()
	changed := m.path != path
	m.path = path
	m.pathMu.Unlock()
	if !changed {
		return
	}
	m.connMu.Lock()
	if m.conn != nil {
		_ = m.conn.Close()
		m.conn = nil
	}
	m.connMu.Unlock()
}

// SocketPath returns the VICI socket the manager talks to.
func (m *Manager) SocketPath() string {
	m.pathMu.Lock()
	defer m.pathMu.Unlock()
	return m.path
}

// dial returns a live VICI connection, opening one if needed. A stale socket —
// charon restarted under us — is discarded and reopened, so a daemon restart does
// not permanently break the panel's control.
//
// It deliberately does not take the Manager's own mutex: Ensure holds that one
// while it loads a connection, so reaching for it here would deadlock every
// reconcile tick against itself.
func (m *Manager) dial() error {
	m.connMu.Lock()
	defer m.connMu.Unlock()
	if m.conn != nil {
		return nil
	}
	path := m.SocketPath()
	if path == "" {
		path = DefaultSocketPath()
	}
	c, err := DialVICI(path, 3*time.Second)
	if err != nil {
		return err
	}
	m.conn = c
	return nil
}

// send runs one VICI request, reconnecting once if the socket went stale. A
// reconnect on the first attempt is safe because every request the panel makes
// is idempotent or explicitly load/unload of a named connection.
func (m *Manager) send(sections []Section) ([]Section, error) {
	if err := m.dial(); err != nil {
		return nil, err
	}
	m.connMu.Lock()
	c := m.conn
	m.connMu.Unlock()
	if c == nil {
		return nil, fmt.Errorf("strongSwan VICI is not connected")
	}
	reply, err := c.Send(sections)
	if err == nil {
		return reply, nil
	}
	m.connMu.Lock()
	if m.conn == c {
		_ = c.Close()
		m.conn = nil
	}
	m.connMu.Unlock()
	return nil, err
}

func (m *Manager) sendErr(err error, args ...any) error {
	logger.Debugf("ikev2: VICI request failed: "+err.Error(), args...)
	return err
}

// loadConnection loads an instance's connection, its child config, its auth
// definitions and the host identity it needs, in one message.
//
// Order matters: the identity sections must exist before the connection refers
// to them, so a first load in a fresh charon would otherwise be rejected for a
// missing certificate.
func (m *Manager) loadConnection(inst Instance) error {
	sections := RenderHostIdentity(inst)
	sections = append(sections, RenderAuth(inst)...)
	sections = append(sections, RenderConnection(inst)...)
	sections = append(sections, childSAConfig(inst)...)
	if _, err := m.send(sections); err != nil {
		return err
	}
	if !inst.isServer() {
		// An initiator with no TRIP yet never connects; kicking it is what turns
		// a loaded connection into a live one.
		if _, err := m.send([]Section{loadConnSection(inst)}); err != nil {
			return err
		}
	}
	return nil
}

func loadConnSection(inst Instance) Section {
	s := Section{Name: "load-conn"}
	s.Set("name", inst.instanceName())
	s.Set("load", "yes")
	return s
}

func (m *Manager) unloadConnection(inst Instance) error {
	s := Section{Name: "unload-conn"}
	s.Set("name", inst.instanceName())
	_, err := m.send([]Section{s})
	return err
}

// initiate asks charon to bring up the IKE_SA for an exit. Bounded: a refused
// initiation is reported to the caller and retried on the next reconcile tick
// rather than spun on.
func (m *Manager) initiate(inst Instance) error {
	s := Section{Name: "initiate"}
	s.Set("child", inst.instanceName())
	_, err := m.send([]Section{s})
	return err
}

// terminate tears down an account's IKE_SA on one connection. An empty username
// terminates the whole connection, which is how an exit is stopped.
func (m *Manager) terminate(inst Instance, username string) error {
	s := Section{Name: "terminate"}
	if strings.TrimSpace(username) == "" {
		s.Set("ike", inst.instanceName())
	} else {
		s.Set("ike", inst.instanceName())
		s.Set("peer-id", username)
		s.Set("child", inst.instanceName())
	}
	_, err := m.send([]Section{s})
	return err
}

// saInfo is one established child SA as the panel needs it.
type saInfo struct {
	Username string
	InnerIP  string
	RemoteIP string
	BytesIn  int64
	BytesOut int64
	// Since is when the panel first observed this SA, not when the peer claims
	// to have connected: strongSwan's own install time is a monotonic offset and
	// cannot be turned into a wall clock.
	Since time.Time
}

// listSAs reads the child SAs belonging to an instance.
//
// The SA table is read per instance rather than once globally because a child
// SA carries the connection it belongs to; reading everything and filtering in
// Go would put every tunnel's traffic in one place, which is exactly the
// confusion the per-exit identity split is meant to avoid.
func (m *Manager) listSAs(inst Instance) ([]saInfo, error) {
	reply, err := m.send([]Section{{Name: "list-sas"}})
	if err != nil {
		return nil, err
	}
	conn := inst.instanceName()
	var out []saInfo
	for _, s := range reply {
		if !strings.HasPrefix(s.Name, "ike-sa") && !strings.HasPrefix(s.Name, "child-sa") {
			continue
		}
		// Only SAs on this instance's connection count. Without the filter a
		// server tunnel would report every client's bytes for every other
		// tunnel.
		if owner := s.get("conn"); owner != "" && owner != conn {
			continue
		}
		if child := s.get("name"); child != "" && child != conn {
			continue
		}
		out = append(out, saInfo{
			Username: firstNonEmpty(s.get("peer-id"), s.get("remote-id")),
			InnerIP:  firstNonEmpty(s.get("child-remote-addrs"), s.get("child-local-addrs")),
			RemoteIP: s.get("remote-host"),
			BytesIn:  parseCounter(s.get("bytes-in")),
			BytesOut: parseCounter(s.get("bytes-out")),
			Since:    parseSAInstallTime(s.get("installed")),
		})
	}
	return out, nil
}

func (s Section) get(key string) string {
	for i, k := range s.Keys {
		if strings.EqualFold(k, key) {
			return s.Values[i]
		}
	}
	return ""
}

// parseSAInstallTime parses a strongSwan "installed" value. strongSwan reports
// this as seconds on its own monotonic clock, not a wall clock, so it is kept
// only for the builds that do report a real timestamp; the session age shown in
// the panel comes from when the panel first observed the SA instead, which is a
// fact the panel actually knows.
func parseSAInstallTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999",
		"2006-01-02 15:04:05",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// parseCounter reads a byte counter. An absent or unparseable counter is -1, not
// zero: charon omits counters for an SA that carries no traffic, and reporting
// that as zero traffic would book a false accounting entry.
func parseCounter(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" && false {
		return -1
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return -1
	}
	return n
}

// Ensure loads the tunnel for an instance, or reloads it when its configuration
// changed. A no-op when the desired tunnel is already loaded with the same
// configuration.
//
// It bypasses the restart backoff: an operator saving a corrected config must
// not have to wait out a delay earned by the broken one.
func (m *Manager) Ensure(inst Instance) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ensureLocked(inst, true)
}

// ensureLocked converges one connection. force skips the backoff; the periodic
// reconcile passes false so a connection that will not load is not retried on
// every tick, while an explicit save passes true.
func (m *Manager) ensureLocked(inst Instance, force bool) error {
	if err := inst.Validate(); err != nil {
		// A refused configuration must not leave a half-loaded connection behind.
		return err
	}
	cur, exists := m.adapters[inst.ID]
	if exists {
		cur.mu.Lock()
		same := cur.loaded && cur.fingerprint == inst.fingerprint()
		cur.mu.Unlock()
		if same {
			cur.retry.OK()
			return nil
		}
		if !force && !cur.retry.Due() {
			logger.Debugf("ikev2: connection %d is still inside its retry backoff (%d failures)", inst.ID, cur.retry.Failures())
			return nil
		}
	}
	if !inst.isServer() {
		if err := m.checkSingleExitLocked(inst); err != nil {
			return err
		}
	}

	fp := inst.fingerprint()
	a := &adapter{inst: inst, mgr: m, fingerprint: fp, retry: vpn.NewRetry()}
	if err := a.applyLocked(); err != nil {
		// Nothing has been unloaded yet, so a working connection is unaffected —
		// except that its config file was just overwritten by the failed apply.
		// Restore it so on-disk state still describes what is loaded.
		if exists {
			m.rollbackLocked(inst.ID, cur, err)
			return err
		}
		a.setError(err)
		a.retry.Fail()
		// Keep the tunnel in the map even though it never came up. What the
		// entry is worth is its retry state and its recorded error: without them
		// the next reconcile builds a fresh adapter with a fresh backoff and
		// re-sends a configuration charon has already refused, on every tick,
		// forever. It also means Status reports a tunnel that is down instead of
		// omitting it.
		m.adapters[inst.ID] = a
		return err
	}
	if exists {
		if err := cur.Stop(context.Background()); err != nil {
			logger.Warningf("ikev2: unloading connection %d before reconfigure failed: %v", inst.ID, err)
		}
	}
	if err := a.Start(context.Background()); err != nil {
		if exists {
			m.rollbackLocked(inst.ID, cur, err)
			return err
		}
		// Same reasoning as the apply failure above: Start has already armed the
		// backoff, the entry only has to survive.
		m.adapters[inst.ID] = a
		return err
	}
	m.adapters[inst.ID] = a
	return nil
}

// checkSingleExitLocked refuses a second concurrent IKEv2 exit.
//
// Each exit installs XFRM policies covering all traffic, and the kernel resolves
// overlapping policies by priority rather than by intent. With two exits live,
// one exit's packets are encrypted into the other's SA: traffic still appears to
// leave through a tunnel, which is the hardest kind of misroute to notice.
// Separating them needs per-exit packet marks plus routing rules, which the
// panel does not manage. Refusing is the only honest option — and it fails
// closed, leaving the existing exit untouched.
func (m *Manager) checkSingleExitLocked(inst Instance) error {
	for id, cur := range m.adapters {
		if id == inst.ID || cur.inst.isServer() {
			continue
		}
		cur.mu.Lock()
		loaded := cur.loaded
		cur.mu.Unlock()
		if loaded {
			return fmt.Errorf("IKEv2 exit %q is already active; only one IKEv2 exit can run at a time because overlapping XFRM policies cannot be told apart", cur.inst.Tag)
		}
	}
	return nil
}

// rollbackLocked puts a connection that was working before a configuration
// change back the way it was.
//
// A rejected edit must not cost the operator the tunnel they already had: the
// old config is re-rendered over the new one and the old connection is loaded
// again. The change is still reported as failed — the panel does not pretend the
// new configuration is live — and the next reconcile retries it under backoff.
func (m *Manager) rollbackLocked(id int, cur *adapter, cause error) {
	if err := cur.applyLocked(); err != nil {
		logger.Errorf("ikev2: rolling connection %d back failed to rewrite its config: %v", id, err)
		return
	}
	cur.retry.OK()
	if err := cur.Start(context.Background()); err != nil {
		logger.Errorf("ikev2: rolling connection %d back failed to reload it: %v (original failure: %v)", id, err, cause)
		return
	}
	m.adapters[id] = cur
	logger.Warningf("ikev2: connection %d kept its previous configuration; the new one was rejected: %v", id, cause)
}

func (m *Manager) removeFilesLocked(a *adapter) {
	_ = os.Remove(connConfPath(a.inst))
	_ = os.Remove(markerPath(a.inst))
	_ = os.RemoveAll(filepath.Join(stateDir(), a.inst.instanceName()))
}

// Remove unloads and forgets the tunnel for an id.
func (m *Manager) Remove(id int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.adapters[id]
	if !ok {
		return
	}
	_ = cur.Stop(context.Background())
	m.removeFilesLocked(cur)
	delete(m.adapters, id)
	logger.Infof("ikev2: removed connection %d", id)
}

// Reconcile drives the loaded set toward the desired instances. Used at boot and
// periodically, so a tunnel removed from the panel is torn down and a changed one
// reloaded.
func (m *Manager) Reconcile(desired []Instance) {
	m.mu.Lock()
	defer m.mu.Unlock()
	want := make(map[int]struct{}, len(desired))
	for _, inst := range desired {
		want[inst.ID] = struct{}{}
	}
	for id, cur := range m.adapters {
		if _, ok := want[id]; !ok {
			_ = cur.Stop(context.Background())
			m.removeFilesLocked(cur)
			delete(m.adapters, id)
		}
	}
	for _, inst := range desired {
		// force=false: a connection that keeps failing is retried on the backoff
		// schedule, not on every tick, and only that connection is affected.
		if err := m.ensureLocked(inst, false); err != nil {
			// One bad connection must not stop the others from converging.
			logger.Warningf("ikev2: reconcile failed for connection %d: %v", inst.ID, err)
		}
	}
}

// StopAll unloads every managed connection. Called on panel shutdown; charon
// itself is a system service and is deliberately left running.
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, cur := range m.adapters {
		_ = cur.Stop(context.Background())
		m.removeFilesLocked(cur)
		delete(m.adapters, id)
	}
	m.connMu.Lock()
	if m.conn != nil {
		_ = m.conn.Close()
		m.conn = nil
	}
	m.connMu.Unlock()
}

// HasRunning reports whether any managed connection is currently loaded.
func (m *Manager) HasRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, cur := range m.adapters {
		cur.mu.Lock()
		loaded := cur.loaded
		cur.mu.Unlock()
		if loaded {
			return true
		}
	}
	return false
}

// Status returns the state of every managed connection, keyed by inbound id.
func (m *Manager) Status() map[int]vpn.State {
	m.mu.Lock()
	adapters := make([]*adapter, 0, len(m.adapters))
	for _, a := range m.adapters {
		adapters = append(adapters, a)
	}
	m.mu.Unlock()
	out := make(map[int]vpn.State, len(adapters))
	for _, a := range adapters {
		out[a.inst.ID] = a.Status()
	}
	return out
}

// Adapter returns the vpn.Adapter for a connection id.
func (m *Manager) Adapter(id int) (vpn.Adapter, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.adapters[id]
	if !ok {
		return nil, false
	}
	return a, true
}

// Traffic is a per-account byte delta scraped from charon, ready to be folded
// into panel accounting.
type Traffic struct {
	Tag   string
	Email string
	Up    int64
	Down  int64
}

// CollectTraffic polls every managed connection and returns the per-account byte
// deltas since the previous poll, the accounts with a live session, and each
// connection's state. Polling also refreshes health, so monitoring and
// accounting share one read of the daemon rather than two.
func (m *Manager) CollectTraffic() ([]Traffic, []string, map[int]vpn.State) {
	m.mu.Lock()
	adapters := make([]*adapter, 0, len(m.adapters))
	for _, a := range m.adapters {
		adapters = append(adapters, a)
	}
	m.mu.Unlock()

	var out []Traffic
	var online []string
	states := make(map[int]vpn.State, len(adapters))
	for _, a := range adapters {
		a.mu.Lock()
		loaded := a.loaded
		a.mu.Unlock()
		if !loaded {
			states[a.inst.ID] = a.Status()
			continue
		}
		traffic := a.countTraffic()
		counters, byUser := traffic.counters, traffic.byUser
		states[a.inst.ID] = a.Status()
		if a.inst.RouteThroughXray {
			// The Xray bridge meters this tunnel's bytes, so only per-account
			// deltas are taken — rolling the tunnel total up here as well would
			// count the same bytes twice.
			for email, s := range byUser {
				if s.UpBytes > 0 || s.DownBytes > 0 {
					out = append(out, Traffic{Tag: a.inst.Tag, Email: email, Up: s.UpBytes, Down: s.DownBytes})
				}
			}
		} else {
			out = append(out, Traffic{Tag: a.inst.Tag, Email: "", Up: counters.UpBytes, Down: counters.DownBytes})
		}
		for email := range byUser {
			online = append(online, email)
		}
	}
	return out, online, states
}

// Terminate revokes an account's access across one connection. An account the
// connection does not serve cannot be disconnected, and that is reported as an
// error on purpose: access is decided by the panel, not by the tunnel.
func (m *Manager) Terminate(id int, username string) error {
	m.mu.Lock()
	a, ok := m.adapters[id]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("no ikev2 connection %d is loaded", id)
	}
	return a.DisconnectSession(username)
}

// writeSecretFiles writes the instance's private key material as 0600 files and
// returns the paths charon should reference.
//
// Values that strongSwan can read from a file are written to disk; values it
// cannot (an EAP password) are not written at all and are carried in the load
// message instead. Either way the panel never returns a secret to a caller and
// never puts one in a metric label.
func (inst Instance) writeSecretFiles() error {
	dir := filepath.Join(stateDir(), inst.instanceName())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	write := func(name, body string) error {
		if strings.TrimSpace(body) == "" {
			return nil
		}
		return os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600)
	}
	if err := write("ca.pem", inst.CA); err != nil {
		return err
	}
	if err := write("host.crt", inst.HostCert); err != nil {
		return err
	}
	if err := write("host.key", inst.HostKey); err != nil {
		return err
	}
	if err := write("client.crt", inst.ClientCert); err != nil {
		return err
	}
	if err := write("client.key", inst.ClientKey); err != nil {
		return err
	}
	return nil
}

// renderConf builds the swanctl.conf fragment for an instance.
//
// This file is what lets a charon that outlived the panel recover the panel's
// tunnels, and what makes "was this ever applied?" answerable from disk. It
// carries no account password.
func renderConf(inst Instance) string {
	var b strings.Builder
	name := inst.instanceName()
	b.WriteString("connections {\n")
	b.WriteString("  " + name + " {\n")
	b.WriteString("    version = " + strconv.Itoa(ikeVersion(inst)) + "\n")
	b.WriteString("    proposals = " + nonEmpty(inst.Encryption, "aes256-sha256-modp2048") + "\n")
	if inst.isServer() {
		b.WriteString("    local_addrs = " + nonEmpty(inst.Listen, "0.0.0.0") + "\n")
		b.WriteString("    local_port = " + strconv.Itoa(orDefault(inst.Port, 500)) + "\n")
		b.WriteString("    mode = passive\n")
	} else {
		b.WriteString("    remote_addrs = " + inst.Remote + "\n")
		b.WriteString("    remote_port = " + strconv.Itoa(orDefault(inst.RemotePort, 500)) + "\n")
		b.WriteString("    mode = active\n")
		b.WriteString("    reqid = " + strconv.Itoa(reqID(inst)) + "\n")
	}
	b.WriteString("    dpd_delay = 30s\n")
	b.WriteString("    dpd_timeout = 120s\n")
	b.WriteString("    rekey_time = 4h\n")
	b.WriteString("    children {\n")
	b.WriteString("      " + name + " {\n")
	if inst.isServer() {
		b.WriteString("        local_addrs = " + inst.Subnet + "\n")
	} else {
		// An exit sends everything through the tunnel; without these the child's
		// SA covers nothing and traffic leaves over the real interface.
		b.WriteString("        local_addrs = 0.0.0.0/0,::/0\n")
		b.WriteString("        remote_addrs = 0.0.0.0/0,::/0\n")
		b.WriteString("        start_action = start\n")
		b.WriteString("        mode = tunnel\n")
	}
	b.WriteString("        esp_proposals = " + nonEmpty(inst.Encryption, "aes256-sha256-modp2048") + "\n")
	b.WriteString("        df = on\n")
	b.WriteString("        rekey_time = 1h\n")
	b.WriteString("      }\n")
	b.WriteString("    }\n")
	b.WriteString("  }\n")
	b.WriteString("}\n")
	return b.String()
}

func touchMarker(inst Instance) error {
	if err := os.MkdirAll(stateDir(), 0o750); err != nil {
		return err
	}
	return os.WriteFile(markerPath(inst), []byte(inst.fingerprint()), 0o600)
}

// LoadedInstances returns the connections the panel previously loaded, for a
// charon that restarted underneath it. This is deliberately not used to skip a
// load: the fingerprint is re-checked against the running daemon's own view
// instead, because a marker file can outlive the SA it records.
func LoadedInstances() []string {
	entries, err := os.ReadDir(stateDir())
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".loaded") {
			out = append(out, strings.TrimSuffix(e.Name(), ".loaded"))
		}
	}
	slices.Sort(out)
	return out
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// sanitizeErr keeps an error safe to expose and log. A VICI error can quote the
// offending section, which for an auth section would include a credential.
func sanitizeErr(err error) string {
	if err == nil {
		return ""
	}
	return ScrubLine(err.Error())
}
