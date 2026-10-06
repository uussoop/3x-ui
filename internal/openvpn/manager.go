package openvpn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/vpn"
)

// fingerprint is a digest of everything the generated config depends on. It
// exists so a reconcile can tell "nothing changed, leave the running tunnel
// alone" from "something changed, restart", without diffing rendered files or
// remembering which field moved. Passwords are hashed, not stored, so the
// fingerprint can be compared and logged without leaking them.
func (inst Instance) fingerprint() string {
	h := sha256.New()
	writeField := func(k, v string) {
		fmt.Fprintf(h, "%s=%s\x00", k, v)
	}
	writeField("role", string(inst.role()))
	writeField("listen", inst.Listen)
	writeField("port", strconv.Itoa(inst.Port))
	writeField("proto", inst.proto())
	writeField("dev", inst.devName())
	writeField("subnet", inst.Subnet)
	writeField("dns", inst.DNSServer)
	writeField("ca", digestOf(inst.CA))
	writeField("cert", digestOf(inst.Cert))
	writeField("key", digestOf(inst.Key))
	writeField("profile", digestOf(inst.Profile))
	writeField("remote", inst.Remote)
	writeField("remotePort", strconv.Itoa(inst.RemotePort))
	writeField("remoteProto", inst.RemoteProto)
	writeField("user", digestOf(inst.Username))
	writeField("pass", digestOf(inst.Password))
	writeField("routeXray", strconv.FormatBool(inst.RouteThroughXray))
	writeField("xrayPort", strconv.Itoa(inst.XrayRoutePort))
	writeField("probeTarget", inst.ProbeTarget)
	writeField("probeDevice", inst.ProbeDevice)
	// Clients are sorted so a reordered array in stored settings is not read as
	// a change, matching how the other managed protocol managers fingerprint.
	lines := make([]string, 0, len(inst.Clients))
	for _, c := range inst.Clients {
		if !c.Enabled {
			continue
		}
		lines = append(lines, c.Username+":"+digestOf(c.Password))
	}
	slices.Sort(lines)
	writeField("clients", strings.Join(lines, ";"))
	return hex.EncodeToString(h.Sum(nil))
}

func digestOf(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Validate checks an instance without touching disk or starting anything. It is
// the gate that keeps a bad configuration from reaching a privileged process,
// and the one the save path calls so the operator learns about a problem before
// the tunnel is supposed to come up.
func (inst Instance) Validate() error {
	// A probe target is validated wherever it appears, not just where it is used:
	// a typo would otherwise only surface as an exit that reports a probe failure
	// for a reason that has nothing to do with the tunnel. An empty target is
	// legitimate — it means the tunnel is judged on its sessions alone.
	if target := strings.TrimSpace(inst.ProbeTarget); target != "" {
		if err := vpn.ValidateProbeTarget(target); err != nil {
			return err
		}
	}
	// Every field written into the config file has to stay on one line. The
	// file is a list of directives, so a newline in a value would add whatever
	// came next as a directive of its own — a device, a remote or a pushed DNS
	// server is exactly as good a place to hide `plugin` or `up` as a password
	// is a place to hide an account. The rendered config is meant to be the
	// complete statement of what the daemon may do; this keeps that true.
	for _, f := range []struct{ name, value string }{
		{"device", inst.Dev},
		{"remote", inst.Remote},
		{"dns server", inst.DNSServer},
	} {
		if strings.ContainsAny(f.value, "\r\n") {
			return fmt.Errorf("%s contains a newline, which would add directives to the generated config", f.name)
		}
	}
	if !inst.isServer() {
		// The exit's credential file is line-structured — user on the first
		// line, password on the second, and openvpn reads exactly those two.
		// A newline in either half truncates the credential at the break, so
		// the operator would be handed a password that never works with no
		// way to see why.
		if strings.ContainsAny(inst.Username, "\r\n") || strings.ContainsAny(inst.Password, "\r\n") {
			return fmt.Errorf("exit credentials contain a newline")
		}
	}
	if inst.isServer() {
		// Only a server listens, so only a server has a port to validate. An
		// exit carries no local port at all and its RemotePort is checked below.
		if inst.Port <= 0 || inst.Port > 65535 {
			return fmt.Errorf("port %d is out of range", inst.Port)
		}
		if inst.Cert == "" || inst.Key == "" {
			return fmt.Errorf("server tunnel needs a certificate and private key")
		}
		if inst.Subnet != "" && !ValidSubnet(inst.Subnet) {
			return fmt.Errorf("subnet %q is not a valid network", inst.Subnet)
		}
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
			// A newline in a username or password would inject extra lines into
			// the auth-user-pass-verify file, silently creating an account the
			// operator never added.
			if strings.ContainsAny(c.Username, "\r\n") || strings.ContainsAny(c.Password, "\r\n") {
				return fmt.Errorf("client %q has a credential containing a newline", user)
			}
			if strings.Contains(user, " ") {
				return fmt.Errorf("client username %q contains a space, which the auth file cannot represent", user)
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

	// Client side.
	host := strings.TrimSpace(inst.Remote)
	if host == "" && strings.TrimSpace(inst.Profile) != "" {
		_, err := ParseProfile(inst.Profile)
		if err != nil {
			return err
		}
		return nil
	}
	if host == "" {
		return fmt.Errorf("client tunnel has no remote server")
	}
	if !ValidHost(host) {
		return fmt.Errorf("remote %q is not a valid host", host)
	}
	if inst.RemotePort < 0 || inst.RemotePort > 65535 {
		return fmt.Errorf("remote port %d is out of range", inst.RemotePort)
	}
	// An exit without a pinned CA would accept any server certificate, which
	// makes the exit trivially interceptable and defeats the point of routing
	// through a VPN.
	if strings.TrimSpace(inst.CA) == "" && strings.TrimSpace(inst.Profile) == "" {
		return fmt.Errorf("client tunnel has no CA certificate; a tunnel that accepts any server certificate is not usable as an exit")
	}
	return nil
}

// adapter is the per-tunnel vpn.Adapter implementation. One exists per managed
// tunnel; the Manager owns them.
type adapter struct {
	inst     Instance
	mgr      *Manager
	mgmt     *mgmtClient
	mgmtPass string

	mu          sync.Mutex
	proc        tunnelProcess
	configPath  string
	fingerprint string
	applied     bool
	// retry is this tunnel's own restart backoff. It is per adapter so a broken
	// exit cannot throttle a healthy inbound, which is what a shared/global
	// restart interval would do.
	retry *vpn.Retry

	// last* is the previous counters snapshot, used to turn cumulative daemon
	// counters into accounting deltas without double-counting across a
	// rekey, where openvpn restarts its TUN statistics.
	lastUp          int64
	lastDown        int64
	lastHadCounters bool

	// sessionsByUser caches the last status poll so DisconnectSession can map a
	// panel account to the address openvpn's client-kill needs.
	sessionsByUser map[string]mgmtSession
	lastPollOK     bool
	lastPollErr    string
	lastError      string
	lastProbe      time.Time
	probeLatency   time.Duration
	// probePinned records that the last latency measurement's socket was bound
	// to the tunnel device. Unpinned means the measurement followed the routing
	// table, which is weaker evidence and is reported as such.
	probePinned bool
	healthy     bool
	failures    int
}

// Validate implements vpn.Adapter.
func (a *adapter) Validate() error { return a.inst.Validate() }

// Apply writes the tunnel's config and secret files. It is idempotent: the
// rendered bytes depend only on the instance, so applying twice produces the
// same files.
func (a *adapter) Apply() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.applyLocked()
}

// Start brings the tunnel up.
//
// It is idempotent in the sense the contract requires: starting a tunnel that is
// already running with the same configuration does nothing and drops no client
// sessions. A configuration change is not Start's business — the manager builds
// a fresh adapter for that, so there is no path here where a running tunnel is
// silently restarted out from under connected clients.
func (a *adapter) Start(_ context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.proc != nil && a.proc.IsRunning() {
		if a.fingerprint == a.inst.fingerprint() {
			return nil
		}
		// Same daemon, changed configuration. openvpn reads its config only at
		// startup, so this is the only way the change takes effect. It is
		// reached only through an adapter whose fingerprint was never applied,
		// which is why it is safe to treat as an error rather than silently
		// dropping sessions.
		return fmt.Errorf("tunnel %d is running with a different configuration; rebuild it instead of restarting in place", a.inst.ID)
	}
	if !a.applied {
		if err := a.applyLocked(); err != nil {
			return err
		}
	}
	proc := spawnProcess(a.configPath, fmt.Sprintf("%s %d", a.inst.role(), a.inst.ID))
	if err := proc.Start(); err != nil {
		a.lastError = sanitizeErr(err)
		// The failure is recorded and counted here rather than only at the
		// reconcile loop, so the backoff grows per failed attempt instead of
		// once per failed reconcile.
		a.retry.Fail()
		return err
	}
	a.proc = proc
	a.lastError = ""
	a.retry.OK()
	// A restarted daemon's counters start over, so the previous snapshot must
	// not be carried across or the first poll would report a huge negative delta.
	a.lastUp, a.lastDown, a.lastHadCounters = 0, 0, false
	a.healthy = false
	a.failures = 0
	logger.Infof("openvpn: started %s tunnel %d", a.inst.role(), a.inst.ID)
	return nil
}

func (a *adapter) applyLocked() error {
	if err := a.inst.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(configDir(), 0o750); err != nil {
		return err
	}
	var p profileParams
	if !a.inst.isServer() && strings.TrimSpace(a.inst.Profile) != "" {
		parsed, err := ParseProfile(a.inst.Profile)
		if err != nil {
			return err
		}
		p = parsed
	}
	if a.inst.CA != "" {
		p.CA = a.inst.CA
	}
	if a.inst.Cert != "" {
		p.Cert = a.inst.Cert
	}
	if a.inst.Key != "" {
		p.Key = a.inst.Key
	}
	if err := a.inst.writeSecretFiles(p, a.inst.Clients); err != nil {
		return err
	}
	// Written with the config so the daemon can never start against a missing
	// or stale password file; the value is unchanged across applies, so this
	// does not invalidate a running tunnel.
	if err := a.inst.writeMgmtPassword(a.mgmtPass); err != nil {
		return err
	}
	var rendered string
	if a.inst.isServer() {
		rendered = RenderServerConfig(a.inst)
	} else {
		rendered = RenderClientConfig(a.inst, p)
	}
	if err := os.WriteFile(a.configPath, []byte(rendered), 0o640); err != nil {
		return err
	}
	a.applied = true
	return nil
}

// Stop takes the tunnel down. Other tunnels are untouched: each has its own
// process and its own device.
func (a *adapter) Stop(_ context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.proc == nil {
		return nil
	}
	err := a.proc.Stop()
	a.proc = nil
	a.healthy = false
	if err != nil && err.Error() != "openvpn is not running" {
		return err
	}
	logger.Infof("openvpn: stopped %s tunnel %d", a.inst.role(), a.inst.ID)
	return nil
}

// Status returns the configured/connected/healthy split. Only the management
// interface can prove a session is established, so healthy is decided by a
// successful status poll that saw the expected sessions — never by "the process
// is up".
func (a *adapter) Status() vpn.State {
	a.mu.Lock()
	proc := a.proc
	healthy := a.healthy
	latency := a.probeLatency
	lastProbe := a.lastProbe
	probeErr := a.lastPollErr
	lastError := a.lastError
	failures := a.failures
	applied := a.applied
	pinned := a.probePinned
	a.mu.Unlock()

	st := vpn.State{
		Role:        a.inst.role(),
		Configured:  applied && a.configPathExists(),
		Connected:   proc != nil && proc.IsRunning(),
		Healthy:     healthy,
		Latency:     latency,
		LastProbe:   lastProbe,
		ProbeErr:    probeErr,
		ProbePinned: pinned,
		LastError:   lastError,
	}
	_ = failures
	if !st.Healthy && st.ProbeErr == "" {
		// Distinguish "never probed" and "not running" from "silently broken":
		// an operator looking at the panel must be able to tell a tunnel that
		// has not been checked yet from one that was checked and is fine.
		switch {
		case !st.Connected:
			st.ProbeErr = "tunnel is not running"
		default:
			st.ProbeErr = "no successful probe yet"
		}
	}
	return st
}

func (a *adapter) configPathExists() bool {
	_, err := os.Stat(a.configPath)
	return err == nil
}

// ListSessions returns the live sessions, mapped onto panel accounts.
//
// A session whose common name is not a known panel account is still reported,
// but with its name as-is rather than being dropped: a tunnel admitting an
// unexpected client is exactly the condition an operator needs to see, and
// silently omitting it would look like a quiet tunnel.
func (a *adapter) ListSessions() ([]vpn.Session, error) {
	reply, err := a.poll()
	if err != nil {
		return nil, err
	}
	out := make([]vpn.Session, 0, len(reply.Sessions))
	for _, s := range reply.Sessions {
		sess := vpn.Session{
			Username:    s.CommonName,
			IP:          firstNonEmpty(s.VirtualIP, s.VirtualIPv6),
			RealAddress: s.RealAddress,
		}
		if s.BytesIn >= 0 {
			sess.DownBytes = s.BytesIn
		}
		if s.BytesOut >= 0 {
			sess.UpBytes = s.BytesOut
		}
		if t, ok := parseOpenVPNTime(s.Since); ok {
			sess.Since = t
		}
		out = append(out, sess)
	}
	return out, nil
}

// DisconnectSession kills one account's session. Only the named client's
// session is torn down; every other client keeps its connection, which is why
// this is preferred over restarting the tunnel to revoke access.
func (a *adapter) DisconnectSession(username string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return fmt.Errorf("no username given")
	}
	reply, err := a.poll()
	if err != nil {
		return err
	}
	var target string
	for _, s := range reply.Sessions {
		if s.CommonName == username {
			target = s.RealAddress
			break
		}
	}
	if target == "" {
		// Already gone. Reporting an error here would make a revocation race
		// look like a failure, and the desired state is already satisfied.
		return nil
	}
	return a.mgmt.KillSession(target)
}

// poll fetches daemon status and updates health and counter state. This is the
// single place that talks to the management interface, so health and counters
// can never disagree about what the daemon actually reports.
//
// The daemon read happens outside the adapter lock (it blocks on a socket) and
// the lock is taken only to fold the result in, so a slow management interface
// cannot block Status, Start or Stop.
func (a *adapter) poll() (statusReply, error) {
	reply, err := a.mgmt.Status()
	if err != nil {
		a.mu.Lock()
		a.lastProbe = time.Now()
		a.healthy = false
		a.failures++
		a.lastPollErr = sanitizeErr(err)
		a.lastPollOK = false
		a.mu.Unlock()
		return statusReply{}, err
	}

	// A management-interface round trip measures the daemon, not the tunnel, so
	// it is never reported as tunnel latency. The tunnel's own latency comes
	// from a probe through it, which only exists when the operator configured a
	// target; otherwise latency stays zero, meaning "not measured".
	var measured vpn.ProbeResult
	var pinned bool
	measured, pinned = a.probe(reply)

	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastProbe = time.Now()
	a.lastPollErr = ""
	a.lastPollOK = true
	if measured.OK {
		a.probeLatency = measured.Latency
		a.probePinned = pinned
	}

	if a.inst.isServer() {
		// A server tunnel is healthy when the daemon is up and serving. Its
		// clients' sessions are listed separately; a server with no client
		// right now is not a fault.
		a.healthy = true
		a.lastPollErr = ""
	} else {
		// An exit is healthy only when it actually carries traffic. A session
		// alone is not enough when a probe target is configured: the session
		// can be up while the tunnel's routing is broken, and reporting that
		// as healthy would put a black-holing exit in front of clients.
		switch {
		case len(reply.Sessions) == 0:
			a.healthy = false
			a.failures++
			a.lastPollErr = "tunnel has no established session"
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

	// Cache the mapping DisconnectSession needs.
	if a.sessionsByUser == nil {
		a.sessionsByUser = map[string]mgmtSession{}
	}
	for k := range a.sessionsByUser {
		delete(a.sessionsByUser, k)
	}
	for _, s := range reply.Sessions {
		if s.CommonName != "" {
			a.sessionsByUser[s.CommonName] = s
		}
	}
	return reply, nil
}

// probeThrough measures the tunnel's data plane. It is a variable so the health
// policy that consumes it — which tunnel is reported usable, and why — can be
// tested on a machine with no tunnel device. The probe itself is tested on its
// own terms in package vpn; what is stubbed here is the call site, never the
// measurement a real tunnel gets.
var probeThrough = vpn.TCPProbe

// probe measures the tunnel's data plane when the instance has a probe target.
// The pinned return value reports whether the probe's socket was bound to the
// tunnel device, so a caller can tell a device-pinned measurement from one that
// merely followed the routing table.
//
// An exit with no target is not probed: inventing a target would send the panel's
// traffic to a third party the operator never chose.
func (a *adapter) probe(reply statusReply) (res vpn.ProbeResult, pinned bool) {
	target := strings.TrimSpace(a.inst.ProbeTarget)
	if a.inst.isServer() || target == "" || len(reply.Sessions) == 0 {
		return vpn.ProbeResult{}, false
	}
	res, pinned, _ = probeThrough(context.Background(), target, a.inst.probeDevice(), vpn.DefaultProbeTimeout)
	return res, pinned
}

// countTraffic is Counters plus the per-session breakdown. The vpn.Adapter
// contract only exposes the tunnel totals; accounting additionally needs to know
// which account the bytes belong to, so the richer form stays package-internal
// and Counters adapts it to the contract.
type countTraffic struct {
	counters vpn.Counters
	byUser   map[string]vpn.Session
}

// countTraffic polls the daemon and returns the tunnel totals and per-session
// bytes as accounting deltas.
//
// The daemon's own counters are cumulative and reset on rekey (openvpn restarts
// its TUN statistics when the data channel renegotiates) and on restart. Taking
// a raw difference across such a reset would book a huge negative delta, or
// with unsigned arithmetic a huge positive one. So a decrease is treated as a
// counter reset: the new value is taken as the delta for this interval, which
// is correct because everything counted before the reset was already booked.
func (a *adapter) countTraffic() countTraffic {
	reply, err := a.poll()
	if err != nil {
		// A failed poll reports the last known totals rather than zeroes: the
		// accounting job must not book a sudden drop in traffic because the
		// management interface was briefly unreachable.
		a.mu.Lock()
		up, down := a.lastUp, a.lastDown
		a.mu.Unlock()
		if up < 0 {
			up = 0
		}
		if down < 0 {
			down = 0
		}
		return countTraffic{counters: vpn.Counters{UpBytes: up, DownBytes: down}}
	}

	a.mu.Lock()
	up, down := a.lastUp, a.lastDown
	if !a.lastHadCounters || reply.UpBytes < up || reply.DownBytes < down {
		// First reading, or the daemon's counters went backwards (rekey or
		// restart): count everything since the reset, and never a negative.
		up, down = reply.UpBytes, reply.DownBytes
		if up < 0 {
			up = 0
		}
		if down < 0 {
			down = 0
		}
	} else {
		up, down = reply.UpBytes-a.lastUp, reply.DownBytes-a.lastDown
	}
	a.lastUp, a.lastDown = reply.UpBytes, reply.DownBytes
	a.lastHadCounters = reply.HasCounters
	failures := a.failures
	a.mu.Unlock()

	byUser := make(map[string]vpn.Session, len(reply.Sessions))
	for _, s := range reply.Sessions {
		if s.CommonName == "" {
			continue
		}
		sess := vpn.Session{
			Username:    s.CommonName,
			RealAddress: s.RealAddress,
			IP:          firstNonEmpty(s.VirtualIP, s.VirtualIPv6),
			UpBytes:     s.BytesOut,
			DownBytes:   s.BytesIn,
		}
		if t, ok := parseOpenVPNTime(s.Since); ok {
			sess.Since = t
		}
		byUser[s.CommonName] = sess
	}

	return countTraffic{
		counters: vpn.Counters{
			UpBytes:             up,
			DownBytes:           down,
			Sessions:            len(reply.Sessions),
			ConsecutiveFailures: failures,
		},
		byUser: byUser,
	}
}

// Counters returns the tunnel's cumulative counters since the previous poll.
// It is the vpn.Adapter form; accounting uses countTraffic to additionally get
// the per-session split.
func (a *adapter) Counters() vpn.Counters {
	return a.countTraffic().counters
}

// Manager owns the set of running OpenVPN daemons keyed by inbound id.
type Manager struct {
	mu       sync.Mutex
	adapters map[int]*adapter
}

var (
	managerOnce sync.Once
	manager     *Manager
)

// GetManager returns the process-wide OpenVPN manager singleton.
func GetManager() *Manager {
	managerOnce.Do(func() {
		manager = &Manager{adapters: map[int]*adapter{}}
	})
	return manager
}

func (m *Manager) newAdapter(inst Instance) (*adapter, error) {
	pass, err := newManagementPassword()
	if err != nil {
		return nil, err
	}
	a := &adapter{
		inst:     inst,
		mgr:      m,
		mgmtPass: pass,
		retry:    vpn.NewRetry(),
	}
	if inst.isServer() {
		a.configPath = configPathForID(inst.ID)
	} else {
		a.configPath = configPathForID(inst.ID)
	}
	a.mgmt = &mgmtClient{
		addr:     fmt.Sprintf("127.0.0.1:%d", inst.managementPort()),
		password: pass,
		timeout:  3 * time.Second,
	}
	return a, nil
}

// Ensure starts the tunnel for an instance, or restarts it when its
// configuration changed. A no-op when the desired tunnel is already running
// with the same configuration.
//
// It bypasses the restart backoff: an operator saving a corrected config must
// not have to wait out a delay earned by the broken one.
func (m *Manager) Ensure(inst Instance) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ensureLocked(inst, true)
}

// ensureLocked converges one tunnel. force skips the backoff; the periodic
// reconcile passes false so a tunnel that will not start is not restarted on
// every tick, while an explicit save passes true.
func (m *Manager) ensureLocked(inst Instance, force bool) error {
	if err := inst.Validate(); err != nil {
		// A refused configuration must not leave a half-started tunnel behind.
		return err
	}
	fp := inst.fingerprint()
	cur, exists := m.adapters[inst.ID]
	if exists {
		cur.mu.Lock()
		running := cur.proc != nil && cur.proc.IsRunning()
		cur.mu.Unlock()
		if running && cur.fingerprint == fp {
			cur.retry.OK()
			return nil
		}
		// A daemon that is not running was started at some point and died (or
		// never came up), so its next restart is an attempt that can fail again
		// and must count towards the backoff.
		if !running {
			cur.retry.Fail()
		}
		if !force && !cur.retry.Due() {
			logger.Debugf("openvpn: tunnel %d is still inside its restart backoff (%d failures)", inst.ID, cur.retry.Failures())
			return nil
		}
	}

	a, err := m.newAdapter(inst)
	if err != nil {
		return err
	}
	a.fingerprint = fp
	if err := a.applyLocked(); err != nil {
		// Nothing has been stopped yet, so the running tunnel is unaffected —
		// except that its config files were just overwritten by the failed
		// apply. Restore them so on-disk state still describes what is running.
		if exists {
			m.rollbackLocked(inst.ID, cur, err)
			return err
		}
		a.lastError = sanitizeErr(err)
		a.retry.Fail()
		// Keep the tunnel in the map even though it never came up. What the
		// entry is worth is its retry state and its recorded error: without them
		// the next reconcile builds a fresh adapter with a fresh backoff and
		// re-spawns a daemon that has already refused to start, on every tick,
		// forever. It also means Status reports a tunnel that is down instead of
		// omitting it.
		m.adapters[inst.ID] = a
		return err
	}
	if exists {
		if err := cur.Stop(context.Background()); err != nil {
			logger.Warningf("openvpn: stopping tunnel %d before reconfigure failed: %v", inst.ID, err)
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

// rollbackLocked puts a tunnel that was working before a configuration change
// back the way it was.
//
// A rejected edit must not cost the operator the tunnel they already had: the
// old config is re-rendered over the new one and the old daemon is started
// again. The change is still reported as failed — the panel does not pretend the
// new configuration is live — and the next reconcile retries it under backoff.
func (m *Manager) rollbackLocked(id int, cur *adapter, cause error) {
	if err := cur.applyLocked(); err != nil {
		logger.Errorf("openvpn: rolling tunnel %d back failed to rewrite its config: %v", id, err)
		return
	}
	cur.retry.OK()
	if err := cur.Start(context.Background()); err != nil {
		// The rollback itself failed: the tunnel is down and the reason must be
		// visible, not swallowed by the original error.
		logger.Errorf("openvpn: rolling tunnel %d back failed to restart it: %v (original failure: %v)", id, err, cause)
		return
	}
	m.adapters[id] = cur
	logger.Warningf("openvpn: tunnel %d kept its previous configuration; the new one was rejected: %v", id, cause)
}

func (m *Manager) removeFilesLocked(a *adapter) {
	_ = os.Remove(a.configPath)
	// The secrets directory and the config live under one slug, so removing the
	// directory is what takes the tunnel's credentials with it.
	_ = os.RemoveAll(a.inst.dir())
}

// Remove stops and forgets the tunnel for an id.
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
	logger.Infof("openvpn: removed tunnel %d", id)
}

// Reconcile drives the running set toward the desired instances. Used at boot
// and periodically, so a crashed daemon is restarted and a deleted inbound is
// torn down.
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
		// force=false: a tunnel that keeps failing is retried on the backoff
		// schedule, not on every tick, and only that tunnel is affected.
		if err := m.ensureLocked(inst, false); err != nil {
			// One bad tunnel must not stop the others from converging.
			logger.Warningf("openvpn: reconcile failed for tunnel %d: %v", inst.ID, err)
		}
	}
}

// StopAll stops every managed tunnel. Called on panel shutdown.
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, cur := range m.adapters {
		_ = cur.Stop(context.Background())
		m.removeFilesLocked(cur)
		delete(m.adapters, id)
	}
}

// HasRunning reports whether any managed tunnel is currently up.
func (m *Manager) HasRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, cur := range m.adapters {
		if cur.proc != nil && cur.proc.IsRunning() {
			return true
		}
	}
	return false
}

// Status returns the state of every managed tunnel, keyed by inbound id.
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

// Adapter returns the vpn.Adapter for a tunnel id.
func (m *Manager) Adapter(id int) (vpn.Adapter, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.adapters[id]
	if !ok {
		return nil, false
	}
	return a, true
}

// Traffic is a per-client byte delta scraped from a tunnel's management
// interface, ready to be folded into panel accounting.
type Traffic struct {
	Tag   string
	Email string
	Up    int64
	Down  int64
}

// CollectTraffic polls every managed tunnel and returns the per-account byte
// deltas since the previous poll, the accounts with a live session, and each
// tunnel's state. Polling also refreshes health, so monitoring and accounting
// share one read of the daemon rather than two.
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
		if a.proc == nil || !a.proc.IsRunning() {
			states[a.inst.ID] = a.Status()
			continue
		}
		// Tunnel-level deltas first; they are what a non-routed inbound needs.
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
			tag := a.inst.Tag
			out = append(out, Traffic{Tag: tag, Email: "", Up: counters.UpBytes, Down: counters.DownBytes})
		}
		for email := range byUser {
			online = append(online, email)
		}
	}
	return out, online, states
}

// DisconnectSession evicts one account's session from the tunnel serving it.
// The daemon refuses to disconnect an account it does not know, which is
// correct: access is decided by the panel, not by the tunnel.
func (m *Manager) DisconnectSession(id int, username string) error {
	m.mu.Lock()
	a, ok := m.adapters[id]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("no openvpn tunnel %d is running", id)
	}
	return a.DisconnectSession(username)
}

// parseOpenVPNTime parses the "since" timestamp openvpn reports in its routing
// table, e.g. "Sun Oct  5 19:00:00 2026". An unparseable timestamp yields no
// time rather than a wrong one, so callers fall back to "session age unknown".
func parseOpenVPNTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	layouts := []string{
		"Mon Jan  2 15:04:05 2006",
		"Mon Jan _2 15:04:05 2006",
		time.RFC1123Z,
		time.RFC1123,
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// sanitizeErr keeps an error string safe to expose and log by dropping anything
// that looks like a credential. Management-interface auth failures and openvpn
// config errors can quote the offending line.
func sanitizeErr(err error) string {
	if err == nil {
		return ""
	}
	return ScrubLine(err.Error())
}
