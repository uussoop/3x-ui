package openvpn

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The recovery paths are the ones that must not be wrong — a rejected edit
// costing the operator a working tunnel, or a tunnel that cannot start being
// hammered on every reconcile tick — and none of them can be reached on a
// machine with no openvpn binary, no TUN device and no root. fakeProcess is the
// stand-in that makes them testable.
type fakeProcess struct {
	mu sync.Mutex
	// configPath is the generated config this child would run, so a start
	// attempt can be judged by the configuration it is being asked to run.
	configPath string
	starts     int
	stops      int
	running    bool
	lastLine   string
}

func (p *fakeProcess) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.starts++
	if err := spawnGate(p.configPath); err != nil {
		p.lastLine = err.Error()
		return err
	}
	p.running = true
	p.lastLine = "Initialization Sequence Completed"
	return nil
}

func (p *fakeProcess) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.running {
		return errors.New("openvpn is not running")
	}
	p.stops++
	p.running = false
	return nil
}

func (p *fakeProcess) IsRunning() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.running
}

func (p *fakeProcess) LastLine() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastLine
}

// spawnGate decides whether a start attempt succeeds, judging the attempt by
// the config file it is being started with. Returning an error is how a test
// says "the daemon cannot run this configuration" — which is the only shape a
// rollback can be observed in: the previous configuration still starts, the new
// one does not.
var spawnGate = func(configPath string) error { _ = configPath; return nil }

// useFakeProcess swaps the real openvpn child for one the test controls, and
// fails the test if any code path starts a tunnel outside the fake.
func useFakeProcess(t *testing.T) *processList {
	t.Helper()
	t.Setenv("XUI_BIN_FOLDER", t.TempDir())
	prev, prevGate := spawnProcess, spawnGate
	procs := &processList{}
	spawnProcess = func(configPath, _ string) tunnelProcess {
		return procs.add(&fakeProcess{configPath: configPath})
	}
	spawnGate = func(string) error { return nil }
	t.Cleanup(func() {
		spawnProcess, spawnGate = prev, prevGate
	})
	return procs
}

type processList struct {
	mu sync.Mutex
	ps []*fakeProcess
}

func (l *processList) add(p *fakeProcess) *fakeProcess {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ps = append(l.ps, p)
	return p
}

func (l *processList) all() []*fakeProcess {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]*fakeProcess(nil), l.ps...)
}

// starts is how many times something was asked to bring a tunnel up. It is the
// number that must not grow while a tunnel sits inside its backoff.
func (l *processList) starts() int {
	total := 0
	for _, p := range l.all() {
		p.mu.Lock()
		total += p.starts
		p.mu.Unlock()
	}
	return total
}

func (l *processList) running() int {
	n := 0
	for _, p := range l.all() {
		if p.IsRunning() {
			n++
		}
	}
	return n
}

// refuseAccounts makes a start attempt fail when the tunnel's own auth file
// names one of the given accounts, and succeed otherwise.
func refuseAccounts(accounts ...string) {
	spawnGate = func(configPath string) error {
		auth := filepath.Join(strings.TrimSuffix(configPath, ".conf"), "auth-users.txt")
		data, err := os.ReadFile(auth)
		if err != nil {
			return err
		}
		for _, acct := range accounts {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, acct+" ") {
					return fmt.Errorf("option error: unrecognized auth file entry for %s", acct)
				}
			}
		}
		return nil
	}
}

// A rejected reconfiguration must not cost the operator the tunnel they already
// had. The failure is still reported — the panel does not pretend the new
// configuration is live — but the previous tunnel is started again, so clients
// keep working while the operator fixes the edit.
func TestRejectedReconfigureRollsBackToTheWorkingTunnel(t *testing.T) {
	useFakeProcess(t)
	m := &Manager{adapters: map[int]*adapter{}}

	working := serverInstance()
	if err := m.Ensure(working); err != nil {
		t.Fatalf("Ensure the working configuration: %v", err)
	}
	if !m.HasRunning() {
		t.Fatal("precondition: the first configuration is not running")
	}

	// The daemon refuses to start with the new account and accepts the
	// configuration it is already running.
	refuseAccounts("dave")

	broken := serverInstance()
	broken.Clients = append(broken.Clients, ClientConfig{Username: "dave", Password: "pw-dave", Enabled: true})
	if err := m.Ensure(broken); err == nil {
		t.Fatal("the daemon's refusal was not reported to the caller")
	}

	if !m.HasRunning() {
		t.Error("the tunnel stayed down after a rejected change; a bad edit cost the operator a working tunnel")
	}
	m.mu.Lock()
	cur, ok := m.adapters[7]
	running := cur != nil && cur.proc != nil && cur.proc.IsRunning()
	gotClients := []ClientConfig{}
	if ok {
		gotClients = cur.inst.Clients
	}
	m.mu.Unlock()
	if !ok || !running {
		t.Fatalf("tunnel 7 running = %v after rollback, want the previous tunnel still up", running)
	}
	if len(gotClients) != 1 || gotClients[0].Username != "alice" {
		t.Errorf("the manager is tracking %+v after rollback, want the configuration that is actually running", gotClients)
	}

	// The on-disk state must describe what is running, or the next reconcile
	// would think the rejected configuration had taken effect.
	users, err := os.ReadFile(filepath.Join(configDir(), "server-7", "auth-users.txt"))
	if err != nil {
		t.Fatalf("read auth file: %v", err)
	}
	if strings.Contains(string(users), "dave") {
		t.Errorf("the rejected account is still on disk:\n%s", users)
	}
}

// Once the daemon accepts the new configuration again, the tunnel must converge
// to it. Without this a rollback would become a permanent loss of the change.
func TestReconcileConvergesAfterTheRefusalLifts(t *testing.T) {
	useFakeProcess(t)
	m := &Manager{adapters: map[int]*adapter{}}
	if err := m.Ensure(serverInstance()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	refuseAccounts("dave")
	want := serverInstance()
	want.Clients = append(want.Clients, ClientConfig{Username: "dave", Password: "pw-dave", Enabled: true})
	m.Reconcile([]Instance{want})

	users, err := os.ReadFile(filepath.Join(configDir(), "server-7", "auth-users.txt"))
	if err != nil {
		t.Fatalf("read auth file: %v", err)
	}
	if strings.Contains(string(users), "dave") {
		t.Error("the daemon refused the account and it was reported as live anyway")
	}

	spawnGate = func(string) error { return nil }
	// An explicit save must go through immediately, otherwise a corrected config
	// would appear to be ignored until the backoff expired.
	if err := m.Ensure(want); err != nil {
		t.Fatalf("Ensure after the daemon recovered: %v", err)
	}
	users, err = os.ReadFile(filepath.Join(configDir(), "server-7", "auth-users.txt"))
	if err != nil {
		t.Fatalf("read auth file: %v", err)
	}
	if !strings.Contains(string(users), "dave") {
		t.Error("the change never took effect once the daemon accepted it")
	}
}

// A tunnel that cannot start must not be restarted on every reconcile tick.
// Each attempt re-reads the same broken config and fails the same way, so a
// retry per tick buys nothing and costs a process spawn plus log noise.
func TestReconcileBacksOffAFailedStart(t *testing.T) {
	procs := useFakeProcess(t)
	spawnGate = func(string) error { return errors.New("option error: cannot open config file") }
	m := &Manager{adapters: map[int]*adapter{}}

	broken := serverInstance()
	m.Reconcile([]Instance{broken})
	first := procs.starts()
	if first == 0 {
		t.Fatal("precondition: the first reconcile never tried to start")
	}

	// Immediately after the failure the next reconcile must not try again.
	m.Reconcile([]Instance{broken})
	if got := procs.starts(); got != first {
		t.Errorf("start attempts = %d, want %d: a tunnel that cannot start is being restarted on every tick", got, first)
	}

	// An explicit save must still be attempted, or a corrected config would look
	// like it was ignored.
	if err := m.Ensure(broken); err == nil {
		t.Fatal("Ensure reported success while the daemon refused to start")
	}
	if got := procs.starts(); got <= first {
		t.Errorf("start attempts = %d, want more than %d: an explicit save was swallowed by the backoff", got, first)
	}
}

// The backoff must be per tunnel: one broken tunnel must not delay a healthy
// one, which is what a shared restart interval would do.
func TestBackoffIsPerTunnel(t *testing.T) {
	procs := useFakeProcess(t)
	m := &Manager{adapters: map[int]*adapter{}}

	broken := serverInstance()
	broken.ID = 8
	refuseAccounts("alice") // tunnel 8's only account, so tunnel 8 never starts
	m.Reconcile([]Instance{broken})
	badStarts := procs.starts()

	// A different, valid tunnel still starts despite the other one's failures.
	spawnGate = func(string) error { return nil }
	healthy := serverInstance()
	healthy.ID = 9
	if err := m.Ensure(healthy); err != nil {
		t.Fatalf("a healthy tunnel was blocked by another one's failures: %v", err)
	}
	if !m.HasRunning() {
		t.Error("the healthy tunnel did not start")
	}

	// Reconciling both must leave the broken one alone: its backoff is its own,
	// and the healthy one's success must not clear it.
	m.Reconcile([]Instance{broken, healthy})
	m.mu.Lock()
	var failures int
	var due bool
	if a, ok := m.adapters[8]; ok && a.retry != nil {
		failures = a.retry.Failures()
		due = a.retry.Due()
	}
	m.mu.Unlock()
	if failures == 0 {
		t.Error("the broken tunnel's backoff was cleared by an unrelated success")
	}
	if due {
		t.Error("the broken tunnel is immediately due for another attempt")
	}
	if got := procs.starts(); got != badStarts+1 {
		// exactly one more start: the one the healthy tunnel needed.
		t.Errorf("start attempts = %d, want %d (the broken tunnel must not be restarted again)", got, badStarts+1)
	}
}

// A configuration that fails validation must never reach the daemon. The daemon
// runs with privileges the panel's edit path does not, and a config that cannot
// work is not worth the privilege.
func TestInvalidConfigurationNeverReachesTheDaemon(t *testing.T) {
	procs := useFakeProcess(t)
	m := &Manager{adapters: map[int]*adapter{}}

	bad := serverInstance()
	bad.Cert = ""
	if err := m.Ensure(bad); err == nil {
		t.Fatal("a server with no certificate was accepted")
	}
	if got := procs.starts(); got != 0 {
		t.Errorf("%d start attempts reached the daemon for a configuration that cannot work", got)
	}
	if m.HasRunning() {
		t.Error("a refused configuration left a tunnel behind")
	}
}

// A tunnel that will not start must still be visible, with the reason, rather
// than disappearing from Status. Monitoring that omits a down tunnel is worse
// than no monitoring: it reads as "nothing to see here".
func TestFailedStartIsVisibleInStatus(t *testing.T) {
	useFakeProcess(t)
	spawnGate = func(string) error { return errors.New("option error: unsupported option --ca") }
	m := &Manager{adapters: map[int]*adapter{}}

	if err := m.Ensure(serverInstance()); err == nil {
		t.Fatal("Ensure reported success while nothing could start")
	}
	m.mu.Lock()
	a, ok := m.adapters[7]
	m.mu.Unlock()
	if !ok {
		t.Fatal("the tunnel left no record, so nothing could report why it is down")
	}
	st := a.Status()
	if st.Ready() {
		t.Error("a tunnel that never started reports itself ready")
	}
	if st.LastError == "" {
		t.Error("Status hides the start failure, leaving the operator nothing to act on")
	}
	if a.retry.Failures() == 0 {
		t.Error("the failed start did not count towards the backoff")
	}
	if a.retry.Due() {
		t.Error("a tunnel that cannot start is immediately due for another attempt")
	}
}
