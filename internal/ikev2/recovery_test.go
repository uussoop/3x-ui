package ikev2

import (
	"strings"
	"testing"
)

// A rejected reconfiguration must not cost the operator the tunnel they already
// had. The failure is still reported — the panel does not pretend the new
// configuration is live — but the previous connection is reloaded, so clients
// keep working while the operator fixes the edit.
func TestRejectedReconfigureRollsBackToTheWorkingConnection(t *testing.T) {
	srv := newFakeVICI(t)
	m := newTestManager(t, srv)

	working := testServerInstance()
	if err := m.Ensure(working); err != nil {
		t.Fatalf("Ensure the working configuration: %v", err)
	}
	if !m.HasRunning() {
		t.Fatal("precondition: the first configuration is not loaded")
	}

	// strongSwan refuses the new configuration but accepts the previous one,
	// which is how a real daemon behaves: it refuses what it cannot parse, not
	// everything it is sent.
	srv.mu.Lock()
	srv.rejectSection = "connections.xui-7.remote-dave"
	srv.mu.Unlock()

	// A change that is otherwise valid: one more account, same everything else.
	broken := testServerInstance()
	broken.Clients = append(broken.Clients, ClientConfig{Username: "dave", Password: "pw-dave", ID: "dave", Enabled: true})
	if err := m.Ensure(broken); err == nil {
		t.Fatal("strongSwan's refusal was not reported to the caller")
	}

	// The tunnel that was working must be back: the rollback reloads it, so the
	// failure cost a restart but not the service.
	if !m.HasRunning() {
		t.Error("the tunnel stayed down after a rejected change; a bad edit cost the operator a working tunnel")
	}
	if !srv.isLoaded("xui-7") {
		t.Errorf("charon holds %v after rollback, want xui-7 reloaded", srv.connections())
	}

	// And the panel must be honest: the rejected configuration is not in force,
	// so the account it would have added never reached the daemon, and the
	// configuration that was working is the one being served again.
	if srv.isLoaded("xui-7.remote-dave") {
		t.Error("an account from the rejected configuration was loaded")
	}
	if !srv.isLoaded("xui-7.remote-alice") {
		t.Errorf("charon holds %v after rollback, want the previously working account xui-7.remote-alice", srv.connections())
	}
}

// Once the daemon accepts the new configuration again, the tunnel must converge
// to it. Without this, a rollback could become a permanent loss of the change.
func TestReconcileRetriesAfterTheDaemonRecovers(t *testing.T) {
	srv := newFakeVICI(t)
	m := newTestManager(t, srv)
	if err := m.Ensure(testServerInstance()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	srv.mu.Lock()
	srv.rejectSection = "connections.xui-7.remote-dave"
	srv.mu.Unlock()
	want := testServerInstance()
	want.Clients = append(want.Clients, ClientConfig{Username: "dave", Password: "pw-dave", ID: "dave", Enabled: true})

	// The reconcile must not report success while the daemon refuses.
	m.Reconcile([]Instance{want})
	if srv.isLoaded("xui-7.remote-dave") {
		t.Error("an account the daemon refused was reported as loaded")
	}

	srv.mu.Lock()
	srv.rejectSection = ""
	srv.mu.Unlock()

	// Retry immediately: an explicit save is an operator action and must not wait
	// out a backoff earned by an earlier failure.
	if err := m.Ensure(want); err != nil {
		t.Fatalf("Ensure after the daemon recovered: %v", err)
	}
	if !srv.isLoaded("xui-7.remote-dave") {
		t.Error("the change never took effect once the daemon accepted it")
	}
}

// A reconcile that keeps failing must not spin: each attempt re-sends a config
// the daemon has already refused, which is pure load and produces log noise that
// hides real problems.
func TestReconcileBacksOffARefusedConnection(t *testing.T) {
	srv := newFakeVICI(t)
	m := newTestManager(t, srv)
	broken := testServerInstance()
	broken.Subnet = "10.10.0.0/24" // valid, so the refusal has to come from charon
	srv.mu.Lock()
	srv.rejectLoad = "connection refused"
	srv.mu.Unlock()

	m.Reconcile([]Instance{broken})
	first := srv.loadAttempts("xui-7")
	if first == 0 {
		t.Fatal("precondition: the first reconcile never tried to load")
	}

	// Immediately after a failure the next reconcile must not try again.
	m.Reconcile([]Instance{broken})
	if got := srv.loadAttempts("xui-7"); got != first {
		t.Errorf("load attempts = %d, want %d: a refused connection is being retried on every tick", got, first)
	}

	// An explicit save must still go through, otherwise a corrected config would
	// appear to be ignored until the backoff expired.
	if err := m.Ensure(broken); err == nil {
		t.Fatal("Ensure reported success while the daemon refused")
	}
	if got := srv.loadAttempts("xui-7"); got <= first {
		t.Errorf("load attempts = %d, want more than %d: an explicit save was swallowed by the backoff", got, first)
	}
}

// The backoff must be per connection: one broken connection must not delay a
// healthy one, which is what a shared restart interval would do.
func TestBackoffIsPerConnection(t *testing.T) {
	srv := newFakeVICI(t)
	m := newTestManager(t, srv)

	broken := testServerInstance()
	broken.ID = 8
	srv.mu.Lock()
	srv.rejectLoad = "connection refused"
	srv.mu.Unlock()
	m.Reconcile([]Instance{broken})

	// A different, valid connection still loads despite the other one's failures.
	srv.mu.Lock()
	srv.rejectLoad = ""
	srv.mu.Unlock()
	healthy := testServerInstance()
	healthy.ID = 9
	if err := m.Ensure(healthy); err != nil {
		t.Fatalf("a healthy connection was blocked by another one's failures: %v", err)
	}
	if !srv.isLoaded("xui-9") {
		t.Error("the healthy connection did not load")
	}

	// The broken connection must still be inside its own backoff, unaffected by
	// the healthy one's success. Otherwise one tunnel's recovery would clear
	// another tunnel's record and start a retry storm.
	m.Reconcile([]Instance{broken, healthy})
	m.mu.Lock()
	failures := 0
	if a, ok := m.adapters[8]; ok {
		failures = a.retry.Failures()
	}
	m.mu.Unlock()
	if failures == 0 {
		t.Error("the broken connection's backoff was cleared by an unrelated success")
	}
}

// A configuration that fails validation must never reach the daemon at all. The
// daemon runs with privileges the panel's edit path does not, and a config that
// cannot work is not worth the privilege.
func TestInvalidConfigurationNeverReachesTheDaemon(t *testing.T) {
	srv := newFakeVICI(t)
	m := newTestManager(t, srv)

	bad := testExitInstance()
	bad.Remote = ""
	if err := m.Ensure(bad); err == nil {
		t.Fatal("an exit with no remote server was accepted")
	}
	if got := len(srv.commandSections("load-conn")); got != 0 {
		t.Errorf("%d load-conn requests reached the daemon for a configuration that cannot work", got)
	}
	if m.HasRunning() {
		t.Error("a refused configuration left a tunnel behind")
	}
}

// The refusal for a second concurrent exit must be actionable: an operator who
// hits it needs to know which exit is in the way and why.
func TestSingleExitRefusalNamesTheConflict(t *testing.T) {
	srv := newFakeVICI(t)
	m := newTestManager(t, srv)

	first := testExitInstance()
	first.Tag = "exit-de"
	if err := m.Ensure(first); err != nil {
		t.Fatalf("Ensure the first exit: %v", err)
	}

	second := testExitInstance()
	second.ID = 12
	second.Tag = "exit-nl"
	err := m.Ensure(second)
	if err == nil {
		t.Fatal("a second concurrent exit was accepted")
	}
	for _, want := range []string{"exit-de", "one", "XFRM"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal %q does not mention %q, so the operator cannot act on it", err, want)
		}
	}
}