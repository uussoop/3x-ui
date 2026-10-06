package vpn

import (
	"testing"
	"time"
)

// The three states mean different things and must never collapse into one
// boolean: a configured tunnel is not a running tunnel, and a running tunnel is
// not one that is known to be carrying traffic.
func TestStateKeepsTheThreeStatesApart(t *testing.T) {
	var s State
	if s.Configured || s.Connected || s.Healthy {
		t.Errorf("a zero State already claims something: %+v", s)
	}
	if s.Ready() {
		t.Error("a zero State is Ready; fail-closed was lost")
	}

	s.Configured = true
	if s.Connected || s.Healthy {
		t.Error("configuring a tunnel reported it as connected or healthy")
	}
	if s.Ready() {
		t.Error("a configured-but-not-running tunnel is Ready")
	}

	s.Connected = true
	if s.Healthy {
		t.Error("a running tunnel reported healthy without a probe")
	}
	if s.Ready() {
		t.Error("a running-but-unprobed tunnel is Ready; traffic would go into something nobody has checked")
	}
}

// Ready has to care how old the health answer is. Without that bound a tunnel
// that died between two polls keeps a green flag from its last good reading,
// and "Healthy" becomes a statement about the past rather than about now.
func TestReadyRejectsAStaleHealthObservation(t *testing.T) {
	fresh := State{
		Connected: true,
		Healthy:   true,
		LastProbe: time.Now(),
	}
	if !fresh.Ready() {
		t.Fatal("a freshly probed tunnel is not Ready")
	}

	stale := fresh
	stale.LastProbe = time.Now().Add(-HealthTTL - time.Second)
	if stale.Ready() {
		t.Error("a tunnel whose last probe is older than HealthTTL is still Ready; a dead one would keep carrying traffic in the selector")
	}

	// Just inside the window still counts, or an ordinary poll delay would
	// flicker a healthy tunnel out of the selector.
	almost := fresh
	almost.LastProbe = time.Now().Add(-HealthTTL + time.Second)
	if !almost.Ready() {
		t.Error("a tunnel probed just inside HealthTTL dropped out of Ready; the window is tighter than the poll interval")
	}
}

// A rejected configuration must not make a tunnel that is still serving the
// previous one un-Ready: the failure belongs to the edit, not to the tunnel
// that stayed up. This is what makes rollback visible without being fatal.
func TestLastErrorAloneDoesNotBlockAWorkingTunnel(t *testing.T) {
	s := State{
		Connected: true,
		Healthy:   true,
		LastProbe: time.Now(),
		LastError: "the new configuration was rejected",
	}
	if !s.Ready() {
		t.Error("a tunnel serving its previous configuration is not Ready because an edit failed; rollback would look like an outage")
	}
}

// A nil Retry means "no failures recorded". Adapters build it in a struct
// literal, so a missing one has to mean retry freely rather than panic halfway
// through a reconcile.
func TestNilRetryBehavesAsNoBackoff(t *testing.T) {
	var r *Retry
	if !r.Due() {
		t.Error("a nil Retry is not due; a tunnel with no recorded failure would never start")
	}
	if r.Failures() != 0 {
		t.Errorf("a nil Retry reports %d failures", r.Failures())
	}
	r.Fail()
	if r.Failures() != 0 {
		t.Error("a nil Retry recorded a failure it has nowhere to keep")
	}
	if !r.Due() {
		t.Error("a nil Retry armed a backoff it does not have")
	}
	r.OK() // must not panic
}
