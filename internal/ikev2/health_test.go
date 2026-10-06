package ikev2

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/vpn"
)

// The health policy decides whether an exit may be sent traffic, and none of it
// can be exercised without a tunnel device. probeRecorder replaces the dial
// with a scripted answer and keeps every call the adapter made, so a test can
// assert both the policy and that the panel probed exactly what it said it
// would.
type probeRecorder struct {
	mu     sync.Mutex
	calls  []probeCall
	result vpn.ProbeResult
	pinned bool
	err    error
}

type probeCall struct {
	target string
	device string
}

func (r *probeRecorder) answer(result vpn.ProbeResult, pinned bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.result, r.pinned, r.err = result, pinned, err
}

func (r *probeRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func (r *probeRecorder) last() probeCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.calls) == 0 {
		return probeCall{}
	}
	return r.calls[len(r.calls)-1]
}

func (r *probeRecorder) install(t *testing.T) {
	t.Helper()
	prev := probeThrough
	probeThrough = func(_ context.Context, target, device string, _ time.Duration) (vpn.ProbeResult, bool, error) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.calls = append(r.calls, probeCall{target: target, device: device})
		return r.result, r.pinned, r.err
	}
	t.Cleanup(func() { probeThrough = prev })
}

// probeExitInstance is an exit holding an established child SA, configured with
// the probe target the operator chose.
func probeExitInstance() Instance {
	inst := testExitInstance()
	inst.ProbeTarget = "198.51.100.7:443"
	return inst
}

func probedExitAdapter(t *testing.T, inst Instance) (*adapter, *fakeVICI, *probeRecorder) {
	t.Helper()
	srv := newFakeVICI(t)
	m := newTestManager(t, srv)
	srv.setSAs([]string{exitSA("xui-9", "10.10.0.2", "203.0.113.9", 5000, 9000, true)})
	a := newTestAdapter(t, m, srv, inst)
	a.loaded = true
	a.applied = true
	rec := &probeRecorder{}
	rec.install(t)
	return a, srv, rec
}

// An exit whose data plane does not answer must never be Ready. A child SA can
// be established while the tunnel's routing is broken, which is exactly the
// state that would put a black-holing exit in front of clients.
func TestExitProbeFailureFailsClosed(t *testing.T) {
	a, _, rec := probedExitAdapter(t, probeExitInstance())
	rec.answer(vpn.ProbeResult{Err: "i/o timeout"}, false, errors.New("i/o timeout"))

	if _, err := a.poll(); err != nil {
		t.Fatalf("poll: %v", err)
	}
	st := a.Status()
	if st.Healthy {
		t.Error("an exit whose probe failed reported healthy; traffic would be routed into a tunnel that cannot carry it")
	}
	if st.Ready() {
		t.Error("Ready() = true after a failed probe")
	}
	if !strings.Contains(st.ProbeErr, "probe through the tunnel failed") {
		t.Errorf("ProbeErr = %q, want the probe failure named", st.ProbeErr)
	}
	if st.Latency != 0 {
		t.Errorf("Latency = %s after a failed probe; a failure must not report a measurement", st.Latency)
	}
	if a.Counters().ConsecutiveFailures == 0 {
		t.Error("a failed probe recorded no failure, so nothing downstream could tell it was failing")
	}
}

// A probe that succeeds is the proof of health, and its measurement must be
// labelled with how strong it was: a socket pinned to the tunnel device proves
// the traffic stayed in the tunnel, one that merely followed the routing table
// does not.
func TestExitProbeSuccessRecordsLatencyAndPinning(t *testing.T) {
	a, _, rec := probedExitAdapter(t, probeExitInstance())
	rec.answer(vpn.ProbeResult{OK: true, Latency: 42 * time.Millisecond}, true, nil)

	if _, err := a.poll(); err != nil {
		t.Fatalf("poll: %v", err)
	}
	st := a.Status()
	if !st.Healthy {
		t.Fatalf("an exit whose probe succeeded is not healthy: %q", st.ProbeErr)
	}
	if st.ProbeErr != "" {
		t.Errorf("ProbeErr = %q after a successful probe", st.ProbeErr)
	}
	if st.Latency != 42*time.Millisecond {
		t.Errorf("Latency = %s, want the measured 42ms", st.Latency)
	}
	if !st.ProbePinned {
		t.Error("ProbePinned = false for a device-pinned probe; the stronger measurement is being reported as the weaker one")
	}
	if n := rec.count(); n != 1 {
		t.Errorf("probe attempts = %d, want exactly one per poll", n)
	}
	if got := rec.last(); got.target != "198.51.100.7:443" {
		t.Errorf("probed %q, want the configured target", got.target)
	}
	// The probe has to go out on the tunnel's own interface, or the kernel is
	// free to satisfy it over the real uplink and a tunnel that silently
	// bypasses the VPN would look perfect.
	if got, want := rec.last().device, probeExitInstance().probeDevice(); got != want {
		t.Errorf("probe device = %q, want the exit's tunnel device %q", got, want)
	}

	rec.answer(vpn.ProbeResult{Err: "i/o timeout"}, false, errors.New("i/o timeout"))
	if _, err := a.poll(); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if a.Status().Healthy {
		t.Error("the exit stayed healthy after its probe stopped succeeding")
	}
}

// The panel must not send its own traffic anywhere the operator did not choose,
// so an exit with no probe target is never dialled. The latency it reports must
// then be zero: a VICI round trip measures the daemon over a local socket, and
// presenting that as tunnel latency would have an operator reading a local IPC
// timing as VPN performance.
func TestExitWithoutProbeTargetIsNeverDialledAndReportsNoLatency(t *testing.T) {
	inst := testExitInstance()
	a, _, rec := probedExitAdapter(t, inst)
	rec.answer(vpn.ProbeResult{OK: true, Latency: time.Millisecond}, false, nil)

	if _, err := a.poll(); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if n := rec.count(); n != 0 {
		t.Errorf("the panel dialled %q on its own initiative; an exit with no target must never be probed", rec.last().target)
	}
	st := a.Status()
	if st.Latency != 0 {
		t.Errorf("Latency = %s with no probe configured; the daemon's own round trip is being reported as the tunnel's", st.Latency)
	}
	if !st.Healthy {
		t.Errorf("an exit with an established child SA and no probe configured reported unhealthy: %q", st.ProbeErr)
	}
}

// A responder has no traffic of its own to send, so probing it would mean
// inventing a destination for the panel to talk to. Its health comes from
// charon loading and answering the connection, which is all it can be asked.
func TestServerIsNeverProbed(t *testing.T) {
	srv := newFakeVICI(t)
	m := newTestManager(t, srv)
	srv.setSAs([]string{})
	inst := testServerInstance()
	inst.ProbeTarget = "198.51.100.7:443"
	a := newTestAdapter(t, m, srv, inst)
	a.loaded = true
	a.applied = true
	rec := &probeRecorder{}
	rec.install(t)
	rec.answer(vpn.ProbeResult{Err: "would fail"}, false, errors.New("would fail"))

	if _, err := a.poll(); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if n := rec.count(); n != 0 {
		t.Errorf("the responder was probed %d times at a destination nobody chose", n)
	}
	if !a.Status().Healthy {
		t.Error("an idle responder reported unhealthy; monitoring would show a perfectly good inbound as down")
	}
}

// An exit with no established child SA has no tunnel to probe through, so the
// probe must be skipped — and the exit must be unhealthy regardless, since
// routing traffic into it would leak past the VPN.
func TestExitWithoutChildSAIsNotProbed(t *testing.T) {
	srv := newFakeVICI(t)
	m := newTestManager(t, srv)
	srv.setSAs([]string{})
	a := newTestAdapter(t, m, srv, probeExitInstance())
	a.loaded = true
	a.applied = true
	rec := &probeRecorder{}
	rec.install(t)
	rec.answer(vpn.ProbeResult{OK: true, Latency: time.Millisecond}, false, nil)

	if _, err := a.poll(); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if n := rec.count(); n != 0 {
		t.Errorf("the exit was probed %d times with no child SA to probe through", n)
	}
	if a.Status().Healthy {
		t.Error("an exit with no child SA reported healthy; traffic would leave over the real interface")
	}
}
