package openvpn

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/vpn"
)

// The health policy is the part of an exit that decides whether traffic is
// allowed to be sent into it, and none of it can be exercised without a tunnel
// device. probeRecorder replaces the dial with a scripted answer and keeps
// every call the adapter made, so a test can assert both the policy and that
// the panel probed exactly what it said it would.
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

// probeExit is an exit configured with a probe target, in the shape the panel
// derives one from an outbound: negative id, a CA it will verify, and a target
// the operator chose.
func probeExit() Instance {
	return Instance{
		ID: -8, Tag: "exit", Role: "client",
		Remote: "vpn.example.com", RemotePort: 1194,
		CA:          "CA",
		Username:    "alice",
		Password:    "pw",
		ProbeTarget: "198.51.100.7:443",
	}
}

// An exit whose data plane does not answer must never be Ready. The session can
// be up while the tunnel's routing is broken, which is exactly the state that
// would put a black-holing exit in front of clients.
func TestExitProbeFailureFailsClosed(t *testing.T) {
	a, _ := newTestAdapterWithServer(t, probeExit())
	rec := &probeRecorder{}
	rec.install(t)
	rec.answer(vpn.ProbeResult{Err: "connection refused"}, false, errors.New("connection refused"))

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
	if n := a.Counters().ConsecutiveFailures; n == 0 {
		t.Error("a failed probe recorded no failure, so nothing downstream could tell it was failing")
	}
}

// A probe that succeeds is the proof of health, and its measurement must be
// labelled with how strong it was: a socket pinned to the tunnel device proves
// the traffic stayed in the tunnel, one that merely followed the routing table
// does not, and the difference has to reach monitoring.
func TestExitProbeSuccessRecordsLatencyAndPinning(t *testing.T) {
	a, _ := newTestAdapterWithServer(t, probeExit())
	rec := &probeRecorder{}
	rec.install(t)
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
	if got := rec.count(); got != 1 {
		t.Errorf("probe attempts = %d, want exactly one per poll", got)
	}
	if got := rec.last(); got.target != "198.51.100.7:443" {
		t.Errorf("probed %q, want the configured target", got.target)
	}
	// The probe has to go out on the tunnel's own device, or the kernel is free
	// to satisfy it over the real uplink and a tunnel that silently bypasses
	// would look perfect.
	if got := rec.last().device; got != ExitDev(-8) {
		t.Errorf("probe device = %q, want the exit's tunnel device %q", got, ExitDev(-8))
	}

	// Health must fall as soon as the probe does: a cached good answer would
	// keep a dead tunnel selectable.
	rec.answer(vpn.ProbeResult{Err: "i/o timeout"}, false, errors.New("i/o timeout"))
	if _, err := a.poll(); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if a.Status().Healthy {
		t.Error("the exit stayed healthy after its probe stopped succeeding")
	}
}

// The panel must not send its own traffic anywhere the operator did not choose,
// so an exit with no probe target is never dialled — and, having measured
// nothing, is not reported as measured either.
func TestExitWithoutProbeTargetIsNeverDialled(t *testing.T) {
	inst := probeExit()
	inst.ProbeTarget = ""
	a, _ := newTestAdapterWithServer(t, inst)
	rec := &probeRecorder{}
	rec.install(t)
	rec.answer(vpn.ProbeResult{OK: true, Latency: time.Millisecond}, false, nil)

	if _, err := a.poll(); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if n := rec.count(); n != 0 {
		t.Errorf("the panel dialled %q on its own initiative; an exit with no target must never be probed", rec.last().target)
	}
	if got := a.Status().Latency; got != 0 {
		t.Errorf("Latency = %s with no probe configured; a tunnel that was not measured must not report a measurement", got)
	}
}

// A server has no traffic of its own to send, so probing it would mean inventing
// a destination for the panel to talk to. Its health comes from the management
// interface answering, which is the only thing the panel can honestly ask.
func TestServerTunnelIsNeverProbed(t *testing.T) {
	inst := serverInstance()
	inst.ProbeTarget = "198.51.100.7:443"
	a, _ := newTestAdapterWithServer(t, inst)
	rec := &probeRecorder{}
	rec.install(t)
	rec.answer(vpn.ProbeResult{Err: "would fail"}, false, errors.New("would fail"))

	if _, err := a.poll(); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if n := rec.count(); n != 0 {
		t.Errorf("the server tunnel was probed %d times at a destination nobody configured meaningfully", n)
	}
	if !a.Status().Healthy {
		t.Error("an idle server tunnel reported unhealthy; monitoring would show a working inbound as down")
	}
}

// An exit that holds no session must not be probed: there is no tunnel to send
// a probe through, so dialling would be the panel reaching out to a third party
// to learn nothing. It must also be unhealthy, since routing traffic into an
// exit with no session would black-hole it.
func TestExitWithoutSessionIsNotProbedAndIsUnhealthy(t *testing.T) {
	a, _ := newTestAdapterWithServer(t, probeExit(), []string{
		"OpenVPN Client: 10.8.0.6:1194",
		"ROUTING_TABLE",
		"END",
	})
	rec := &probeRecorder{}
	rec.install(t)
	rec.answer(vpn.ProbeResult{OK: true, Latency: time.Millisecond}, false, nil)

	if _, err := a.poll(); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if n := rec.count(); n != 0 {
		t.Errorf("the exit was probed %d times with no session to probe through", n)
	}
	if a.Status().Healthy {
		t.Error("an exit with no established session reported healthy; traffic routed to it would be black-holed")
	}
}
