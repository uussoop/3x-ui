package vpn

import (
	"context"
	"net"
	"runtime"
	"testing"
	"time"
)

// listenProbeTarget starts a throwaway TCP listener and returns its address.
func listenProbeTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return ln.Addr().String()
}

func TestTCPProbeMeasuresAReachableTarget(t *testing.T) {
	res, _, err := TCPProbe(context.Background(), listenProbeTarget(t), "", time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !res.OK {
		t.Fatalf("probe failed against a listening target: %s", res.Err)
	}
	if res.Latency <= 0 {
		t.Fatalf("latency = %s, want a positive measurement", res.Latency)
	}
	if res.Err != "" {
		t.Fatalf("a successful probe reported an error: %s", res.Err)
	}
}

func TestTCPProbeFailsOnAClosedPort(t *testing.T) {
	// Bind and immediately release a port so nothing is listening on it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	res, _, probeErr := TCPProbe(context.Background(), addr, "", time.Second)
	if probeErr != nil {
		t.Fatalf("probe: %v", probeErr)
	}
	if res.OK {
		t.Fatal("a probe against a closed port reported success")
	}
	if res.Err == "" {
		t.Fatal("a failed probe must say why, or an operator cannot act on it")
	}
	if res.Latency != 0 {
		t.Fatalf("a failed probe reported latency %s", res.Latency)
	}
}

func TestTCPProbeRejectsMalformedTargets(t *testing.T) {
	// A target that is not host:port must be refused up front. Silently
	// "probing" it would report a tunnel as unhealthy for a reason that has
	// nothing to do with the tunnel.
	for _, target := range []string{
		"",
		"example.com",
		"https://example.com/path",
		"example.com:notaport",
		"example.com:0",
		"example.com:70000",
		":443",
	} {
		res, _, err := TCPProbe(context.Background(), target, "", time.Second)
		if err == nil {
			t.Errorf("target %q was accepted (result %+v)", target, res)
		}
	}
}

func TestTCPProbeHonoursItsDeadline(t *testing.T) {
	// 203.0.113.0/24 is TEST-NET-3: reserved for documentation, so nothing
	// answers and the probe must give up on its own instead of hanging the
	// reconcile loop.
	start := time.Now()
	res, _, err := TCPProbe(context.Background(), "203.0.113.1:9", "", 300*time.Millisecond)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.OK {
		t.Fatal("a probe to an unroutable address reported success")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("probe took %s, well past its 300ms deadline", elapsed)
	}
}

func TestDeviceBindingIsRealOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("per-socket device binding is a Linux facility")
	}
	// The whole point of binding is that the probe cannot be satisfied by the
	// real uplink. If a socket pinned to a device that does not exist still
	// connects, the binding is a no-op and a leaky tunnel would look healthy.
	target := listenProbeTarget(t)
	res, bound, err := TCPProbe(context.Background(), target, "xui-no-such-device", time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !bound {
		t.Fatal("this platform reported that it cannot bind a socket to a device")
	}
	if res.OK {
		t.Fatal("a probe bound to a nonexistent device succeeded, so the binding is not applied")
	}
}

func TestBindSocketToDeviceReportsSupportHonestly(t *testing.T) {
	// A platform that cannot bind must say so, so callers can record that the
	// probe was weaker rather than reporting a strong result they did not earn.
	_, bound := BindSocketToDevice("x")
	if want := runtime.GOOS == "linux"; bound != want {
		t.Fatalf("device binding support = %v on %s, want %v", bound, runtime.GOOS, want)
	}
}