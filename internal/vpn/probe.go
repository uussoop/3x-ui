package vpn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// ProbeResult is the outcome of one data-plane probe through a tunnel.
type ProbeResult struct {
	// OK reports that traffic actually reached the target through the tunnel.
	OK bool
	// Latency is the time the probe's connection handshake took. Zero when the
	// probe failed; zero is also how a caller tells "no latency measured" from
	// "measured instantly", which does not happen on a real network.
	Latency time.Duration
	// Err is the failure reason, empty on success. It is derived from a dial
	// error and never contains credentials.
	Err string
}

// DefaultProbeTimeout bounds one probe so a black-holed tunnel cannot stall the
// reconcile loop for longer than the loop's own period.
const DefaultProbeTimeout = 3 * time.Second

// TCPProbe measures the data plane of a tunnel by opening a TCP connection to
// target ("host:port") and timing the handshake.
//
// device, when non-empty, is the tunnel's network device. Binding the probe's
// socket to that device is what makes the result meaningful: without it the
// kernel is free to satisfy the probe over the real uplink, so a tunnel whose
// traffic is silently bypassing the VPN would still report a good latency. With
// it, the probe can only succeed if the tunnel itself carries the packets —
// which is also the check that catches IPv6 escaping an IPv4-only tunnel.
//
// An OS without per-socket device binding still gets a usable probe (the routing
// table decides), and the caller is told so through the second return value.
func TCPProbe(ctx context.Context, target, device string, timeout time.Duration) (ProbeResult, bool, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return ProbeResult{}, false, errors.New("no probe target configured")
	}
	if err := ValidateProbeTarget(target); err != nil {
		return ProbeResult{}, false, err
	}
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var lc net.Dialer
	bindDevice, bound := BindSocketToDevice(device)
	if device != "" && bound {
		lc.Control = bindDevice
	}
	start := time.Now()
	conn, err := lc.DialContext(ctx, "tcp", target)
	if err != nil {
		return ProbeResult{Err: sanitizeProbeErr(err)}, bound, nil
	}
	latency := time.Since(start)
	_ = conn.Close()
	return ProbeResult{OK: true, Latency: latency}, bound, nil
}

// ValidateProbeTarget rejects anything that is not a plain host:port.
//
// A probe target ends up in a dial call, so it must not be able to name a scheme,
// a path or a wildcard: "https://x/y" or "example.com:80:90" would be a confusing
// failure rather than a rejected one.
func ValidateProbeTarget(target string) error {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("probe target %q is not host:port", target)
	}
	if host == "" {
		return errors.New("probe target has no host")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n <= 0 || n > 65535 {
		return fmt.Errorf("probe target port %q is not a port number", port)
	}
	return nil
}

// sanitizeProbeErr keeps a dial failure short and free of anything that could be
// a credential. net.OpError strings already contain only host/port, but a
// resolver error can quote more, so the message is truncated rather than trusted.
func sanitizeProbeErr(err error) string {
	msg := err.Error()
	// Strip the net package's operation/direction scaffolding, which adds
	// nothing an operator can act on.
	if opErr := new(net.OpError); errors.As(err, &opErr) && opErr.Err != nil {
		msg = opErr.Err.Error()
	}
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return msg
}