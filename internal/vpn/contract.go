// Package vpn defines the small contract every VPN adapter in the panel
// implements, plus the process supervision and secret-handling helpers the
// adapters share.
//
// Xray-core has no OpenVPN or IKEv2 inbound, so such inbounds are served by
// standalone daemons (openvpn, strongswan) exactly like the mtproto inbounds are
// served by mtg-multi: one child process per inbound, configured from a file
// the panel generates, entirely outside the Xray config and lifecycle. Keeping
// one contract for both adapters means the reconcile jobs, the recovery logic
// and the monitoring code do not need a per-protocol fork, while each adapter
// keeps full ownership of its own configuration format.
//
// Three states are tracked separately throughout, because they mean different
// things operationally:
//
//   - Configured: a config for the tunnel exists on disk (and the adapter
//     validated it). Says nothing about whether the daemon runs.
//   - Connected: the daemon process is up. Says nothing about whether the
//     tunnel carries traffic.
//   - Healthy: a probe through the tunnel succeeded recently. The only state
//     the panel's health selector is allowed to consume.
package vpn

import (
	"context"
	"time"
)

// Role is which side of the tunnel a managed instance runs.
type Role string

const (
	// RoleServer is an inbound: the panel accepts VPN clients.
	RoleServer Role = "server"
	// RoleClient is an outbound/exit: the panel dials a remote VPN server.
	RoleClient Role = "client"
)

// State is the observed state of one tunnel. Configured, Connected and Healthy
// are independent; see the package comment for why they must not be collapsed
// into a single boolean.
type State struct {
	// Role is which side of the tunnel this instance runs.
	Role Role
	// Configured reports that a validated config file exists on disk.
	Configured bool
	// Connected reports that the daemon process is running.
	Connected bool
	// Healthy reports that a probe through the tunnel succeeded within the
	// last HealthTTL. This is the only field the health selector may read.
	Healthy bool
	// Latency is the round-trip time of the last successful probe, or 0 when
	// the tunnel has never been probed. It is never a management-interface
	// round trip: that measures the daemon, not the tunnel.
	Latency time.Duration
	// LastProbe is when the last probe attempt completed, successful or not.
	LastProbe time.Time
	// ProbeErr is the failure reason of the last probe attempt, empty when it
	// succeeded. It never contains credentials.
	ProbeErr string
	// ProbePinned reports that the last successful probe's socket was bound to
	// the tunnel's device. False means the probe merely followed the routing
	// table, which is weaker evidence — an unpinned latency is labelled as
	// weaker rather than presented as proof the traffic stayed in the tunnel.
	ProbePinned bool
	// LastError is the last configuration/apply/start failure, empty when the
	// last operation succeeded.
	LastError string
}

// HealthTTL is how long one successful health observation stands for.
//
// Health is polled, not pushed: an observation is a statement about the moment
// it was taken. Letting an old one count forever would keep a tunnel that died
// between polls selectable, which is exactly the failure this package's
// fail-closed contract exists to prevent. The value is generous relative to the
// poll interval so an ordinary tick delay does not flicker a healthy tunnel,
// and tight enough that a tunnel which really died stops being Ready within one
// poll of the operator noticing anything.
const HealthTTL = 60 * time.Second

// Ready reports whether the tunnel may carry traffic: it must be running, and
// it must have a health observation that is still fresh. Fail-closed by
// construction — an instance that is merely configured, running but not yet
// probed, or probed so long ago that the answer says nothing about now, is
// never Ready.
func (s State) Ready() bool {
	if !s.Connected || !s.Healthy {
		return false
	}
	if s.LastProbe.IsZero() || time.Since(s.LastProbe) > HealthTTL {
		return false
	}
	return true
}

// Session is one connected VPN client. For a RoleServer it is a panel account
// connected to this inbound; for a RoleClient it is the single egress session
// the panel holds to the remote server.
type Session struct {
	// Username is the panel account email owning the session. It is what
	// access rules and per-client accounting key on.
	Username string
	// IP is the address assigned to the client inside the tunnel.
	IP string
	// RealAddress is the client's pre-tunnel address, as observed by the
	// daemon.
	RealAddress string
	// UpBytes/DownBytes are the cumulative byte counters for the session as
	// reported by the daemon. They reset when the daemon re-keys or restarts;
	// callers turn them into deltas, they are not accounting values.
	UpBytes   int64
	DownBytes int64
	// Since is when the daemon reports the session as established.
	Since time.Time
}

// Counters is a point-in-time snapshot of one tunnel's cumulative counters.
// Like Session's per-session counters these are cumulative-and-resetting, not
// accounting deltas.
type Counters struct {
	// UpBytes/DownBytes are cumulative bytes sent/received over the tunnel.
	UpBytes   int64
	DownBytes int64
	// Sessions is the number of currently established sessions.
	Sessions int
	// ConsecutiveFailures counts connect/handshake failures since the last
	// success. The recovery backoff is derived from it.
	ConsecutiveFailures int
}

// Client is a panel account permitted to use a server-side tunnel.
type Client struct {
	// Username is the panel account email. It is the tunnel's user identity,
	// which is what lets VPN traffic keep client attribution once it is
	// bridged into the Xray routing path.
	Username string
	// Password is the shared secret. It never leaves the generated config
	// file and is never returned in an API response.
	Password string
	// Email mirrors Username for callers that build session rows.
	Email string
}

// Adapter is the contract one managed tunnel implements. An adapter instance is
// bound to a single tunnel (one inbound or one outbound); a protocol manager
// owns a set of adapters keyed by inbound id and reconciles them.
type Adapter interface {
	// Validate checks the adapter's desired configuration without touching
	// disk or starting anything. It is what rejects an imported profile
	// before anything is executed.
	Validate() error
	// Apply renders the config file for the current desired configuration.
	// It must be idempotent: applying twice yields identical bytes.
	Apply() error
	// Start brings the tunnel up. It must be idempotent: starting an already
	// running tunnel is a no-op, not an error.
	Start(ctx context.Context) error
	// Stop takes the tunnel down, releasing its ports and devices. It must be
	// idempotent and must not affect any other tunnel.
	Stop(ctx context.Context) error
	// Status returns the current configured/connected/healthy split.
	Status() State
	// ListSessions returns the currently established sessions. A RoleClient
	// adapter returns at most one session.
	ListSessions() ([]Session, error)
	// DisconnectSession tears down one session by its panel account name. It
	// is how a revoked account is evicted without restarting the tunnel, so
	// other clients are unaffected.
	DisconnectSession(username string) error
	// Counters returns a cumulative snapshot for traffic accounting.
	Counters() Counters
}
