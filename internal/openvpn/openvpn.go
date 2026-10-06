// Package openvpn manages standalone OpenVPN daemons — one child process per
// panel inbound or outbound — for both tunnel directions.
//
// Xray-core cannot terminate or originate an OpenVPN session, so these
// inbounds/outbounds live entirely outside the Xray config and lifecycle, the
// same way the mtproto inbounds live outside it as mtg processes. What differs
// from mtproto is that OpenVPN speaks a real management protocol, which is what
// makes this adapter useful rather than opaque: the panel talks to the daemon's
// management interface to list live sessions, disconnect one account without
// disturbing the others, and read per-client byte counters.
//
// Security posture of the server side: user/password auth only (no
// certificates issued by the panel, so nothing depends on a CA the panel would
// have to manage), management interface bound to loopback with a generated
// password, and a strict --script-security so an operator can never turn the
// daemon into a script runner through a crafted config.
//
// Security posture of the client side: an imported .ovpn profile is *parsed*,
// never executed. Directives that run programs or load plugins (up/down,
// plugin, script-security, management, route-up, ipchange, ...) are rejected
// outright rather than sanitised, because a tunnel config is not a place where
// "best effort" filtering is a safe default — the panel would be handing an
// untrusted string to a privileged process. Everything the adapter keeps from a
// profile is a small allowlist of connection parameters.
package openvpn

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/config"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/vpn"
)

// GetBinaryName returns the openvpn binary filename for the current OS and arch.
func GetBinaryName() string {
	name := fmt.Sprintf("openvpn-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

// GetBinaryPath returns the full path to the openvpn binary, alongside Xray.
func GetBinaryPath() string {
	return config.GetBinFolderPath() + "/" + GetBinaryName()
}

// BinaryAvailable reports whether an openvpn binary is present. The adapters
// treat a missing binary as "configured but cannot run" rather than a fatal
// panel error: an operator may legitimately enable an OpenVPN inbound on a
// panel that is only a controller for that tunnel.
func BinaryAvailable() bool {
	_, err := os.Stat(GetBinaryPath())
	return err == nil
}

func configDir() string {
	return config.GetBinFolderPath() + "/openvpn"
}

func configPathForID(id int) string {
	return fmt.Sprintf("%s/%s.conf", configDir(), instanceSlug(id))
}

// instanceSlug names one tunnel's files. Inbounds and exits share the directory,
// so the slug has to say which is which or a negative exit id would produce a
// filename indistinguishable from a malformed inbound id.
func instanceSlug(id int) string {
	if id < 0 {
		return fmt.Sprintf("exit-%d", -id)
	}
	return fmt.Sprintf("server-%d", id)
}

// ClientConfig is one account permitted to authenticate against a server-side
// tunnel, or the credentials for a client-side tunnel.
type ClientConfig struct {
	Username string
	Password string
	Enabled  bool
}

// Instance is the desired runtime configuration of one OpenVPN tunnel. The same
// struct describes both directions; Role picks which side the generated config
// puts the panel on.
type Instance struct {
	ID   int
	Tag  string
	Role vpn.Role

	// Server side.
	Listen string
	Port   int
	// Proto is the transport for a server-side tunnel, "udp" or "tcp".
	Proto string
	// Subnet is the tunnel network in CIDR form, e.g. "10.8.0.0/24".
	Subnet string
	// DNSServer is pushed to connected clients.
	DNSServer string
	// Cert, Key and CA are PEM blobs. They are written to 0600 files in the
	// tunnel's private directory and are never returned by any API.
	Cert string
	Key  string
	CA   string
	// Clients are the accounts allowed to connect.
	Clients []ClientConfig

	// Client side.
	Remote        string
	RemotePort    int
	RemoteProto   string
	Username      string
	Password      string
	Profile       string
	ImportAllowed bool

	// Dev names the TUN device; empty lets openvpn pick.
	Dev string
	// Verb is the openvpn log verbosity for this tunnel.
	Verb int

	// RouteThroughXray bridges this tunnel's traffic through the Xray routing
	// path so VPN clients keep panel access rules and per-client accounting.
	RouteThroughXray bool
	XrayRoutePort    int

	// ProbeTarget is a host:port an exit tunnel is measured against ("1.1.1.1:443",
	// say). Empty means no data-plane measurement: the tunnel is then judged
	// purely on whether it holds a session, and its latency is reported as
	// unknown rather than guessed.
	ProbeTarget string
	// ProbeDevice overrides the device the probe's socket is pinned to. Empty
	// means the tunnel's own device.
	ProbeDevice string
}

// probeDevice is the interface an exit's probe is pinned to. Pinned explicitly
// so the measurement cannot be satisfied by the real uplink: a probe that may go
// any way proves nothing about whether the tunnel carries traffic.
func (inst Instance) probeDevice() string {
	if d := strings.TrimSpace(inst.ProbeDevice); d != "" {
		return d
	}
	return inst.devName()
}

func (inst Instance) role() vpn.Role {
	if inst.Role == "" {
		return vpn.RoleServer
	}
	return inst.Role
}

func (inst Instance) isServer() bool { return inst.role() == vpn.RoleServer }

func (inst Instance) bindTo() string {
	listen := inst.Listen
	if listen == "" {
		listen = "0.0.0.0"
	}
	return fmt.Sprintf("%s:%d", listen, inst.Port)
}

// devName is the tunnel device this instance owns.
//
// The name is derived, not openvpn's default "tun", because the panel binds
// Xray's exit outbound to it by name and two tunnels must never share one
// device. An operator-supplied name wins; a stored "tun"/"tap" is treated as
// unset, since it means "pick the next free tunN" and cannot be referenced.
func (inst Instance) devName() string {
	dev := strings.TrimSpace(inst.Dev)
	if dev != "" && !strings.EqualFold(dev, "tun") && !strings.EqualFold(dev, "tap") {
		return dev
	}
	if inst.isServer() {
		return ServerDev(inst.ID)
	}
	return ExitDev(inst.ID)
}

func (inst Instance) proto() string {
	if strings.EqualFold(inst.Proto, "tcp") || strings.EqualFold(inst.RemoteProto, "tcp") {
		return "tcp"
	}
	return "udp"
}

func (inst Instance) verbosity() int {
	if inst.Verb > 0 {
		return inst.Verb
	}
	return 3
}

// InstanceFromInbound derives a desired server-side Instance from an openvpn
// inbound. Returns false when the inbound is not a usable openvpn inbound.
//
// Only enabled clients with a non-empty username are served: openvpn's
// auth-user-pass-verify reads one file, and a client without a username cannot
// be attributed back to a panel account, which would break both access rules
// and accounting.
func InstanceFromInbound(ib *model.Inbound) (Instance, bool) {
	if ib == nil || ib.Protocol != model.OpenVPN {
		return Instance{}, false
	}
	settings := ib.Settings
	var parsed struct {
		Mode            string `json:"mode"`
		Proto           string `json:"proto"`
		Subnet          string `json:"subnet"`
		DNSServer       string `json:"dnsServer"`
		Cert            string `json:"cert"`
		Key             string `json:"key"`
		CA              string `json:"ca"`
		Dev              string `json:"dev"`
		Verb             int    `json:"verb"`
		RouteThroughXray bool   `json:"routeThroughXray"`
		RouteXrayPort    int    `json:"routeXrayPort"`
		ProbeTarget      string `json:"probeTarget"`
		ProbeDevice      string `json:"probeDevice"`
		Clients         []struct {
			Email    string `json:"email"`
			Username string `json:"username"`
			Password string `json:"password"`
			Enable   bool   `json:"enable"`
		} `json:"clients"`
	}
	if err := json.Unmarshal([]byte(settings), &parsed); err != nil {
		return Instance{}, false
	}
	role := vpn.RoleServer
	if strings.EqualFold(parsed.Mode, "client") {
		role = vpn.RoleClient
	}
	inst := Instance{
		ID:               ib.Id,
		Tag:              ib.Tag,
		Role:             role,
		Listen:           ib.Listen,
		Port:             ib.Port,
		Proto:            parsed.Proto,
		Subnet:           parsed.Subnet,
		DNSServer:        parsed.DNSServer,
		Cert:             parsed.Cert,
		Key:              parsed.Key,
		CA:               parsed.CA,
		Dev:              parsed.Dev,
		Verb:             parsed.Verb,
		RouteThroughXray: parsed.RouteThroughXray,
		XrayRoutePort:    parsed.RouteXrayPort,
		ProbeTarget:      parsed.ProbeTarget,
		ProbeDevice:      parsed.ProbeDevice,
	}
	for _, c := range parsed.Clients {
		if !c.Enable {
			continue
		}
		user := strings.TrimSpace(c.Username)
		if user == "" {
			user = strings.TrimSpace(c.Email)
		}
		if user == "" || c.Password == "" {
			continue
		}
		inst.Clients = append(inst.Clients, ClientConfig{Username: user, Password: c.Password, Enabled: true})
	}
	return inst, true
}

// newManagementPassword mints the password protecting the daemon's management
// interface. The interface is loopback-only but not private: any local process
// that can reach the port can otherwise kill arbitrary client sessions and read
// the config, so it is always authenticated. The value lives only in the
// generated config file (mode 0600) and in the manager's memory.
func newManagementPassword() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}