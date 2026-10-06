// Package ikev2 manages IKEv2 tunnels through strongSwan's VICI protocol.
//
// Xray-core cannot terminate or originate an IKEv2 session, so these
// inbounds/exits live outside the Xray config and lifecycle entirely. The
// difference from the OpenVPN adapter is the control surface: rather than
// spawning a per-tunnel daemon, the panel drives a single system-wide charon
// over its VICI socket. That is what makes separate XFRM identities per exit
// possible — each exit is a distinct connection object with its own
// reqid/ID pair, so two exits never share kernel state and one being torn down
// cannot disturb the other.
//
// Authentication is EAP username/password (the panel account) plus mutual
// certificate where configured, and a pre-shared key only for the
// authentication method that actually needs one. Secrets are handed to VICI in
// memory over a socket the panel creates with owner-only permissions, and never
// reach a response, a log line, or a metric label.
package ikev2

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/vpn"
)

// ClientConfig is one panel account permitted to authenticate against a
// server-side tunnel.
type ClientConfig struct {
	Username string
	Password string
	// ID is the IKE identity suffix for this account, e.g. "alice". It defaults
	// to the username so a connection's peer ID matches its panel account.
	ID string
	Enabled bool
}

// Instance is the desired state of one IKEv2 tunnel.
type Instance struct {
	ID   int
	Tag  string
	Role vpn.Role

	// Server side.
	Listen string
	Port   int
	// Subnet is the pool the responder hands out, e.g. "10.10.0.0/24".
	Subnet string
	// DNSServer is pushed to connected clients.
	DNSServer string
	// HostCert/HostKey identify the panel to clients.
	HostCert string
	HostKey  string
	// CA is the trust anchor for client certificates. Required when the
	// account's auth method includes certificate authentication.
	CA string
	// PSK is only used by an account whose auth method needs one.
	PSK string
	// AuthMethod is "eap-mschapv2" (the default, panel-account based),
	// "cert", or "psk".
	AuthMethod string
	// UniqueIDs forces a distinct IKE identity per account. Left off, one
	// shared identity would let any account impersonate another, so the panel
	// turns it on unless explicitly disabled.
	UniqueIDs bool
	Clients   []ClientConfig

	// Client side.
	Remote      string
	RemotePort  int
	// RemoteID is the IKE identity the peer is expected to present. Left empty
	// the panel accepts the remote address as the identity, which is weaker than
	// pinning a real identity, so an operator can set it explicitly.
	RemoteID    string
	LocalAddr   string
	LocalPort   int
	NATTraversal bool
	IKEVersion  int
	Encryption  string
	Username    string
	Password    string
	ClientCert  string
	ClientKey   string
	// Identity is this exit's XFRM/IKE identity. Distinct per exit so kernel
	// policy and SA state cannot collide.
	Identity string
	// ReqID is the XFRM reqid for this exit's policies and SAs.
	ReqID int

	// RouteThroughXray bridges this tunnel's traffic through the Xray routing
	// path so VPN clients keep panel access rules and per-client accounting.
	RouteThroughXray bool
	XrayRoutePort    int

	// ProbeTarget is a host:port an exit tunnel is measured against. Empty means
	// no data-plane measurement: the tunnel is then judged purely on whether it
	// holds an established child SA, and its latency is reported as unknown
	// rather than guessed.
	ProbeTarget string
	// ProbeDevice is the interface the probe's socket is pinned to. Empty means
	// the exit's own kernel interface.
	ProbeDevice string
}

// probeDevice is the interface an exit's probe is pinned to. Pinned explicitly
// so the measurement cannot be satisfied by the real uplink: a probe that may go
// any way proves nothing about whether the tunnel carries traffic.
func (inst Instance) probeDevice() string {
	if d := strings.TrimSpace(inst.ProbeDevice); d != "" {
		return d
	}
	return ExitDev(inst.ID)
}

func (inst Instance) role() vpn.Role {
	if inst.Role == "" {
		return vpn.RoleServer
	}
	return inst.Role
}

func (inst Instance) isServer() bool { return inst.role() == vpn.RoleServer }

// devName is the kernel interface this tunnel's SA gets.
//
// The name is derived, not charon's default ipsecN, because the panel binds
// Xray's exit outbound to it by name and two tunnels must never share one
// interface.
func (inst Instance) devName() string {
	if inst.isServer() {
		return ServerDev(inst.ID)
	}
	return ExitDev(inst.ID)
}

func (inst Instance) authMethod() string {
	if strings.TrimSpace(inst.AuthMethod) != "" {
		return strings.ToLower(strings.TrimSpace(inst.AuthMethod))
	}
	return "eap-mschapv2"
}

// instanceName is the strongSwan connection name. It must be unique per panel
// instance and stable across restarts, so it is derived from the id rather than
// from mutable settings.
func (inst Instance) instanceName() string {
	return fmt.Sprintf("xui-%d", inst.ID)
}

// InstanceFromInbound derives a desired Instance from an ikev2 inbound. Returns
// false when the inbound is not a usable ikev2 inbound.
func InstanceFromInbound(ib *model.Inbound) (Instance, bool) {
	if ib == nil || ib.Protocol != model.IKEv2 {
		return Instance{}, false
	}
	var parsed struct {
		Mode            string `json:"mode"`
		Subnet          string `json:"subnet"`
		DNSServer       string `json:"dnsServer"`
		HostCert        string `json:"hostCert"`
		HostKey         string `json:"hostKey"`
		CA              string `json:"caCert"`
		PSK             string `json:"psk"`
		AuthMethod      string `json:"authMethod"`
		UniqueIDs       *bool  `json:"uniqueIds"`
		Encryption      string `json:"encryption"`
		NATTraversal    *bool  `json:"natTraversal"`
		RouteThroughXray bool   `json:"routeThroughXray"`
		RouteXrayPort    int    `json:"routeXrayPort"`
		ProbeTarget      string `json:"probeTarget"`
		ProbeDevice      string `json:"probeDevice"`
		Clients          []struct {
			Email    string `json:"email"`
			Username string `json:"username"`
			Password string `json:"password"`
			ID       string `json:"id"`
			Enable   bool   `json:"enable"`
		} `json:"clients"`
	}
	if err := json.Unmarshal([]byte(ib.Settings), &parsed); err != nil {
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
		Subnet:           parsed.Subnet,
		DNSServer:        parsed.DNSServer,
		HostCert:         parsed.HostCert,
		HostKey:          parsed.HostKey,
		CA:               parsed.CA,
		PSK:              parsed.PSK,
		AuthMethod:       parsed.AuthMethod,
		Encryption:       parsed.Encryption,
		NATTraversal:     true,
		RouteThroughXray: parsed.RouteThroughXray,
		XrayRoutePort:    parsed.RouteXrayPort,
		ProbeTarget:      strings.TrimSpace(parsed.ProbeTarget),
		ProbeDevice:      strings.TrimSpace(parsed.ProbeDevice),
	}
	if parsed.NATTraversal != nil {
		inst.NATTraversal = *parsed.NATTraversal
	}
	// A shared identity would let any account impersonate another, so
	// per-account identities are the default and disabling them is explicit.
	inst.UniqueIDs = parsed.UniqueIDs == nil || *parsed.UniqueIDs
	if role == vpn.RoleClient {
		inst.Identity = clientIdentity(ib.Id)
		inst.ReqID = reqIDFor(ib.Id)
		inst.IKEVersion = 2
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
		id := strings.TrimSpace(c.ID)
		if id == "" {
			id = user
		}
		inst.Clients = append(inst.Clients, ClientConfig{
			Username: user,
			Password: c.Password,
			ID:       id,
			Enabled:  true,
		})
	}
	return inst, true
}

// clientIdentity is the per-exit IKE identity. Including the instance id keeps
// two exits distinct even when they dial the same peer.
func clientIdentity(id int) string {
	return fmt.Sprintf("xui-exit-%d", id)
}

// newSecret mints a random value for a generated credential the panel owns.
// Used for the per-connection IKE ID salt, so two exits never derive the same
// identity from the same inputs.
func newSecret(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// DefaultSocketPath is where the panel expects strongSwan's VICI socket when the
// daemon is local. It matches strongSwan's own default so an operator does not
// have to configure a nonstandard path.
func DefaultSocketPath() string {
	if p := strings.TrimSpace(os.Getenv("XUI_SWAN_VICI")); p != "" {
		return p
	}
	return "/var/run/charon.vici"
}