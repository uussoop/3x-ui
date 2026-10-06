package openvpn

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/vpn"
)

// An openvpn *outbound* is an exit: the panel runs openvpn as a client and
// sends selected traffic through the tunnel. Xray has no openvpn proxy, so the
// template entry is not something the core can use as-is — it is replaced at
// config-generation time by a freedom outbound pinned to the tunnel's device
// (see BuildDeviceBridge). The panel therefore owns the whole lifecycle of an
// exit, exactly as it does for an inbound.

// openvpnOutboundSettings mirrors the frontend's OpenVPN outbound settings. The
// field names are the schema's own, so a settings object that validates in the
// UI parses here without a translation table that could drift.
type openvpnOutboundSettings struct {
	Mode         string `json:"mode"`
	Config       string `json:"config"`
	AuthUserPass string `json:"authUserPass"`
	Dev          string `json:"dev"`
	Proto        string `json:"proto"`
	Remote       string `json:"remote"`
	Port         int    `json:"port"`
	Cipher       string `json:"cipher"`
	Auth         string `json:"auth"`
	CompLzo      string `json:"compLzo"`
	Verb         int    `json:"verb"`
	CA           string `json:"ca"`
	Cert         string `json:"cert"`
	Key          string `json:"key"`
	TLSAuth      string `json:"tlsAuth"`
	ProbeTarget  string `json:"probeTarget"`
	ProbeDevice  string `json:"probeDevice"`
}

// IsOpenVPNOutbound reports whether a raw outbound JSON object from the Xray
// template carries the panel's openvpn pseudo-protocol.
func IsOpenVPNOutbound(raw []byte) bool {
	var probe struct {
		Protocol string `json:"protocol"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return false
	}
	return strings.EqualFold(probe.Protocol, "openvpn")
}

// OutboundID derives a stable instance id for an exit from its outbound tag.
//
// Exits have no database id, but every path, port and device name in this
// package is keyed by instance id, so one has to be synthesised. It is negative
// because inbound ids are positive: an exit can therefore never collide with an
// inbound in the managers' map, in a config filename or in a management port.
//
// The value is deliberately bounded so the derived management port stays a valid
// port number. Two different tags hashing to the same id would make one exit's
// tunnel overwrite the other's, so callers check for that (see OutboundIDUnique).
func OutboundID(tag string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(tag))
	// 1..50000 keeps the derived management port inside 8705..57004.
	return -(int(h.Sum32()%50000) + 1)
}

// OutboundIDUnique derives ids for a whole set of exit tags and reports the tags
// whose ids collided. A collision is refused rather than resolved silently: two
// exits sharing an id would share a management port and a device name, and the
// second would take over the first's tunnel.
func OutboundIDUnique(tags []string) (map[string]int, []string, error) {
	byID := make(map[int]string, len(tags))
	byTag := make(map[string]int, len(tags))
	var clashes []string
	for _, tag := range tags {
		id := OutboundID(tag)
		if other, dup := byID[id]; dup {
			clashes = append(clashes, fmt.Sprintf("%s and %s both map to exit %d", other, tag, -id))
			continue
		}
		byID[id] = tag
		byTag[tag] = id
	}
	if len(clashes) > 0 {
		return nil, clashes, fmt.Errorf("openvpn exit tags collide: %s", strings.Join(clashes, "; "))
	}
	return byTag, nil, nil
}

// ExitDev returns the tunnel device an exit owns.
//
// The name must be deterministic, not openvpn's default "tun", for two reasons:
// the panel binds Xray's outbound to this device by name, and two exits sharing
// one device would send each other's traffic through the wrong tunnel.
func ExitDev(id int) string {
	if id > 0 {
		return fmt.Sprintf("xui-ovpn-s%d", id)
	}
	return fmt.Sprintf("xui-ovpn-e%d", -id)
}

// ServerDev returns the tunnel device a server-side inbound owns.
func ServerDev(id int) string { return fmt.Sprintf("xui-ovpn-s%d", id) }

// InstanceFromOutbound derives a client-mode instance from one raw template
// outbound. It returns false when the entry is not a usable exit, which the
// caller must treat as a configuration error rather than something to skip.
func InstanceFromOutbound(tag string, raw []byte) (Instance, bool) {
	var wrapper struct {
		Settings json.RawMessage `json:"settings"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil || len(wrapper.Settings) == 0 {
		return Instance{}, false
	}
	var parsed openvpnOutboundSettings
	if err := json.Unmarshal(wrapper.Settings, &parsed); err != nil {
		return Instance{}, false
	}
	if strings.TrimSpace(tag) == "" {
		return Instance{}, false
	}

	id := OutboundID(tag)
	inst := Instance{
		ID:               id,
		Tag:              tag,
		Role:             vpn.RoleClient,
		Remote:           strings.TrimSpace(parsed.Remote),
		RemotePort:       parsed.Port,
		RemoteProto:      parsed.Proto,
		Dev:              ExitDev(id),
		Verb:             parsed.Verb,
		CA:               parsed.CA,
		Cert:             parsed.Cert,
		Key:              parsed.Key,
		Profile:          parsed.Config,
		ProbeTarget:      strings.TrimSpace(parsed.ProbeTarget),
		ProbeDevice:      strings.TrimSpace(parsed.ProbeDevice),
	}
	// An operator-supplied device name wins, but only when it is a real name:
	// openvpn's "tun"/"tap" means "pick the next free tunN", which is not
	// something the panel can bind Xray to.
	if dev := strings.TrimSpace(parsed.Dev); dev != "" && !strings.EqualFold(dev, "tun") && !strings.EqualFold(dev, "tap") {
		inst.Dev = dev
	}
	// "user\npass" is how the UI carries a credential pair without adding a
	// second schema shape; openvpn's auth-user-pass file has exactly that form.
	if creds := strings.SplitN(strings.ReplaceAll(parsed.AuthUserPass, "\r\n", "\n"), "\n", 2); len(creds) == 2 {
		inst.Username = strings.TrimSpace(creds[0])
		inst.Password = strings.TrimSpace(creds[1])
	}
	// An imported profile is data, not authority: it is parsed through the same
	// allowlist an inbound's profile goes through, and rejected outright if it
	// carries anything executable.
	if _, err := ParseProfile(parsed.Config); err != nil && strings.TrimSpace(parsed.Config) != "" {
		return Instance{}, false
	}
	return inst, inst.Validate() == nil
}

// BuildDeviceBridge replaces a template "openvpn" outbound with a freedom
// outbound pinned to the exit's tunnel device.
//
// Pinning to the device rather than leaving a plain freedom outbound is the whole
// safety argument for an exit. Without it, traffic meant for the tunnel would
// leave over the real uplink whenever the tunnel was down — the exact leak an
// exit exists to prevent — and a second exit's traffic would go out the first
// exit's device. With it, a tunnel that is not carrying makes the dial fail, so
// the failure is a failed connection rather than a silent bypass.
//
// The replacement keeps the operator's tag, so every routing rule and balancer
// membership that names it keeps working.
func BuildDeviceBridge(tag string, raw []byte) (json.RawMessage, bool) {
	var probe struct {
		Tag string `json:"tag"`
		Settings json.RawMessage `json:"settings"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil || strings.TrimSpace(probe.Tag) == "" {
		return nil, false
	}
	var parsed openvpnOutboundSettings
	if len(probe.Settings) > 0 {
		if err := json.Unmarshal(probe.Settings, &parsed); err != nil {
			return nil, false
		}
	}
	dev := ExitDev(OutboundID(probe.Tag))
	if d := strings.TrimSpace(parsed.Dev); d != "" && !strings.EqualFold(d, "tun") && !strings.EqualFold(d, "tap") {
		dev = d
	}
	replacement := map[string]any{
		"tag":      probe.Tag,
		"protocol": "freedom",
		"settings": map[string]any{},
		// interface is honoured by the core on Linux only. Where it is not
		// honoured the exit cannot be enforced by binding alone, so the
		// generated entry says so rather than pretending: Readiness is checked
		// against the running tunnel before the config is served.
		"streamSettings": map[string]any{
			"sockopt": map[string]any{"interface": dev},
		},
	}
	bs, err := json.Marshal(replacement)
	if err != nil {
		return nil, false
	}
	return bs, true
}