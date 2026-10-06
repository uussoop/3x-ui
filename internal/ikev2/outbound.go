package ikev2

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/vpn"
)

// An ikev2 *outbound* is an exit: strongSwan runs as an initiator and Xray sends
// selected traffic through the tunnel. Xray has no IKEv2 proxy, so the template
// entry is replaced at config-generation time by a freedom outbound pinned to the
// exit's kernel interface (see BuildDeviceBridge).
//
// Unlike OpenVPN, two IKEv2 exits cannot both be active on one host. An exit
// installs XFRM policies for all traffic, and the kernel matches them by
// priority rather than by which tunnel the packet was meant for: with two exits
// both covering 0.0.0.0/0, one exit's packets would be encrypted by the other's
// SA. Separating them needs per-exit packet marks and routing rules, which the
// panel deliberately does not manipulate (it refuses to shell out and refuses to
// run arbitrary scripts). So a second concurrent exit is refused rather than
// silently misrouted.

// ikev2OutboundSettings mirrors the frontend's IKEv2 outbound settings.
type ikev2OutboundSettings struct {
	Mode        string `json:"mode"`
	Remote      string `json:"remote"`
	Port        int    `json:"port"`
	LocalAddr   string `json:"localAddr"`
	NATTraversal *bool  `json:"natTraversal"`
	IKEVersion  int    `json:"ikeVersion"`
	Encryption  string `json:"encryption"`
	AuthMethod  string `json:"authMethod"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	PSK         string `json:"psk"`
	CACert      string `json:"caCert"`
	ClientCert  string `json:"clientCert"`
	ClientKey   string `json:"clientKey"`
	ProbeTarget string `json:"probeTarget"`
	ProbeDevice string `json:"probeDevice"`
}

// IsIKEv2Outbound reports whether a raw outbound JSON object from the Xray
// template carries the panel's ikev2 pseudo-protocol.
func IsIKEv2Outbound(raw []byte) bool {
	var probe struct {
		Protocol string `json:"protocol"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return false
	}
	return strings.EqualFold(probe.Protocol, "ikev2")
}

// OutboundID derives a stable instance id for an exit from its outbound tag.
// Negative, so an exit can never collide with an inbound in the managers' map or
// in a connection name.
func OutboundID(tag string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(tag))
	// 1..50000 keeps the derived XFRM reqid inside the kernel's range and far
	// from the 4000+inboundId range that inbounds use.
	return -(int(h.Sum32()%50000) + 1)
}

// OutboundIDUnique derives ids for a whole set of exit tags and reports the tags
// whose ids collided. Two exits sharing an id would share a reqid and an
// interface name, so a collision is refused rather than resolved silently.
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
		return nil, clashes, fmt.Errorf("ikev2 exit tags collide: %s", strings.Join(clashes, "; "))
	}
	return byTag, nil, nil
}

// ExitDev returns the kernel interface name an exit's tunnel gets. It must be
// deterministic: the panel binds Xray's outbound to it by name, and an
// operator-chosen name is honoured when it is a real one.
func ExitDev(id int) string {
	if id > 0 {
		return fmt.Sprintf("xui-ike-s%d", id)
	}
	return fmt.Sprintf("xui-ike-e%d", -id)
}

// ServerDev returns the kernel interface name a responder's tunnel gets.
func ServerDev(id int) string { return fmt.Sprintf("xui-ike-s%d", id) }

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
	var parsed ikev2OutboundSettings
	if err := json.Unmarshal(wrapper.Settings, &parsed); err != nil {
		return Instance{}, false
	}
	if strings.TrimSpace(tag) == "" {
		return Instance{}, false
	}

	id := OutboundID(tag)
	inst := Instance{
		ID:           id,
		Tag:          tag,
		Role:         vpn.RoleClient,
		Remote:       strings.TrimSpace(parsed.Remote),
		RemotePort:   parsed.Port,
		RemoteID:     strings.TrimSpace(parsed.Username),
		LocalAddr:    parsed.LocalAddr,
		Encryption:   parsed.Encryption,
		AuthMethod:   parsed.AuthMethod,
		Username:     parsed.Username,
		Password:     parsed.Password,
		PSK:          parsed.PSK,
		CA:           parsed.CACert,
		ClientCert:   parsed.ClientCert,
		ClientKey:    parsed.ClientKey,
		IKEVersion:   2,
		NATTraversal: true,
		Identity:     clientIdentity(-id),
		ReqID:        reqIDFor(id),
		ProbeTarget:  strings.TrimSpace(parsed.ProbeTarget),
		ProbeDevice:  strings.TrimSpace(parsed.ProbeDevice),
	}
	_ = parsed.Mode
	if parsed.NATTraversal != nil {
		inst.NATTraversal = *parsed.NATTraversal
	}
	if parsed.IKEVersion > 0 {
		inst.IKEVersion = parsed.IKEVersion
	}
	if dev := strings.TrimSpace(parsed.ProbeDevice); dev != "" {
		inst.ProbeDevice = dev
	} else {
		inst.ProbeDevice = ExitDev(id)
	}
	if _, err := ParseProbeTarget(inst.ProbeTarget); err != nil && inst.ProbeTarget != "" {
		return Instance{}, false
	}
	return inst, inst.Validate() == nil
}

// ParseProbeTarget is a thin wrapper kept so the outbound path validates the
// probe target with the same rules the runtime probe applies.
func ParseProbeTarget(target string) (string, error) {
	if strings.TrimSpace(target) == "" {
		return "", nil
	}
	if err := vpn.ValidateProbeTarget(target); err != nil {
		return "", err
	}
	return strings.TrimSpace(target), nil
}

// reqIDFor maps an instance id to an XFRM reqid.
//
// The mapping has to be injective: two exits with the same reqid would share
// kernel SA and policy state, so tearing one down could tear down the other's
// tunnel. Inbounds use 4000+id; exits land in a separate band.
func reqIDFor(id int) int {
	if id < 0 {
		return 40000 + (-id)
	}
	return 4000 + id
}

// BuildDeviceBridge replaces a template "ikev2" outbound with a freedom
// outbound pinned to the exit's kernel interface.
//
// Pinning is what makes the exit enforceable rather than decorative. An IKEv2
// child SA that is torn down takes its policies with it, so an unbound freedom
// outbound would fall back to the real uplink exactly when the tunnel is
// broken — silently leaking the traffic the exit was chosen to protect. Bound to
// an interface that no longer exists, the dial fails instead.
func BuildDeviceBridge(tag string, raw []byte) (json.RawMessage, bool) {
	var probe struct {
		Tag      string          `json:"tag"`
		Settings json.RawMessage `json:"settings"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil || strings.TrimSpace(probe.Tag) == "" {
		return nil, false
	}
	replacement := map[string]any{
		"tag":      probe.Tag,
		"protocol": "freedom",
		"settings": map[string]any{},
		"streamSettings": map[string]any{
			"sockopt": map[string]any{"interface": ExitDev(OutboundID(probe.Tag))},
		},
	}
	bs, err := json.Marshal(replacement)
	if err != nil {
		return nil, false
	}
	return bs, true
}