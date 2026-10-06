package service

import (
	"encoding/json"
	"fmt"

	"github.com/mhsanaei/3x-ui/v3/internal/ikev2"
	"github.com/mhsanaei/3x-ui/v3/internal/openvpn"
	json_util "github.com/mhsanaei/3x-ui/v3/internal/util/json_util"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

// transformVPNExitOutbounds replaces each template "openvpn"/"ikev2" outbound
// with a freedom outbound pinned to that exit's tunnel device.
//
// It runs before anything else reads OutboundConfigs, for the same reason
// transformAmneziaWGOutbounds does: the core has no openvpn or ikev2 proxy and
// would reject the raw entry outright.
//
// The replacement is deliberately device-bound rather than a bare freedom
// outbound. An unbound exit is not an exit at all — when its tunnel drops, the
// kernel policies go with it and the same traffic leaves over the real uplink,
// so a broken exit would silently become a bypass instead of a failure. Bound to
// a device that no longer exists, the dial fails, and failing is the correct
// behaviour for an exit whose tunnel is down.
//
// An entry that cannot be bridged fails generation instead of being skipped: a
// silently dropped outbound would take a routing rule or balancer member with it,
// and the operator would only find out as missing traffic.
func transformVPNExitOutbounds(cfg *xray.Config) error {
	if len(cfg.OutboundConfigs) == 0 {
		return nil
	}
	var outbounds []json.RawMessage
	if err := json.Unmarshal(cfg.OutboundConfigs, &outbounds); err != nil {
		return err
	}
	changed := false
	for i, raw := range outbounds {
		bridge, isExit := vpnExitBridge(raw)
		if !isExit {
			continue
		}
		replacement, ok := bridge(raw)
		if !ok {
			var probe struct {
				Tag string `json:"tag"`
			}
			tagErr := json.Unmarshal(raw, &probe)
			if tagErr != nil {
				return fmt.Errorf("VPN exit outbound %d: unreadable tag: %w", i, tagErr)
			}
			return fmt.Errorf("VPN exit outbound %d (%q): cannot bridge: tag must be a non-empty string", i, probe.Tag)
		}
		outbounds[i] = replacement
		changed = true
	}
	if !changed {
		return nil
	}
	bs, err := json.Marshal(outbounds)
	if err != nil {
		return err
	}
	cfg.OutboundConfigs = json_util.RawMessage(bs)
	return nil
}

// vpnExitBridge returns the bridge builder for a raw outbound, and whether the
// outbound is a VPN exit at all.
func vpnExitBridge(raw []byte) (func([]byte) (json.RawMessage, bool), bool) {
	switch {
	case openvpn.IsOpenVPNOutbound(raw):
		return func(in []byte) (json.RawMessage, bool) {
			var probe struct {
				Tag string `json:"tag"`
			}
			if err := json.Unmarshal(in, &probe); err != nil {
				return nil, false
			}
			return openvpn.BuildDeviceBridge(probe.Tag, in)
		}, true
	case ikev2.IsIKEv2Outbound(raw):
		return func(in []byte) (json.RawMessage, bool) {
			var probe struct {
				Tag string `json:"tag"`
			}
			if err := json.Unmarshal(in, &probe); err != nil {
				return nil, false
			}
			return ikev2.BuildDeviceBridge(probe.Tag, in)
		}, true
	default:
		return nil, false
	}
}

// VPNExitTags returns the outbound tags that are served by a managed VPN daemon,
// in the order the template lists them.
func VPNExitTags(template string) ([]string, error) {
	if template == "" {
		return nil, nil
	}
	cfg := &xray.Config{}
	if err := json.Unmarshal([]byte(template), cfg); err != nil {
		return nil, err
	}
	if len(cfg.OutboundConfigs) == 0 {
		return nil, nil
	}
	var raws []json.RawMessage
	if err := json.Unmarshal(cfg.OutboundConfigs, &raws); err != nil {
		return nil, err
	}
	var tags []string
	for _, raw := range raws {
		if _, isExit := vpnExitBridge(raw); !isExit {
			continue
		}
		var probe struct {
			Tag string `json:"tag"`
		}
		if err := json.Unmarshal(raw, &probe); err != nil || probe.Tag == "" {
			continue
		}
		tags = append(tags, probe.Tag)
	}
	return tags, nil
}