package service

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/ikev2"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/openvpn"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

// DesiredOpenVPNInstances derives the openvpn daemons this panel should be
// running: one per enabled local openvpn inbound, serving only the accounts that
// are both enabled in the inbound settings and not depletion-disabled in
// client_traffics. That is the same effective client set
// buildInboundForLocalRuntime pushes on interactive edits, so the reconcile job
// and the push paths agree on one fingerprint — a disagreement would surface as
// a needless tunnel restart, and a job reading only raw settings would keep
// accepting a depleted client until an unrelated restart. Inbounds whose every
// account is filtered away are omitted so Reconcile tears their daemon down.
func (s *InboundService) DesiredOpenVPNInstances() ([]openvpn.Instance, error) {
	db := database.GetDB()
	var inbounds []*model.Inbound
	err := db.Model(model.Inbound{}).
		Where("protocol = ? AND enable = ? AND node_id IS NULL", model.OpenVPN, true).
		Find(&inbounds).Error
	if err != nil {
		return nil, err
	}
	if len(inbounds) == 0 {
		return nil, nil
	}

	instances := make([]openvpn.Instance, 0, len(inbounds))
	emails := make([]string, 0)
	for _, ib := range inbounds {
		inst, ok := openvpn.InstanceFromInbound(ib)
		if !ok {
			continue
		}
		instances = append(instances, inst)
		for _, c := range inst.Clients {
			emails = append(emails, c.Username)
		}
	}
	if len(instances) == 0 {
		return nil, nil
	}

	disabled, err := trafficDisabledEmails(db, emails)
	if err != nil {
		return nil, err
	}
	served := instances[:0]
	for _, inst := range instances {
		kept := make([]openvpn.ClientConfig, 0, len(inst.Clients))
		for _, c := range inst.Clients {
			if _, off := disabled[c.Username]; !off {
				kept = append(kept, c)
			}
		}
		inst.Clients = kept
		// A server tunnel with no accounts left would still listen and accept
		// nothing, so it is dropped and its daemon torn down. An exit has no
		// account list here, so it is always served.
		if len(inst.Clients) > 0 || inst.Role != "server" {
			served = append(served, inst)
		}
	}
	return served, nil
}

// OpenVPNExitsFromTemplate derives the openvpn exits the panel should be
// running from a raw Xray template: one per outbound carrying the panel's
// openvpn pseudo-protocol.
//
// An exit that cannot be derived is a configuration error, not something to
// skip: the outbound is still in the Xray template and its traffic is still
// routed to it, so silently not running the tunnel would leave that traffic to
// fail (or, worse, to be rerouted) with nothing in the panel explaining why.
func OpenVPNExitsFromTemplate(template string) ([]openvpn.Instance, error) {
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
	rawByTag := map[string]json.RawMessage{}
	for _, raw := range raws {
		if !openvpn.IsOpenVPNOutbound(raw) {
			continue
		}
		var probe struct {
			Tag string `json:"tag"`
		}
		if err := json.Unmarshal(raw, &probe); err != nil {
			return nil, err
		}
		if probe.Tag == "" {
			return nil, fmt.Errorf("openvpn exit outbound has no tag; every outbound must be addressable by routing rules")
		}
		if _, dup := rawByTag[probe.Tag]; dup {
			return nil, fmt.Errorf("openvpn exit outbound %q is defined twice", probe.Tag)
		}
		tags = append(tags, probe.Tag)
		rawByTag[probe.Tag] = raw
	}
	// Two exits whose tags hash to the same id would share a tunnel device and a
	// management port, so the second would silently take over the first.
	if _, _, err := openvpn.OutboundIDUnique(tags); err != nil {
		return nil, err
	}
	out := make([]openvpn.Instance, 0, len(tags))
	for _, tag := range tags {
		inst, ok := openvpn.InstanceFromOutbound(tag, rawByTag[tag])
		if !ok {
			return nil, fmt.Errorf("openvpn exit %q is not a usable exit; check its remote endpoint, CA and credentials", tag)
		}
		out = append(out, inst)
	}
	return out, nil
}

// IKEv2ExitsFromTemplate derives the ikev2 exits the panel should be running from
// a raw Xray template. An exit that cannot be derived is refused rather than
// skipped, for the same reason as the openvpn exits.
func IKEv2ExitsFromTemplate(template string) ([]ikev2.Instance, error) {
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
	rawByTag := map[string]json.RawMessage{}
	for _, raw := range raws {
		if !ikev2.IsIKEv2Outbound(raw) {
			continue
		}
		var probe struct {
			Tag string `json:"tag"`
		}
		if err := json.Unmarshal(raw, &probe); err != nil {
			return nil, err
		}
		if probe.Tag == "" {
			return nil, fmt.Errorf("ikev2 exit outbound has no tag; every outbound must be addressable by routing rules")
		}
		if _, dup := rawByTag[probe.Tag]; dup {
			return nil, fmt.Errorf("ikev2 exit outbound %q is defined twice", probe.Tag)
		}
		tags = append(tags, probe.Tag)
		rawByTag[probe.Tag] = raw
	}
	if _, _, err := ikev2.OutboundIDUnique(tags); err != nil {
		return nil, err
	}
	out := make([]ikev2.Instance, 0, len(tags))
	for _, tag := range tags {
		inst, ok := ikev2.InstanceFromOutbound(tag, rawByTag[tag])
		if !ok {
			return nil, fmt.Errorf("ikev2 exit %q is not a usable exit; check its remote endpoint, credentials and CA", tag)
		}
		out = append(out, inst)
	}
	return out, nil
}

// applyLocalOpenVPN pushes a single local openvpn inbound's current account set
// to its daemon right after a client edit commits, so an add, removal,
// re-key or enable-toggle takes effect immediately instead of waiting up to the
// reconcile cadence. It re-reads the inbound so it sees the committed settings,
// filters depleted clients exactly like the reconcile job, and is a no-op for
// node-owned or non-openvpn inbounds. Failures are logged and swallowed: the
// reconcile job is the backstop, and an xray restart cannot help the daemon.
func (s *InboundService) applyLocalOpenVPN(inboundId int) {
	inbound, err := s.GetInbound(inboundId)
	if err != nil || inbound == nil || inbound.Protocol != model.OpenVPN || inbound.NodeID != nil {
		return
	}
	rt, err := s.runtimeFor(inbound)
	if err != nil {
		return
	}
	payload := inbound
	if inbound.Enable {
		if built, bErr := s.buildInboundForLocalRuntime(database.GetDB(), inbound); bErr == nil {
			payload = built
		}
	}
	if err := rt.UpdateInbound(context.Background(), inbound, payload); err != nil {
		logger.Debug("openvpn: immediate account apply failed for inbound", inboundId, ":", err)
	}
}

// evictOpenVPNSession is the only place the revocation path talks to the
// openvpn daemon. It is a variable so a test can assert which tunnels an
// account is asked to leave — and which it must not touch — without having to
// run one.
var evictOpenVPNSession = func(inboundID int, email string) error {
	mgr := openvpn.GetManager()
	if !mgr.HasRunning() {
		return nil
	}
	return mgr.DisconnectSession(inboundID, email)
}

// disconnectOpenVPNClient evicts an account from every local openvpn tunnel it
// holds a session on. Revoking access must not wait for the session to time out,
// and must not disturb the other accounts on the same tunnel.
func (s *InboundService) disconnectOpenVPNClient(email string) {
	if email == "" {
		return
	}
	var inbounds []*model.Inbound
	if err := database.GetDB().Model(model.Inbound{}).
		Where("protocol = ? AND node_id IS NULL", model.OpenVPN).
		Find(&inbounds).Error; err != nil {
		return
	}
	for _, ib := range inbounds {
		inst, ok := openvpn.InstanceFromInbound(ib)
		if !ok || inst.Role != "server" {
			continue
		}
		// Deliberately not gated on the account still being in inst.Clients.
		// Every call site runs after the edit has committed, so a deleted,
		// renamed or disabled account is already gone from that list — a
		// membership check would skip precisely the session revocation exists
		// to end. Every local server is asked instead, and the manager treats
		// an account it does not hold as already disconnected, so tunnels
		// that never carried this account are unaffected.
		if err := evictOpenVPNSession(ib.Id, email); err != nil {
			logger.Debug("openvpn: disconnecting", email, "from inbound", ib.Id, "failed:", err)
		}
	}
}
