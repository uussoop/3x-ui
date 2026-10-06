package service

import (
	"context"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/ikev2"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
)

// DesiredIKEv2Instances derives the strongSwan connections this panel should be
// holding: one per enabled local ikev2 inbound. Like the OpenVPN path it serves
// only accounts that are both enabled in the inbound settings and not
// depletion-disabled in client_traffics, so the reconcile job and the push
// paths agree on one fingerprint and a depleted client is actually cut off
// instead of merely being marked so.
func (s *InboundService) DesiredIKEv2Instances() ([]ikev2.Instance, error) {
	db := database.GetDB()
	var inbounds []*model.Inbound
	err := db.Model(model.Inbound{}).
		Where("protocol = ? AND enable = ? AND node_id IS NULL", model.IKEv2, true).
		Find(&inbounds).Error
	if err != nil {
		return nil, err
	}
	if len(inbounds) == 0 {
		return nil, nil
	}

	instances := make([]ikev2.Instance, 0, len(inbounds))
	emails := make([]string, 0)
	for _, ib := range inbounds {
		inst, ok := ikev2.InstanceFromInbound(ib)
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
		kept := make([]ikev2.ClientConfig, 0, len(inst.Clients))
		for _, c := range inst.Clients {
			if _, off := disabled[c.Username]; !off {
				kept = append(kept, c)
			}
		}
		inst.Clients = kept
		// A responder with no accounts left must stop terminating: it would
		// otherwise keep advertising an IKE_SA_INIT it can never authenticate.
		if len(inst.Clients) > 0 || inst.Role != "server" {
			served = append(served, inst)
		}
	}
	return served, nil
}

// applyLocalIKEv2 pushes a single local ikev2 inbound's current account set to
// strongSwan right after a client edit commits, so access changes take effect
// immediately instead of waiting for the reconcile cadence. Failures are logged
// and swallowed: the reconcile job is the backstop and an xray restart is
// irrelevant to a strongSwan connection.
func (s *InboundService) applyLocalIKEv2(inboundId int) {
	inbound, err := s.GetInbound(inboundId)
	if err != nil || inbound == nil || inbound.Protocol != model.IKEv2 || inbound.NodeID != nil {
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
		logger.Debug("ikev2: immediate account apply failed for inbound", inboundId, ":", err)
	}
}

// evictIKEv2Session is the only place the revocation path talks to strongSwan.
// It is a variable so a test can assert which tunnels an account is asked to
// leave without having to run one.
var evictIKEv2Session = func(inboundID int, email string) error {
	mgr := ikev2.GetManager()
	if !mgr.HasRunning() {
		return nil
	}
	return mgr.Terminate(inboundID, email)
}

// disconnectIKEv2Client terminates an account's IKE_SA across every local ikev2
// tunnel it holds one on. A revoked account that keeps its child SA alive would
// keep a working path into the panel's routing, so the termination has to happen
// at reconnect/apply time rather than by restarting charon for everyone.
func (s *InboundService) disconnectIKEv2Client(email string) {
	if email == "" {
		return
	}
	var inbounds []*model.Inbound
	if err := database.GetDB().Model(model.Inbound{}).
		Where("protocol = ? AND node_id IS NULL", model.IKEv2).
		Find(&inbounds).Error; err != nil {
		return
	}
	for _, ib := range inbounds {
		inst, ok := ikev2.InstanceFromInbound(ib)
		if !ok || inst.Role != "server" {
			continue
		}
		// Not gated on the account still being in inst.Clients: this runs
		// after the edit has committed, so a deleted, renamed or disabled
		// account is already out of the list and a membership check would skip
		// the very SA it exists to terminate. See disconnectOpenVPNClient.
		if err := evictIKEv2Session(ib.Id, email); err != nil {
			logger.Debug("ikev2: terminating", email, "on inbound", ib.Id, "failed:", err)
		}
	}
}