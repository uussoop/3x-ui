package job

import (
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/openvpn"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service/outbound"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

// OpenVPNJob reconciles the running openvpn daemons against the enabled openvpn
// inbounds in the database and the openvpn exits in the Xray template, restarts
// any that exited or whose configuration changed, and folds the per-client
// traffic scraped from each daemon's management interface into the usual client
// and inbound accounting.
//
// Inbounds and exits share one manager, and therefore one reconcile: an exit is
// a tunnel like any other, and keeping them in separate managers would mean two
// places that could disagree about which tunnels are supposed to be running.
type OpenVPNJob struct {
	inboundService service.InboundService
	settingService service.SettingService
}

// NewOpenVPNJob creates a new openvpn reconcile/traffic job instance.
func NewOpenVPNJob() *OpenVPNJob {
	return new(OpenVPNJob)
}

// Run reconciles desired openvpn tunnels with running daemons and records
// per-client traffic deltas and online status.
func (j *OpenVPNJob) Run() {
	desired, err := j.inboundService.DesiredOpenVPNInstances()
	if err != nil {
		logger.Warning("openvpn job: get desired instances failed:", err)
		return
	}

	// An exit the panel cannot derive is not skipped silently: the outbound is
	// still in the template and traffic is still routed to it. Logging it loudly
	// and carrying on with the inbounds is the safe half-failure — the exit's
	// outbound is device-bound, so with no tunnel behind it those connections fail
	// rather than escaping over the real uplink.
	exits, exitErr := j.desiredExits()
	if exitErr != nil {
		logger.Warning("openvpn job: cannot derive openvpn exits, they will stay down:", exitErr)
		exits = nil
	}

	exitTags := make(map[string]bool, len(exits))
	for _, inst := range exits {
		exitTags[inst.Tag] = true
	}

	routedTags := make(map[string]bool)
	activeTags := make([]string, 0, len(desired))
	for _, inst := range desired {
		activeTags = append(activeTags, inst.Tag)
		if inst.RouteThroughXray {
			routedTags[inst.Tag] = true
		}
	}

	mgr := openvpn.GetManager()
	all := make([]openvpn.Instance, 0, len(desired)+len(exits))
	all = append(all, desired...)
	all = append(all, exits...)
	mgr.Reconcile(all)

	deltas, onlineEmails, _ := mgr.CollectTraffic()

	// A routed inbound's total is already metered through the Xray bridge by
	// xray_traffic_job, so only non-routed inbounds are rolled up here; per-client
	// deltas are always kept, since the bridge cannot tell VPN users apart.
	clientTraffics := make([]*xray.ClientTraffic, 0, len(deltas))
	inboundUp := make(map[string]int64)
	inboundDown := make(map[string]int64)
	exitUp := make(map[string]int64)
	exitDown := make(map[string]int64)
	for _, d := range deltas {
		if d.Email != "" {
			clientTraffics = append(clientTraffics, &xray.ClientTraffic{
				Email: d.Email,
				Up:    d.Up,
				Down:  d.Down,
			})
		}
		// An exit's bytes left the host through that outbound, so they belong to
		// the outbound's counters. Booking them as inbound traffic instead would
		// invent a phantom inbound row for a tag no inbound owns.
		if exitTags[d.Tag] {
			exitUp[d.Tag] += d.Up
			exitDown[d.Tag] += d.Down
			continue
		}
		if !routedTags[d.Tag] {
			inboundUp[d.Tag] += d.Up
			inboundDown[d.Tag] += d.Down
		}
	}

	traffics := make([]*xray.Traffic, 0, len(inboundUp))
	for tag, up := range inboundUp {
		traffics = append(traffics, &xray.Traffic{
			IsInbound: true,
			Tag:       tag,
			Up:        up,
			Down:      inboundDown[tag],
		})
	}

	if len(traffics) > 0 || len(clientTraffics) > 0 {
		if _, _, err := j.inboundService.AddTraffic(traffics, clientTraffics); err != nil {
			logger.Warning("openvpn job: add traffic failed:", err)
		}
	}

	if len(exitUp) > 0 {
		exitTraffics := make([]*xray.Traffic, 0, len(exitUp))
		for tag, up := range exitUp {
			exitTraffics = append(exitTraffics, &xray.Traffic{
				IsOutbound: true,
				Tag:        tag,
				Up:         up,
				Down:       exitDown[tag],
			})
		}
		if err, _ := (&outbound.OutboundService{}).AddTraffic(exitTraffics, nil); err != nil {
			logger.Warning("openvpn job: add exit traffic failed:", err)
		}
	}

	j.inboundService.RefreshLocalOnlineClients(onlineEmails, activeTags)
}

// desiredExits derives the openvpn exits from the Xray template.
func (j *OpenVPNJob) desiredExits() ([]openvpn.Instance, error) {
	template, err := j.settingService.GetXrayConfigTemplate()
	if err != nil {
		return nil, err
	}
	return service.OpenVPNExitsFromTemplate(template)
}