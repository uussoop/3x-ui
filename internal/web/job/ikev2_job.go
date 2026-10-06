package job

import (
	"github.com/mhsanaei/3x-ui/v3/internal/ikev2"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service/outbound"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

// IKEv2Job reconciles the connections loaded into strongSwan against the enabled
// ikev2 inbounds in the database and the ikev2 exits in the Xray template,
// reloads any whose configuration changed, and folds the per-client traffic
// scraped from the SA table into the usual client and inbound accounting.
//
// Inbounds and exits share one manager, and therefore one reconcile: strongSwan
// is a single system-wide daemon either way, so keeping the two sets apart would
// only mean two places that could disagree about what is loaded.
type IKEv2Job struct {
	inboundService service.InboundService
	settingService service.SettingService
}

// NewIKEv2Job creates a new ikev2 reconcile/traffic job instance.
func NewIKEv2Job() *IKEv2Job {
	return new(IKEv2Job)
}

// Run reconciles desired ikev2 tunnels with the connections loaded into
// strongSwan and records per-client traffic deltas and online status.
func (j *IKEv2Job) Run() {
	desired, err := j.inboundService.DesiredIKEv2Instances()
	if err != nil {
		logger.Warning("ikev2 job: get desired instances failed:", err)
		return
	}

	// An exit the panel cannot derive is not skipped silently: the outbound is
	// still in the template and traffic is still routed to it. The exit's outbound
	// is interface-bound, so with no child SA behind it those connections fail
	// rather than escaping over the real uplink.
	exits, exitErr := j.desiredExits()
	if exitErr != nil {
		logger.Warning("ikev2 job: cannot derive ikev2 exits, they will stay down:", exitErr)
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

	mgr := ikev2.GetManager()
	all := make([]ikev2.Instance, 0, len(desired)+len(exits))
	all = append(all, desired...)
	all = append(all, exits...)
	mgr.Reconcile(all)

	deltas, onlineEmails, _ := mgr.CollectTraffic()

	// A routed inbound's total is already metered through the Xray bridge by
	// xray_traffic_job, so only non-routed inbounds are rolled up here; per-client
	// deltas are always kept, since the bridge cannot tell IKE clients apart.
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
		// the outbound's counters, not to an inbound that does not exist.
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
			logger.Warning("ikev2 job: add traffic failed:", err)
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
			logger.Warning("ikev2 job: add exit traffic failed:", err)
		}
	}

	j.inboundService.RefreshLocalOnlineClients(onlineEmails, activeTags)
}

// desiredExits derives the ikev2 exits from the Xray template.
func (j *IKEv2Job) desiredExits() ([]ikev2.Instance, error) {
	template, err := j.settingService.GetXrayConfigTemplate()
	if err != nil {
		return nil, err
	}
	return service.IKEv2ExitsFromTemplate(template)
}