package handlers

import (
	"errors"
	"net/http"
	"time"

	"github.com/jmpsec/osctrl/pkg/nodeconfig"
	"github.com/jmpsec/osctrl/pkg/osqueryversions"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

const maxBodyStatus = 4 << 10 // 4 KiB: osctrld health and rollback report

// StatusHandler stores the osqueryd health and rollback report of a node of
// the environment. Anything that is not such a node gets 400, never 404:
// osctrld reads 404 as "route not served". Each new rollback event is
// counted and audited once.
func (h *HandlersTLS) StatusHandler(w http.ResponseWriter, r *http.Request) {
	var t types.OsctrldStatusRequest
	env, ok := h.osctrldRequest(w, r, maxBodyStatus, &t, func() string { return t.Secret })
	if !ok {
		return
	}
	// The UUID is untrusted: only a node of this environment is recorded,
	// keyed by the stored (upper-case) UUID.
	if !utils.CheckUUID(t.UUID) {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	node, err := h.Nodes.GetByUUIDEnv(t.UUID, env.ID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
			return
		}
		log.Err(err).Msgf("%s environment: error looking up node for osctrld report", env.Name)
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	// Events recorded before a failure are still counted and audited: a
	// retry sees their ids as stored and would never report them.
	events, err := h.FlagsOverrides.RecordReport(node.UUID, env.ID, t, time.Now())
	ip := utils.GetIP(r)
	for _, kind := range events {
		if kind == "upgrade" {
			// Recorded only for a validated upgrade, so these are not raw strings.
			osctrldUpgradeRollbacks.WithLabelValues(env.Name).Inc()
			h.AuditLog.RolledBackOsquery(ip, env.Name, node.UUID, t.Upgrade.Version, t.Upgrade.Reason, env.ID)
			continue
		}
		stage := t.Flags.Stage
		if kind == "extensions" {
			stage = t.Extensions.Stage
		}
		osctrldRollbacks.WithLabelValues(env.Name, kind, stage).Inc()
		h.AuditLog.RolledBackOsctrld(ip, env.Name, node.UUID, kind, stage, env.ID)
	}
	if err != nil {
		log.Err(err).Msgf("node UUID: %s in %s environment: error recording osctrld report", node.UUID, env.Name)
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	// A rollback under the current rollout's request id pauses it, whether or
	// not this report's event was new: a failed pause is repaired by the next
	// report. The compare-and-set makes a pin's or an old target's id a no-op.
	if u := t.Upgrade; h.OsqueryVersions != nil && u != nil && u.Result == "rejected" && u.RequestID != "" && nodeconfig.ValidUpgrade(*u) {
		host := osqueryversions.HostName(node.Hostname, node.Localname, node.UUID)
		// Server time of the first report of this rollback; a host clock is not trusted.
		var paused bool
		st, err := h.FlagsOverrides.Status(node.UUID)
		if err == nil && st != nil && st.UpgradeEventID == u.EventID && st.UpgradeEventAt != nil {
			paused, err = h.OsqueryVersions.PauseRollout(env.ID, u.RequestID, host, u.Reason, *st.UpgradeEventAt, time.Now())
		}
		if err != nil {
			log.Err(err).Msgf("node UUID: %s in %s environment: error pausing osquery rollout", node.UUID, env.Name)
			utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
			return
		}
		if paused {
			h.AuditLog.RolloutPaused(ip, env.Name, host, u.Version, u.Reason, env.ID)
		}
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, struct{}{})
}
