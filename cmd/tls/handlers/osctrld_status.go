package handlers

import (
	"errors"
	"net/http"
	"time"

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
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, struct{}{})
}
