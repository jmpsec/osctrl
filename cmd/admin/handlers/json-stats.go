package handlers

import (
	"net/http"

	"github.com/jmpsec/osctrl/cmd/admin/sessions"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

// Define targets to be used
var (
	StatsTargets = map[string]bool{
		"environment": true,
		"platform":    true,
	}
)

// JSONStatsHandler for platform/environment stats in JSON
func (h *HandlersAdmin) JSONStatsHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Extract stats target
	target := r.PathValue("target")
	if target == "" {
		log.Info().Msg("error getting target")
		return
	}
	// Verify target
	if !StatsTargets[target] {
		log.Info().Msgf("invalid target %s", target)
		return
	}
	// Extract identifier
	identifier := r.PathValue("identifier")
	if identifier == "" {
		log.Info().Msg("error getting target identifier")
		return
	}
	// Get stats
	var stats nodes.StatsData
	if target == "environment" {
		// Verify identifier
		env, err := h.Envs.Get(identifier)
		if err != nil {
			log.Err(err).Msgf("error getting environment %s", identifier)
			return
		}
		// Check permissions
		if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.UserLevel, env.UUID) {
			log.Info().Msgf("%s has insufficient permissions", ctx[sessions.CtxUser])
			return
		}
		stats, err = h.Nodes.GetStatsByEnv(env.Name, h.Settings.InactiveHours(settings.NoEnvironmentID))
		if err != nil {
			log.Err(err).Msg("error getting stats")
			return
		}
	}
	// Serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, stats)
}
