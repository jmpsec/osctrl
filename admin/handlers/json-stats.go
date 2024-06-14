package handlers

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jmpsec/osctrl/admin/sessions"
	"github.com/jmpsec/osctrl/nodes"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/users"
	"github.com/jmpsec/osctrl/utils"
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
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironmentID), false)
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	vars := mux.Vars(r)
	// Extract stats target
	target, ok := vars["target"]
	if !ok {
		h.Inc(metricAdminErr)
		log.Println("error getting target")
		return
	}
	// Verify target
	if !StatsTargets[target] {
		h.Inc(metricAdminErr)
		log.Printf("invalid target %s", target)
		return
	}
	// Extract identifier
	identifier, ok := vars["identifier"]
	if !ok {
		h.Inc(metricAdminErr)
		log.Println("error getting target identifier")
		return
	}
	// Get stats
	var stats nodes.StatsData
	var err error
	if target == "environment" {
		// Verify identifier
		env, err := h.Envs.Get(identifier)
		if err != nil {
			log.Printf("error getting environment %s - %v", identifier, err)
			h.Inc(metricJSONErr)
			return
		}
		// Check permissions
		if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.UserLevel, env.UUID) {
			log.Printf("%s has insuficient permissions", ctx[sessions.CtxUser])
			h.Inc(metricJSONErr)
			return
		}
		stats, err = h.Nodes.GetStatsByEnv(env.Name, h.Settings.InactiveHours(settings.NoEnvironmentID))
		if err != nil {
			h.Inc(metricAdminErr)
			log.Printf("error getting stats %v", err)
			return
		}
	} else if target == "platform" {
		// Check permissions
		if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, users.NoEnvironment) {
			log.Printf("%s has insuficient permissions", ctx[sessions.CtxUser])
			h.Inc(metricJSONErr)
			return
		}
		stats, err = h.Nodes.GetStatsByPlatform(identifier, h.Settings.InactiveHours(settings.NoEnvironmentID))
		if err != nil {
			log.Printf("error getting platform stats for %s - %v", identifier, err)
			return
		}
	}
	// Serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, stats)
	h.Inc(metricJSONOK)
}
