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
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin), false)
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey("session")).(sessions.ContextValue)
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
	// Extract stats name
	// FIXME verify name
	name, ok := vars["name"]
	if !ok {
		h.Inc(metricAdminErr)
		log.Println("error getting target name")
		return
	}
	// Get stats
	var stats nodes.StatsData
	var err error
	if target == "environment" {
		// Check permissions
		if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.EnvLevel, name) {
			log.Printf("%s has insuficient permissions", ctx[sessions.CtxUser])
			h.Inc(metricJSONErr)
			return
		}
		stats, err = h.Nodes.GetStatsByEnv(name, h.Settings.InactiveHours())
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
		stats, err = h.Nodes.GetStatsByPlatform(name, h.Settings.InactiveHours())
		if err != nil {
			log.Printf("error getting stats %v", err)
			return
		}
	}
	// Serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, stats)
	h.Inc(metricJSONOK)
}
