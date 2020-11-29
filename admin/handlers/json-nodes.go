package handlers

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jmpsec/osctrl/admin/sessions"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/users"
	"github.com/jmpsec/osctrl/utils"
)

// Define targets to be used
var (
	NodeTargets = map[string]bool{
		"all":      true,
		"active":   true,
		"inactive": true,
	}
)

// ReturnedNodes to return a JSON with nodes
type ReturnedNodes struct {
	Data []NodeJSON `json:"data"`
}

// NodeJSON to be used to populate JSON data for a node
type NodeJSON struct {
	Checkbox  string        `json:"checkbox"`
	UUID      string        `json:"uuid"`
	Username  string        `json:"username"`
	Localname string        `json:"localname"`
	IP        string        `json:"ip"`
	Platform  string        `json:"platform"`
	Version   string        `json:"version"`
	Osquery   string        `json:"osquery"`
	LastSeen  CreationTimes `json:"lastseen"`
}

// JSONEnvironmentHandler - Handler for JSON endpoints by environment
func (h *HandlersAdmin) JSONEnvironmentHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricJSONReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin), false)
	vars := mux.Vars(r)
	// Extract environment
	env, ok := vars["environment"]
	if !ok {
		log.Println("error getting environment")
		h.Inc(metricJSONErr)
		return
	}
	// Check if environment is valid
	if !h.Envs.Exists(env) {
		log.Printf("error unknown environment (%s)", env)
		h.Inc(metricJSONErr)
		return
	}
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey("session")).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.EnvLevel, env) {
		log.Printf("%s has insuficient permissions", ctx[sessions.CtxUser])
		h.Inc(metricJSONErr)
		return
	}
	// Extract target
	target, ok := vars["target"]
	if !ok {
		log.Println("error getting target")
		h.Inc(metricJSONErr)
		return
	}
	// Verify target
	if !NodeTargets[target] {
		log.Printf("invalid target %s", target)
		h.Inc(metricJSONErr)
		return
	}
	nodes, err := h.Nodes.GetByEnv(env, target, h.Settings.InactiveHours())
	if err != nil {
		log.Printf("error getting nodes %v", err)
		h.Inc(metricJSONErr)
		return
	}
	// Prepare data to be returned
	nJSON := []NodeJSON{}
	for _, n := range nodes {
		nj := NodeJSON{
			UUID:      n.UUID,
			Username:  n.Username,
			Localname: n.Localname,
			IP:        n.IPAddress,
			Platform:  n.Platform,
			Version:   n.PlatformVersion,
			Osquery:   n.OsqueryVersion,
			LastSeen: CreationTimes{
				Display:   utils.PastFutureTimes(n.UpdatedAt),
				Timestamp: utils.TimeTimestamp(n.UpdatedAt),
			},
		}
		nJSON = append(nJSON, nj)
	}
	returned := ReturnedNodes{
		Data: nJSON,
	}
	// Serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, returned)
	h.Inc(metricJSONOK)
}

// JSONPlatformHandler - Handler for JSON endpoints by platform
func (h *HandlersAdmin) JSONPlatformHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricJSONReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin), false)
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey("session")).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, users.NoEnvironment) {
		log.Printf("%s has insuficient permissions", ctx[sessions.CtxUser])
		h.Inc(metricJSONErr)
		return
	}
	vars := mux.Vars(r)
	// Extract platform
	platform, ok := vars["platform"]
	if !ok {
		log.Println("error getting platform")
		h.Inc(metricJSONErr)
		return
	}
	// Extract target
	target, ok := vars["target"]
	if !ok {
		log.Println("error getting target")
		h.Inc(metricJSONErr)
		return
	}
	// Verify target
	if !NodeTargets[target] {
		log.Printf("invalid target %s", target)
		h.Inc(metricJSONErr)
		return
	}
	nodes, err := h.Nodes.GetByPlatform(platform, target, h.Settings.InactiveHours())
	if err != nil {
		log.Printf("error getting nodes %v", err)
		h.Inc(metricJSONErr)
		return
	}
	// Prepare data to be returned
	var nJSON []NodeJSON
	for _, n := range nodes {
		nj := NodeJSON{
			UUID:      n.UUID,
			Username:  n.Username,
			Localname: n.Localname,
			IP:        n.IPAddress,
			Platform:  n.Platform,
			Version:   n.PlatformVersion,
			Osquery:   n.OsqueryVersion,
			LastSeen: CreationTimes{
				Display:   utils.PastFutureTimes(n.UpdatedAt),
				Timestamp: utils.TimeTimestamp(n.UpdatedAt),
			},
		}
		nJSON = append(nJSON, nj)
	}
	returned := ReturnedNodes{
		Data: nJSON,
	}
	// Serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, returned)
	h.Inc(metricJSONOK)
}
