package handlers

import (
	"net/http"

	"github.com/jmpsec/osctrl/cmd/admin/sessions"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
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
	FirstSeen CreationTimes `json:"firstseen"`
}

// JSONEnvironmentHandler - Handler for JSON endpoints by environment
func (h *HandlersAdmin) JSONEnvironmentHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		log.Info().Msg("error getting environment")
		return
	}
	// Check if environment is valid
	if !h.Envs.Exists(envVar) {
		log.Info().Msgf("error unknown environment (%s)", envVar)
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		log.Err(err).Msgf("error getting environment %s", envVar)
		return
	}
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.UserLevel, env.UUID) {
		log.Info().Msgf("%s has insuficient permissions", ctx[sessions.CtxUser])
		return
	}
	// Extract target
	target := r.PathValue("target")
	if target == "" {
		log.Info().Msg("error getting target")
		return
	}
	// Verify target
	if !NodeTargets[target] {
		log.Info().Msgf("invalid target %s", target)
		return
	}
	nodes, err := h.Nodes.GetByEnv(env.Name, target, h.Settings.InactiveHours(settings.NoEnvironmentID))
	if err != nil {
		log.Err(err).Msg("error getting nodes")
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
			FirstSeen: CreationTimes{
				Display:   utils.PastFutureTimes(n.CreatedAt),
				Timestamp: utils.TimeTimestamp(n.CreatedAt),
			},
		}
		nJSON = append(nJSON, nj)
	}
	returned := ReturnedNodes{
		Data: nJSON,
	}
	// Serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, returned)
}

// JSONPlatformHandler - Handler for JSON endpoints by platform
func (h *HandlersAdmin) JSONPlatformHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, users.NoEnvironment) {
		log.Info().Msgf("%s has insuficient permissions", ctx[sessions.CtxUser])
		return
	}
	// Extract platform
	platform := r.PathValue("platform")
	if platform == "" {
		log.Info().Msg("error getting platform")
		return
	}
	// Extract target
	target := r.PathValue("target")
	if target == "" {
		log.Info().Msg("error getting target")
		return
	}
	// Verify target
	if !NodeTargets[target] {
		log.Info().Msgf("invalid target %s", target)
		return
	}
	nodes, err := h.Nodes.GetByPlatform(platform, target, h.Settings.InactiveHours(settings.NoEnvironmentID))
	if err != nil {
		log.Err(err).Msg("error getting nodes")
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
			FirstSeen: CreationTimes{
				Display:   utils.PastFutureTimes(n.CreatedAt),
				Timestamp: utils.TimeTimestamp(n.CreatedAt),
			},
		}
		nJSON = append(nJSON, nj)
	}
	returned := ReturnedNodes{
		Data: nJSON,
	}
	// Serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, returned)
}
