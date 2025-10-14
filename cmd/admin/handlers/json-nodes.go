package handlers

import (
	"net/http"
	"strconv"

	"github.com/jmpsec/osctrl/cmd/admin/sessions"
	"github.com/jmpsec/osctrl/pkg/nodes"
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

// PaginatedNodes to return a JSON with nodes, paginated
type PaginatedNodes struct {
	Draw     int        `json:"draw"`
	Total    int        `json:"recordsTotal"`
	Filtered int        `json:"recordsFiltered"`
	Data     []NodeJSON `json:"data"`
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
		log.Info().Msgf("%s has insufficient permissions", ctx[sessions.CtxUser])
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
				Display:   utils.PastFutureTimes(n.LastSeen),
				Timestamp: utils.TimeTimestamp(n.LastSeen),
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

// JSONEnvironmentPagingHandler - Handler for JSON endpoints by environment, with pagination
func (h *HandlersAdmin) JSONEnvironmentPagingHandler(w http.ResponseWriter, r *http.Request) {
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
		log.Info().Msgf("%s has insufficient permissions", ctx[sessions.CtxUser])
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
	// Extract DataTables parameters
	draw, _ := strconv.Atoi(r.URL.Query().Get("draw"))
	start, _ := strconv.Atoi(r.URL.Query().Get("start"))
	length, _ := strconv.Atoi(r.URL.Query().Get("length"))
	searchValue := r.URL.Query().Get("search")

	// DB-level counts
	totalCount, err := h.Nodes.CountByEnvTarget(env.Name, target, h.Settings.InactiveHours(settings.NoEnvironmentID))
	if err != nil {
		log.Err(err).Msg("error counting total nodes")
		return
	}
	var filteredCount int64
	var nodesSlice []nodes.OsqueryNode
	hours := h.Settings.InactiveHours(settings.NoEnvironmentID)
	// Ordering (DataTables sends order[0][column], order[0][dir])
	orderColIdxStr := r.URL.Query().Get("order[0][column]")
	orderDir := r.URL.Query().Get("order[0][dir]")
	colName := mapDTColumnToDB(orderColIdxStr)
	desc := (orderDir == "desc")
	if searchValue != "" {
		// Count filtered first
		filteredCount, err = h.Nodes.CountSearchByEnv(env.Name, searchValue, target, hours)
		if err != nil {
			log.Err(err).Msg("error counting search nodes")
			return
		}
		nodesSlice, err = h.Nodes.SearchByEnvPage(env.Name, searchValue, target, hours, start, length, colName, desc)
		if err != nil {
			log.Err(err).Msg("error searching nodes page")
			return
		}
	} else {
		filteredCount = totalCount
		nodesSlice, err = h.Nodes.GetByEnvPage(env.Name, target, hours, start, length, colName, desc)
		if err != nil {
			log.Err(err).Msg("error getting nodes page")
			return
		}
	}
	// Prepare data to be returned
	nJSON := []NodeJSON{}
	for _, n := range nodesSlice {
		nj := NodeJSON{
			UUID:      n.UUID,
			Username:  n.Username,
			Localname: n.Localname,
			IP:        n.IPAddress,
			Platform:  n.Platform,
			Version:   n.PlatformVersion,
			Osquery:   n.OsqueryVersion,
			LastSeen: CreationTimes{
				Display:   utils.PastFutureTimes(n.LastSeen),
				Timestamp: utils.TimeTimestamp(n.LastSeen),
			},
			FirstSeen: CreationTimes{
				Display:   utils.PastFutureTimes(n.CreatedAt),
				Timestamp: utils.TimeTimestamp(n.CreatedAt),
			},
		}
		nJSON = append(nJSON, nj)
	}
	returned := PaginatedNodes{
		Draw:     draw,
		Total:    int(totalCount),
		Filtered: int(filteredCount),
		Data:     nJSON,
	}
	// Serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, returned)
}

// mapDTColumnToDB maps DataTables column index (as string) to actual DB column name.
// DataTables columns order in the UI:
// 0 checkbox,1 uuid,2 username(last user),3 localname,4 ip,5 platform,6 version(platform_version),7 osquery,8 lastseen,9 firstseen
// We only allow ordering on a safe subset of real DB columns.
func mapDTColumnToDB(idx string) string {
	switch idx {
	case "1":
		return "uuid"
	case "2":
		return "username"
	case "3":
		return "localname"
	case "4":
		return "ip_address"
	case "5":
		return "platform"
	case "6":
		return "platform_version"
	case "7":
		return "osquery_version"
	case "8":
		return "last_seen"
	case "9":
		return "created_at" // first seen
	default:
		return "" // fallback to default ordering in caller
	}
}
