package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/jmpsec/osctrl/cmd/admin/sessions"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

// Define log types to be used
var (
	LogTypes = map[string]bool{
		types.ResultLog: true,
		types.StatusLog: true,
	}
)

// ReturnedLogs to return a JSON with status/result logs
type ReturnedLogs struct {
	Data []LogJSON `json:"data"`
}

// CreationTimes to hold creation times
type CreationTimes struct {
	Display   string `json:"display"`
	Timestamp string `json:"timestamp"`
}

// LogJSON to be used to populate JSON data for a status/result log
type LogJSON struct {
	Created CreationTimes `json:"created"`
	First   string        `json:"first"`
	Second  string        `json:"second"`
}

// ReturnedQueryLogs to return a JSON with query logs
type ReturnedQueryLogs struct {
	Data []QueryLogJSON `json:"data"`
}

// QueryTargetNode to return the target of a on-demand query
type QueryTargetNode struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

// QueryLogJSON to be used to populate JSON data for a query log
type QueryLogJSON struct {
	Created CreationTimes   `json:"created"`
	Target  QueryTargetNode `json:"target"`
	Data    string          `json:"data"`
}

// JSONLogsHandler GET requests for JSON status/result logs by node and environment
func (h *HandlersAdmin) JSONLogsHandler(w http.ResponseWriter, r *http.Request) {
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironmentID), false)
	// Extract type
	logType := r.PathValue("type")
	if logType == "" {
		log.Info().Msg("error getting log type")
		return
	}
	// Verify log type
	if !LogTypes[logType] {
		log.Info().Msgf("invalid log type %s", logType)
		return
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		log.Info().Msg("environment is missing")
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
	// Extract UUID
	// FIXME verify UUID
	UUID := r.PathValue("uuid")
	if UUID == "" {
		log.Info().Msg("error getting UUID")
		return
	}
	// Extract parameter for seconds
	// If parameter is not present or invalid, it defaults to 6 hours back
	// secondsBack := int64(utils.SixHours)
	// seconds, ok := r.URL.Query()["seconds"]
	// if ok {
	// 	s, err := strconv.ParseInt(seconds[0], 10, 64)
	// 	if err == nil {
	// 		secondsBack = s
	// 	}
	// }
	// Extract parameter for limit
	// If parameter is not present or invalid, it defaults to 100 items
	limitItems := int(100)
	limit, ok := r.URL.Query()["limit"]
	if ok {
		l, err := strconv.ParseInt(limit[0], 10, 32)
		if err == nil {
			limitItems = int(l)
		}
	}
	// Get logs
	logJSON := []LogJSON{}
	if logType == types.StatusLog && h.AdminConfig.Logger == settings.LoggingDB {
		statusLogs, err := h.DBLogger.StatusLogsLimit(UUID, env.Name, int(limitItems))
		if err != nil {
			log.Err(err).Msg("error getting logs")
			return
		}
		// Prepare data to be returned
		for _, s := range statusLogs {
			_c := CreationTimes{
				Display:   utils.PastFutureTimes(s.CreatedAt),
				Timestamp: strconv.Itoa(int(s.CreatedAt.Unix())),
			}
			_l := LogJSON{
				Created: _c,
				First:   s.Message,
				Second:  s.Severity,
			}
			logJSON = append(logJSON, _l)
		}
	} else if logType == types.ResultLog && h.AdminConfig.Logger == settings.LoggingDB {
		resultLogs, err := h.DBLogger.ResultLogsLimit(UUID, env.Name, int(limitItems))
		if err != nil {
			log.Err(err).Msg("error getting logs")
			return
		}
		// Prepare data to be returned
		for _, r := range resultLogs {
			_l := LogJSON{
				Created: CreationTimes{
					Display:   utils.PastFutureTimes(r.CreatedAt),
					Timestamp: strconv.Itoa(int(r.CreatedAt.Unix())),
				},
				First:  r.Name,
				Second: string(r.Columns),
			}
			logJSON = append(logJSON, _l)
		}
	}
	returned := ReturnedLogs{
		Data: logJSON,
	}
	// Serialize and serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, returned)
}

// JSONQueryLogsHandler for JSON query logs by query name
func (h *HandlersAdmin) JSONQueryLogsHandler(w http.ResponseWriter, r *http.Request) {
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironmentID), false)
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.QueryLevel, users.NoEnvironment) {
		log.Info().Msgf("%s has insuficient permissions", ctx[sessions.CtxUser])
		return
	}
	// Extract query name
	// FIXME verify name
	name := r.PathValue("name")
	if name == "" {
		log.Info().Msg("error getting name")
		return
	}
	// Iterate through targets to get logs
	queryLogJSON := []QueryLogJSON{}
	// Get logs
	if h.DBLogger != nil {
		queryLogs, err := h.DBLogger.QueryLogs(name)
		if err != nil {
			log.Err(err).Msg("error getting logs")
			return
		}
		// Prepare data to be returned
		for _, q := range queryLogs {
			// Get target node
			node, err := h.Nodes.GetByUUID(q.UUID)
			if err != nil {
				node.UUID = q.UUID
				node.Localname = ""
			}
			_c := CreationTimes{
				Display:   utils.PastFutureTimes(q.CreatedAt),
				Timestamp: strconv.Itoa(int(q.CreatedAt.Unix())),
			}
			qData, err := json.Marshal(q.Data)
			if err != nil {
				log.Err(err).Msg("error serializing logs")
				continue
			}
			_l := QueryLogJSON{
				Created: _c,
				Target: QueryTargetNode{
					UUID: node.UUID,
					Name: node.Localname,
				},
				Data: string(qData),
			}
			queryLogJSON = append(queryLogJSON, _l)
		}
	}
	returned := ReturnedQueryLogs{
		Data: queryLogJSON,
	}
	// Serialize and serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, returned)
}
