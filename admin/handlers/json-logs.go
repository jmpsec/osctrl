package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/jmpsec/osctrl/admin/sessions"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/types"
	"github.com/jmpsec/osctrl/users"
	"github.com/jmpsec/osctrl/utils"
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
	h.Inc(metricJSONReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin), false)
	vars := mux.Vars(r)
	// Extract type
	logType, ok := vars["type"]
	if !ok {
		log.Println("error getting log type")
		h.Inc(metricJSONErr)
		return
	}
	// Verify log type
	if !LogTypes[logType] {
		log.Printf("invalid log type %s", logType)
		h.Inc(metricJSONErr)
		return
	}
	// Extract environment
	envVar, ok := vars["environment"]
	if !ok {
		log.Println("environment is missing")
		h.Inc(metricJSONErr)
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		log.Printf("error getting environment %s - %v", envVar, err)
		h.Inc(metricJSONErr)
		return
	}
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey("session")).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.UserLevel, env.UUID) {
		log.Printf("%s has insuficient permissions", ctx[sessions.CtxUser])
		h.Inc(metricJSONErr)
		return
	}
	// Extract UUID
	// FIXME verify UUID
	UUID, ok := vars["uuid"]
	if !ok {
		log.Println("error getting UUID")
		h.Inc(metricJSONErr)
		return
	}
	// Extract parameter for seconds
	// If parameter is not present or invalid, it defaults to 6 hours back
	secondsBack := int64(utils.SixHours)
	seconds, ok := r.URL.Query()["seconds"]
	if ok {
		s, err := strconv.ParseInt(seconds[0], 10, 64)
		if err == nil {
			secondsBack = s
		}
	}
	// Get logs
	logJSON := []LogJSON{}
	if logType == types.StatusLog && h.RedisCache != nil {
		statusLogs, err := h.RedisCache.StatusLogs(UUID, env.Name, secondsBack)
		if err != nil {
			log.Printf("error getting logs %v", err)
			h.Inc(metricJSONErr)
			return
		}
		// Prepare data to be returned
		for _, s := range statusLogs {
			_c := CreationTimes{
				Display:   utils.PastFutureTimesEpoch(int64(s.UnixTime)),
				Timestamp: strconv.Itoa(int(s.UnixTime)),
			}
			_l := LogJSON{
				Created: _c,
				First:   s.Message,
				Second:  s.Severity,
			}
			logJSON = append(logJSON, _l)
		}
	} else if logType == types.ResultLog && h.RedisCache != nil {
		resultLogs, err := h.RedisCache.ResultLogs(UUID, env.Name, secondsBack)
		if err != nil {
			log.Printf("error getting logs %v", err)
			h.Inc(metricJSONErr)
			return
		}
		// Prepare data to be returned
		for _, r := range resultLogs {
			_l := LogJSON{
				Created: CreationTimes{
					Display:   utils.PastFutureTimesEpoch(int64(r.UnixTime)),
					Timestamp: strconv.Itoa(int(r.UnixTime)),
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
	h.Inc(metricJSONOK)
}

// JSONQueryLogsHandler for JSON query logs by query name
func (h *HandlersAdmin) JSONQueryLogsHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricJSONReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin), false)
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey("session")).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.QueryLevel, users.NoEnvironment) {
		log.Printf("%s has insuficient permissions", ctx[sessions.CtxUser])
		h.Inc(metricJSONErr)
		return
	}
	vars := mux.Vars(r)
	// Extract query name
	// FIXME verify name
	name, ok := vars["name"]
	if !ok {
		log.Println("error getting name")
		h.Inc(metricJSONErr)
		return
	}
	// Iterate through targets to get logs
	queryLogJSON := []QueryLogJSON{}
	// Get logs
	if h.RedisCache != nil {
		queryLogs, err := h.RedisCache.QueryLogs(name)
		if err != nil {
			log.Printf("error getting logs %v", err)
			h.Inc(metricJSONErr)
			return
		}
		// Prepare data to be returned
		for _, q := range queryLogs {
			// Get target node
			node, err := h.Nodes.GetByUUID(q.HostIdentifier)
			if err != nil {
				node.UUID = q.HostIdentifier
				node.Localname = ""
			}
			_c := CreationTimes{
				Display:   utils.PastFutureTimesEpoch(int64(q.UnixTime)),
				Timestamp: utils.PastFutureTimesEpoch(int64(q.UnixTime)),
			}
			qData, err := json.Marshal(q.QueryData)
			if err != nil {
				log.Printf("error serializing logs %v", err)
				h.Inc(metricJSONErr)
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
	h.Inc(metricJSONOK)
}
