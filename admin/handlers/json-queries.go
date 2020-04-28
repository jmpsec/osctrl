package handlers

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jmpsec/osctrl/admin/sessions"
	"github.com/jmpsec/osctrl/queries"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/users"
	"github.com/jmpsec/osctrl/utils"
)

// Define targets to be used
var (
	QueryTargets = map[string]bool{
		"all":       true,
		"active":    true,
		"completed": true,
	}
)

// ReturnedQueries to return a JSON with queries
type ReturnedQueries struct {
	Data []QueryJSON `json:"data"`
}

// QueryProgress to be used to show progress for a query
type QueryProgress map[string]int

// QueryData to be used to hold query data
type QueryData map[string]string

// QueryJSON to be used to populate JSON data for a query
type QueryJSON struct {
	Checkbox string        `json:"checkbox"`
	Name     string        `json:"name"`
	Creator  string        `json:"creator"`
	Query    QueryData     `json:"query"`
	Created  CreationTimes `json:"created"`
	Status   string        `json:"status"`
	Progress QueryProgress `json:"progress"`
	Targets  []QueryTarget `json:"targets"`
}

// QueryTarget to be returned with the JSON data for a query
type QueryTarget struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Handler for JSON queries by target
func (h *HandlersAdmin) JSONQueryHandler(w http.ResponseWriter, r *http.Request) {
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
	// Extract target
	target, ok := vars["target"]
	if !ok {
		log.Println("error getting target")
		h.Inc(metricJSONErr)
		return
	}
	// Verify target
	if !QueryTargets[target] {
		log.Printf("invalid target %s", target)
		h.Inc(metricJSONErr)
		return
	}
	// Retrieve queries for that target
	qs, err := h.Queries.GetQueries(target)
	if err != nil {
		log.Printf("error getting queries %v", err)
		h.Inc(metricJSONErr)
		return
	}
	// Prepare data to be returned
	qJSON := []QueryJSON{}
	for _, q := range qs {
		status := queries.StatusActive
		if q.Completed {
			status = queries.StatusComplete
		}
		// Prepare progress data
		progress := make(QueryProgress)
		progress["expected"] = q.Expected
		progress["executions"] = q.Executions
		progress["errors"] = q.Errors
		data := make(QueryData)
		data["query"] = q.Query
		data["name"] = q.Name
		data["link"] = h.queryResultLink(q.Name)
		// Preparing query targets
		ts, _ := h.Queries.GetTargets(q.Name)
		_ts := []QueryTarget{}
		for _, t := range ts {
			_t := QueryTarget{
				Type:  t.Type,
				Value: t.Value,
			}
			_ts = append(_ts, _t)
		}
		// Preparing JSON
		_q := QueryJSON{
			Name:    q.Name,
			Creator: q.Creator,
			Query:   data,
			Created: CreationTimes{
				Display:   utils.PastFutureTimes(q.CreatedAt),
				Timestamp: utils.TimeTimestamp(q.CreatedAt),
			},
			Status:   status,
			Progress: progress,
			Targets:  _ts,
		}
		qJSON = append(qJSON, _q)
	}
	returned := ReturnedQueries{
		Data: qJSON,
	}
	// Serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, returned)
	h.Inc(metricJSONOK)
}
