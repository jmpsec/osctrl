package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
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
func jsonQueryHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricJSONReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Check permissions
	if !adminUsers.CheckPermissions(ctx[ctxUser], users.QueryLevel, users.NoEnvironment) {
		log.Printf("%s has insuficient permissions", ctx[ctxUser])
		incMetric(metricJSONErr)
		return
	}
	vars := mux.Vars(r)
	// Extract target
	target, ok := vars["target"]
	if !ok {
		log.Println("error getting target")
		incMetric(metricJSONErr)
		return
	}
	// Verify target
	if !QueryTargets[target] {
		log.Printf("invalid target %s", target)
		incMetric(metricJSONErr)
		return
	}
	// Retrieve queries for that target
	qs, err := queriesmgr.GetQueries(target)
	if err != nil {
		log.Printf("error getting queries %v", err)
		incMetric(metricJSONErr)
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
		data["deflink"], data["dblink"] = queryResultLink(q.Name)
		// Preparing query targets
		ts, _ := queriesmgr.GetTargets(q.Name)
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
	incMetric(metricJSONOK)
}
