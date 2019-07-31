package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/utils"
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
}

// Handler for JSON queries by target
func jsonQueryHandler(w http.ResponseWriter, r *http.Request) {
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	vars := mux.Vars(r)
	// Extract target
	target, ok := vars["target"]
	if !ok {
		log.Println("error getting target")
		return
	}
	// Verify target
	if !QueryTargets[target] {
		log.Printf("invalid target %s", target)
		return
	}
	// Retrieve queries for that target
	qs, err := queriesmgr.GetQueries(target)
	if err != nil {
		log.Printf("error getting queries %v", err)
		return
	}
	// Prepare data to be returned
	qJSON := []QueryJSON{}
	for _, q := range qs {
		status := queries.StatusActive
		if q.Completed {
			status = queries.StatusComplete
		}
		progress := make(QueryProgress)
		progress["executions"] = q.Executions
		progress["errors"] = q.Errors
		data := make(QueryData)
		data["query"] = q.Query
		data["name"] = q.Name
		_q := QueryJSON{
			Name:    q.Name,
			Creator: q.Creator,
			Query:   data,
			Created: CreationTimes{
				Display:   pastTimeAgo(q.CreatedAt),
				Timestamp: pastTimestamp(q.CreatedAt),
			},
			Status:   status,
			Progress: progress,
		}
		qJSON = append(qJSON, _q)
	}
	returned := ReturnedQueries{
		Data: qJSON,
	}
	// Serialize JSON
	returnedJSON, err := json.Marshal(returned)
	if err != nil {
		log.Printf("error serializing JSON %v", err)
		return
	}
	// Header to serve JSON
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(returnedJSON)
}
