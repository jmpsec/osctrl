package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jmpsec/osctrl/carves"
	"github.com/jmpsec/osctrl/queries"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/utils"
)

// Define targets to be used
var (
	CarvesTargets = map[string]bool{
		"all":       true,
		"active":    true,
		"completed": true,
	}
)

// ReturnedCarves to return a JSON with carves
type ReturnedCarves struct {
	Data []CarveJSON `json:"data"`
}

// CarveProgress to be used to show progress for a carve
type CarveProgress map[string]int

// CarveData to be used to hold query data
type CarveData map[string]string

// CarveJSON to be used to populate JSON data for a carve
type CarveJSON struct {
	Checkbox string        `json:"checkbox"`
	Name     string        `json:"name"`
	Creator  string        `json:"creator"`
	Path     CarveData     `json:"path"`
	Created  CreationTimes `json:"created"`
	Status   string        `json:"status"`
	Progress CarveProgress `json:"progress"`
	Targets  []CarveTarget `json:"targets"`
}

// CarveTarget to be returned with the JSON data for a carve
type CarveTarget struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Handler for JSON carves by target
func jsonCarvesHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricJSONReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Check permissions
	if !checkPermissions(ctx[ctxUser], false, true, false, "") {
		log.Printf("%s has insuficient permissions", ctx[ctxUser])
		incMetric(metricJSONErr)
		return
	}
	vars := mux.Vars(r)
	// Extract target
	target, ok := vars["target"]
	if !ok {
		incMetric(metricJSONErr)
		log.Println("error getting target")
		return
	}
	// Verify target
	if !CarvesTargets[target] {
		incMetric(metricJSONErr)
		log.Printf("invalid target %s", target)
		return
	}
	// Retrieve carves for that target
	qs, err := queriesmgr.GetCarves(target)
	if err != nil {
		incMetric(metricJSONErr)
		log.Printf("error getting query carves %v", err)
		return
	}
	// Prepare data to be returned
	cJSON := []CarveJSON{}
	for _, q := range qs {
		c, err := carvesmgr.GetByQuery(q.Name)
		if err != nil {
			log.Printf("error getting carves %v", err)
			incMetric(metricJSONErr)
			continue
		}
		status := queries.StatusActive
		if len(c) > 0 {
			status = carves.StatusQueried
		}
		if q.Completed {
			status = queries.StatusComplete
		}
		progress := make(CarveProgress)
		progress["expected"] = q.Expected
		progress["executions"] = q.Executions
		progress["errors"] = q.Errors
		data := make(CarveData)
		data["path"] = q.Path
		data["name"] = q.Name
		// Preparing query targets
		ts, _ := queriesmgr.GetTargets(q.Name)
		_ts := []CarveTarget{}
		for _, t := range ts {
			_t := CarveTarget{
				Type:  t.Type,
				Value: t.Value,
			}
			_ts = append(_ts, _t)
		}
		// Preparing JSON
		_c := CarveJSON{
			Name:    q.Name,
			Creator: q.Creator,
			Path:    data,
			Created: CreationTimes{
				Display:   utils.PastFutureTimes(q.CreatedAt),
				Timestamp: utils.TimeTimestamp(q.CreatedAt),
			},
			Status:   status,
			Progress: progress,
			Targets:  _ts,
		}
		cJSON = append(cJSON, _c)
	}
	returned := ReturnedCarves{
		Data: cJSON,
	}
	// Serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, returned)
	incMetric(metricJSONOK)
}
