package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/utils"
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
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	vars := mux.Vars(r)
	// Extract target
	target, ok := vars["target"]
	if !ok {
		incMetric(metricAdminErr)
		log.Println("error getting target")
		return
	}
	// Verify target
	if !CarvesTargets[target] {
		incMetric(metricAdminErr)
		log.Printf("invalid target %s", target)
		return
	}
	// Retrieve carves for that target
	qs, err := queriesmgr.GetCarves(target)
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting query carves %v", err)
		return
	}
	// Prepare data to be returned
	cJSON := []CarveJSON{}
	for _, q := range qs {
		c, err := carvesmgr.GetByQuery(q.Name)
		if err != nil {
			log.Printf("error getting carves %v", err)
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
		progress["total"] = q.Expected
		progress["completed"] = q.Executions
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
				Display:   pastTimeAgo(q.CreatedAt),
				Timestamp: pastTimestamp(q.CreatedAt),
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
	// Serialize JSON
	returnedJSON, err := json.Marshal(returned)
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error serializing JSON %v", err)
		return
	}
	incMetric(metricAdminOK)
	// Header to serve JSON
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(returnedJSON)
}
