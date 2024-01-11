package handlers

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jmpsec/osctrl/admin/sessions"
	"github.com/jmpsec/osctrl/carves"
	"github.com/jmpsec/osctrl/queries"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/users"
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

// JSONCarvesHandler for JSON carves by target
func (h *HandlersAdmin) JSONCarvesHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricJSONReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironment), false)
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.CarveLevel, users.NoEnvironment) {
		log.Printf("%s has insuficient permissions", ctx[sessions.CtxUser])
		h.Inc(metricJSONErr)
		return
	}
	vars := mux.Vars(r)
	// Extract environment
	envVar, ok := vars["env"]
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
	// Extract target
	target, ok := vars["target"]
	if !ok {
		h.Inc(metricJSONErr)
		log.Println("error getting target")
		return
	}
	// Verify target
	if !CarvesTargets[target] {
		h.Inc(metricJSONErr)
		log.Printf("invalid target %s", target)
		return
	}
	// Retrieve carves for that target
	qs, err := h.Queries.GetCarves(target, env.ID)
	if err != nil {
		h.Inc(metricJSONErr)
		log.Printf("error getting query carves %v", err)
		return
	}
	// Prepare data to be returned
	cJSON := []CarveJSON{}
	for _, q := range qs {
		c, err := h.Carves.GetByQuery(q.Name, env.ID)
		if err != nil {
			log.Printf("error getting carves %v", err)
			h.Inc(metricJSONErr)
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
		ts, _ := h.Queries.GetTargets(q.Name)
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
	h.Inc(metricJSONOK)
}
