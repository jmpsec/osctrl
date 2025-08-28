package handlers

import (
	"net/http"

	"github.com/jmpsec/osctrl/cmd/admin/sessions"
	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
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
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
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
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.CarveLevel, env.UUID) {
		log.Info().Msgf("%s has insuficient permissions", ctx[sessions.CtxUser])
		return
	}
	// Extract target
	target := r.PathValue("target")
	if target == "" {
		log.Info().Msg("target is missing")
		return
	}
	// Verify target
	if !CarvesTargets[target] {
		log.Info().Msgf("invalid target %s", target)
		return
	}
	// Retrieve carves for that target
	qs, err := h.Queries.GetCarves(target, env.ID)
	if err != nil {
		log.Err(err).Msg("error getting query carves")
		return
	}
	// Prepare data to be returned
	cJSON := []CarveJSON{}
	for _, q := range qs {
		c, err := h.Carves.GetByQuery(q.Name, env.ID)
		if err != nil {
			log.Err(err).Msg("error getting carves")
			continue
		}
		status := queries.StatusActive
		if len(c) > 0 {
			status = carves.StatusQueried
		}
		if q.Completed {
			status = queries.StatusComplete
		}
		if q.Expired {
			status = queries.StatusExpired
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
}
