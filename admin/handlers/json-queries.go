package handlers

import (
	"net/http"

	"github.com/jmpsec/osctrl/admin/sessions"
	"github.com/jmpsec/osctrl/queries"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/users"
	"github.com/jmpsec/osctrl/utils"
	"github.com/rs/zerolog/log"
)

const ()

// Define targets to be used
var (
	QueryTargets = map[string]bool{
		queries.TargetAll:       true,
		queries.TargetActive:    true,
		queries.TargetCompleted: true,
		queries.TargetSaved:     true,
	}
)

// ReturnedQueries to return a JSON with distributed queries
type ReturnedQueries struct {
	Data []QueryJSON `json:"data"`
}

// ReturnedSaved to return a JSON with saved queries
type ReturnedSaved struct {
	Data []SavedJSON `json:"data"`
}

// QueryProgress to be used to show progress for a query
type QueryProgress map[string]int

// QueryData to be used to hold query data
type QueryData map[string]string

// QueryJSON to be used to populate JSON data for a distributed query
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

// SavedJSON to be used to populate JSON data for a saved query
type SavedJSON struct {
	Checkbox string        `json:"checkbox"`
	Name     string        `json:"name"`
	Creator  string        `json:"creator"`
	Query    string        `json:"query"`
	Created  CreationTimes `json:"created"`
}

// QueryTarget to be returned with the JSON data for a query
type QueryTarget struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// JSONQueryJSON - Helper to convert saved distributed queries to serialized JSON
func (h *HandlersAdmin) JSONQueryJSON(q queries.DistributedQuery, env string) QueryJSON {
	// Prepare progress data
	progress := make(QueryProgress)
	progress["expected"] = q.Expected
	progress["executions"] = q.Executions
	progress["errors"] = q.Errors
	// Prepare query data
	data := make(QueryData)
	data["query"] = q.Query
	data["name"] = q.Name
	data["link"] = h.queryResultLink(q.Name, env)
	// Prepare status
	status := queries.StatusActive
	if q.Completed {
		status = queries.StatusComplete
	}
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
	return QueryJSON{
		Creator: q.Creator,
		Name:    q.Name,
		Query:   data,
		Created: CreationTimes{
			Display:   utils.PastFutureTimes(q.CreatedAt),
			Timestamp: utils.TimeTimestamp(q.CreatedAt),
		},
		Status:   status,
		Progress: progress,
		Targets:  _ts,
	}
}

// JSONSavedJSON - Helper to convert saved queries to serialized JSON
func (h *HandlersAdmin) JSONSavedJSON(q queries.SavedQuery) SavedJSON {
	return SavedJSON{
		Creator: q.Creator,
		Name:    q.Name,
		Query:   q.Query,
		Created: CreationTimes{
			Display:   utils.PastFutureTimes(q.CreatedAt),
			Timestamp: utils.TimeTimestamp(q.CreatedAt),
		},
	}
}

// JSONQueryHandler - Handler for JSON queries by target
func (h *HandlersAdmin) JSONQueryHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricJSONReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironmentID), false)
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.QueryLevel, users.NoEnvironment) {
		log.Info().Msgf("%s has insuficient permissions", ctx[sessions.CtxUser])
		h.Inc(metricJSONErr)
		return
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		log.Info().Msg("environment is missing")
		h.Inc(metricJSONErr)
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		log.Err(err).Msgf("error getting environment %s", envVar)
		h.Inc(metricJSONErr)
		return
	}
	// Extract target
	target := r.PathValue("target")
	if target == "" {
		log.Info().Msg("error getting target")
		h.Inc(metricJSONErr)
		return
	}
	// Verify target
	if !QueryTargets[target] {
		log.Info().Msgf("invalid target %s", target)
		h.Inc(metricJSONErr)
		return
	}
	// If the target is saved queries, get them
	if target == queries.TargetSaved {
		qs, err := h.Queries.GetSavedByCreator(ctx[sessions.CtxUser], env.ID)
		if err != nil {
			log.Err(err).Msg("error getting queries")
			h.Inc(metricJSONErr)
			return
		}
		// Prepare data to be returned
		qJSON := []SavedJSON{}
		for _, q := range qs {
			_q := h.JSONSavedJSON(q)
			qJSON = append(qJSON, _q)
		}
		returned := ReturnedSaved{
			Data: qJSON,
		}
		// Serve JSON
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, returned)
		h.Inc(metricJSONOK)
		return
	}
	// If we are here, retrieve distributed queries for that target
	qs, err := h.Queries.GetQueries(target, env.ID)
	if err != nil {
		log.Err(err).Msg("error getting queries")
		h.Inc(metricJSONErr)
		return
	}
	// Prepare data to be returned
	qJSON := []QueryJSON{}
	for _, q := range qs {
		_q := h.JSONQueryJSON(q, env.UUID)
		qJSON = append(qJSON, _q)
	}
	returned := ReturnedQueries{
		Data: qJSON,
	}
	// Serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, returned)
	h.Inc(metricJSONOK)
}
