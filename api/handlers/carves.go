package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/jmpsec/osctrl/carves"
	"github.com/jmpsec/osctrl/queries"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/types"
	"github.com/jmpsec/osctrl/users"
	"github.com/jmpsec/osctrl/utils"
)

// GET Handler to return a single carve in JSON
func (h *HandlersApi) CarveShowHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAPICarvesReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), false)
	// Extract name
	name := r.PathValue("name")
	if name == "" {
		apiErrorResponse(w, "error getting name", http.StatusInternalServerError, nil)
		h.Inc(metricAPICarvesErr)
		return
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		h.Inc(metricAPICarvesErr)
		return
	}
	// Get environment
	env, err := h.Envs.GetByUUID(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		h.Inc(metricAPICarvesErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.CarveLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		h.Inc(metricAPICarvesErr)
		return
	}
	// Get carve by name
	carve, err := h.Carves.GetByQuery(name, env.ID)
	if err != nil {
		if err.Error() == "record not found" {
			apiErrorResponse(w, "carve not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting carve", http.StatusInternalServerError, err)
		}
		h.Inc(metricAPICarvesErr)
		return
	}
	// Serialize and serve JSON
	if h.Settings.DebugService(settings.ServiceAPI) {
		log.Printf("DebugService: Returned carve %s", name)
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, carve)
	h.Inc(metricAPICarvesOK)
}

// POST Handler to run a carve
func (h *HandlersApi) CarvesRunHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAPICarvesReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), false)
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		h.Inc(metricAPICarvesErr)
		return
	}
	// Get environment
	env, err := h.Envs.GetByUUID(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		h.Inc(metricAPICarvesErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.CarveLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		h.Inc(metricAPICarvesErr)
		return
	}
	var c types.ApiDistributedCarveRequest
	// Parse request JSON body
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		h.Inc(metricAPICarvesErr)
		return
	}
	// Path can not be empty
	if c.Path == "" {
		apiErrorResponse(w, "path can not be empty", http.StatusInternalServerError, nil)
		h.Inc(metricAPICarvesErr)
		return
	}
	query := carves.GenCarveQuery(c.Path, false)
	// Prepare and create new carve
	carveName := carves.GenCarveName()
	newQuery := queries.DistributedQuery{
		Query:         query,
		Name:          carveName,
		Creator:       ctx[ctxUser],
		Expected:      0,
		Executions:    0,
		Active:        true,
		Completed:     false,
		Deleted:       false,
		Type:          queries.CarveQueryType,
		Path:          c.Path,
		EnvironmentID: env.ID,
	}
	if err := h.Queries.Create(newQuery); err != nil {
		apiErrorResponse(w, "error creating query", http.StatusInternalServerError, err)
		h.Inc(metricAPICarvesErr)
		return
	}
	// Create UUID target
	if (c.UUID != "") && h.Nodes.CheckByUUID(c.UUID) {
		if err := h.Queries.CreateTarget(carveName, queries.QueryTargetUUID, c.UUID); err != nil {
			apiErrorResponse(w, "error creating carve UUID target", http.StatusInternalServerError, err)
			h.Inc(metricAPICarvesErr)
			return
		}
	}
	// Update value for expected
	if err := h.Queries.SetExpected(carveName, 1, env.ID); err != nil {
		apiErrorResponse(w, "error setting expected", http.StatusInternalServerError, err)
		h.Inc(metricAPICarvesErr)
		return
	}
	// Return query name as serialized response
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiQueriesResponse{Name: newQuery.Name})
	h.Inc(metricAPICarvesOK)
}

// GET Handler to return carves in JSON
func (h *HandlersApi) apiCarvesShowHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAPICarvesReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), false)
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		h.Inc(metricAPICarvesErr)
		return
	}
	// Get environment
	env, err := h.Envs.GetByUUID(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		h.Inc(metricAPICarvesErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.CarveLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		h.Inc(metricAPICarvesErr)
		return
	}
	// Get carves
	carves, err := h.Carves.GetByEnv(env.ID)
	if err != nil {
		apiErrorResponse(w, "error getting carves", http.StatusInternalServerError, err)
		h.Inc(metricAPICarvesErr)
		return
	}
	if len(carves) == 0 {
		apiErrorResponse(w, "no carves", http.StatusNotFound, nil)
		h.Inc(metricAPICarvesErr)
		return
	}
	// Serialize and serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, carves)
	h.Inc(metricAPICarvesOK)
}
