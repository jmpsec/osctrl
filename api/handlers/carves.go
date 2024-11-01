package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/jmpsec/osctrl/carves"
	"github.com/jmpsec/osctrl/queries"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/types"
	"github.com/jmpsec/osctrl/users"
	"github.com/jmpsec/osctrl/utils"
	"github.com/rs/zerolog/log"
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
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
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
		log.Debug().Msgf("DebugService: Returned carve %s", name)
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, carve)
	h.Inc(metricAPICarvesOK)
}

// GET Handler to return carve queries in JSON by target and environment
func (h *HandlersApi) CarveQueriesHandler(w http.ResponseWriter, r *http.Request) {
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
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.CarveLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		h.Inc(metricAPICarvesErr)
		return
	}
	// Extract target
	targetVar := r.PathValue("target")
	if targetVar == "" {
		apiErrorResponse(w, "error with target", http.StatusBadRequest, nil)
		h.Inc(metricAPICarvesErr)
		return
	}
	// Verify target
	if !QueryTargets[targetVar] {
		apiErrorResponse(w, "invalid target", http.StatusBadRequest, nil)
		h.Inc(metricAPICarvesErr)
		return
	}
	// Get carves
	carves, err := h.Queries.GetCarves(targetVar, env.ID)
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

// GET Handler to return carves in JSON by environment
func (h *HandlersApi) CarveListHandler(w http.ResponseWriter, r *http.Request) {
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
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
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
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
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
	expTime := queries.QueryExpiration(c.ExpHours)
	if c.ExpHours == 0 {
		expTime = time.Time{}
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
		Expired:       false,
		Expiration:    expTime,
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

// CarvesActionHandler - POST Handler to delete/expire a carve
func (h *HandlersApi) CarvesActionHandler(w http.ResponseWriter, r *http.Request) {
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
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		h.Inc(metricAPICarvesErr)
		return
	}
	var msgReturn string
	// Carve can not be empty
	nameVar := r.PathValue("name")
	if nameVar == "" {
		apiErrorResponse(w, "name can not be empty", http.StatusBadRequest, nil)
		h.Inc(metricAPICarvesErr)
		return
	}
	// Check if carve exists
	if !h.Queries.Exists(nameVar, env.ID) {
		apiErrorResponse(w, "carve not found", http.StatusNotFound, nil)
		h.Inc(metricAPICarvesErr)
		return
	}
	// Extract action
	actionVar := r.PathValue("action")
	if actionVar == "" {
		apiErrorResponse(w, "error getting action", http.StatusBadRequest, nil)
		h.Inc(metricAPICarvesErr)
		return
	}
	switch actionVar {
	case settings.CarveDelete:
		if err := h.Queries.Delete(nameVar, env.ID); err != nil {
			apiErrorResponse(w, "error deleting carve", http.StatusInternalServerError, err)
			h.Inc(metricAPICarvesErr)
			return
		}
		msgReturn = fmt.Sprintf("carve %s deleted successfully", nameVar)
	case settings.CarveExpire:
		if err := h.Queries.Expire(nameVar, env.ID); err != nil {
			apiErrorResponse(w, "error expiring carve", http.StatusInternalServerError, err)
			h.Inc(metricAPICarvesErr)
			return
		}
		msgReturn = fmt.Sprintf("carve %s expired successfully", nameVar)
	case settings.CarveComplete:
		if err := h.Queries.Complete(nameVar, env.ID); err != nil {
			apiErrorResponse(w, "error completing carve", http.StatusInternalServerError, err)
			h.Inc(metricAPICarvesErr)
			return
		}
		msgReturn = fmt.Sprintf("carve %s completed successfully", nameVar)
	}
	// Return message as serialized response
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiGenericResponse{Message: msgReturn})
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
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
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
