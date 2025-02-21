package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/utils"
	"github.com/rs/zerolog/log"
)

// Define targets to be used to retrieve an environment map
var (
	EnvMapTargets = map[string]bool{
		"id":   true,
		"uuid": true,
		"name": true,
	}
)

// EnvironmentHandler - GET Handler to return one environment by UUID as JSON
func (h *HandlersApi) EnvironmentHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAPIEnvsReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), false)
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error getting environment", http.StatusBadRequest, nil)
		h.Inc(metricAPIEnvsErr)
		return
	}
	// Get environment by UUID
	env, err := h.Envs.GetByUUID(envVar)
	if err != nil {
		if err.Error() == "record not found" {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, err)
		}
		h.Inc(metricAPIEnvsErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.UserLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		h.Inc(metricAPIEnvsErr)
		return
	}
	// Serialize and serve JSON
	if h.Settings.DebugService(settings.ServiceAPI) {
		log.Debug().Msgf("DebugService: Returned environment %s", env.Name)
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, env)
	h.Inc(metricAPIEnvsOK)
}

// EnvironmentMapHandler - GET Handler to return one environment as JSON
func (h *HandlersApi) EnvironmentMapHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAPIEnvsReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), false)
	// Extract target
	targetVar := r.PathValue("target")
	if targetVar == "" {
		apiErrorResponse(w, "error getting target", http.StatusBadRequest, nil)
		h.Inc(metricAPIEnvsErr)
		return
	}
	// Check if target is valid
	if !EnvMapTargets[targetVar] {
		apiErrorResponse(w, "invalid target", http.StatusBadRequest, fmt.Errorf("invalid target %s", targetVar))
		h.Inc(metricAPIEnvsErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		h.Inc(metricAPIEnvsErr)
		return
	}
	// Prepare map by target
	var envMap interface{}
	var err error
	switch targetVar {
	case "id":
		envMap, err = h.Envs.GetMapByID()
	case "uuid":
		envMap, err = h.Envs.GetMapByString()
	case "name":
		envMap, err = h.Envs.GetMapByString()
	}
	if err != nil {
		apiErrorResponse(w, "error getting environments map", http.StatusInternalServerError, err)
		h.Inc(metricAPIEnvsErr)
		return
	}
	// Serialize and serve JSON
	if h.Settings.DebugService(settings.ServiceAPI) {
		log.Debug().Msg("DebugService: Returned environments map")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, envMap)
	h.Inc(metricAPIEnvsOK)
}

// EnvironmentsHandler - GET Handler to return all environments as JSON
func (h *HandlersApi) EnvironmentsHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAPIEnvsReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), false)
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		h.Inc(metricAPIEnvsErr)
		return
	}
	// Get platforms
	envAll, err := h.Envs.All()
	if err != nil {
		apiErrorResponse(w, "error getting environments", http.StatusInternalServerError, err)
		h.Inc(metricAPIEnvsErr)
		return
	}
	// Serialize and serve JSON
	if h.Settings.DebugService(settings.ServiceAPI) {
		log.Debug().Msg("DebugService: Returned environments")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, envAll)
	h.Inc(metricAPIEnvsOK)
}

// EnvEnrollHandler - GET Handler to return node enrollment values (secret, certificate, one-liner) for an environment as JSON
func (h *HandlersApi) EnvEnrollHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAPIEnvsReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), false)
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error getting environment", http.StatusBadRequest, nil)
		h.Inc(metricAPIEnvsErr)
		return
	}
	// Get environment by name
	env, err := h.Envs.GetByUUID(envVar)
	if err != nil {
		if err.Error() == "record not found" {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, err)
		}
		h.Inc(metricAPIEnvsErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.UserLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		h.Inc(metricAPIEnvsErr)
		return
	}
	// Extract target
	targetVar := r.PathValue("target")
	if targetVar == "" {
		apiErrorResponse(w, "error getting target", http.StatusBadRequest, nil)
		h.Inc(metricAPIEnvsErr)
		return
	}
	var returnData string
	switch targetVar {
	case settings.DownloadSecret:
		returnData = env.Secret
	case settings.DownloadCert:
		returnData = env.Certificate
	case settings.DownloadFlags:
		returnData = env.Flags
	case environments.EnrollShell:
		returnData, err = environments.QuickAddOneLinerShell((env.Certificate != ""), env)
		if err != nil {
			apiErrorResponse(w, "error generating sh one-liner", http.StatusInternalServerError, err)
			h.Inc(metricAPIEnvsErr)
			return
		}
	case environments.EnrollPowershell:
		returnData, err = environments.QuickAddOneLinerPowershell((env.Certificate != ""), env)
		if err != nil {
			apiErrorResponse(w, "error generating ps1 one-liner", http.StatusInternalServerError, err)
			h.Inc(metricAPIEnvsErr)
			return
		}
	default:
		apiErrorResponse(w, "invalid target", http.StatusBadRequest, fmt.Errorf("invalid target %s", targetVar))
		h.Inc(metricAPIEnvsErr)
		return
	}
	// Serialize and serve JSON
	if h.Settings.DebugService(settings.ServiceAPI) {
		log.Debug().Msgf("DebugService: Returned environment %s", returnData)
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiDataResponse{Data: returnData})
	h.Inc(metricAPIEnvsOK)
}

// EnvRemoveHandler - GET Handler to return node removal values for an environment as JSON
func (h *HandlersApi) EnvRemoveHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAPIEnvsReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), false)
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error getting environment", http.StatusBadRequest, nil)
		h.Inc(metricAPIEnvsErr)
		return
	}
	// Get environment by name
	env, err := h.Envs.GetByUUID(envVar)
	if err != nil {
		if err.Error() == "record not found" {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, err)
		}
		h.Inc(metricAPIEnvsErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.UserLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		h.Inc(metricAPIEnvsErr)
		return
	}
	// Extract target
	targetVar := r.PathValue("target")
	if targetVar == "" {
		apiErrorResponse(w, "error getting target", http.StatusInternalServerError, nil)
		h.Inc(metricAPIEnvsErr)
		return
	}
	var returnData string
	switch targetVar {
	case environments.RemoveShell:
		returnData, err = environments.QuickRemoveOneLinerShell((env.Certificate != ""), env)
		if err != nil {
			apiErrorResponse(w, "error generating sh one-liner", http.StatusInternalServerError, err)
			h.Inc(metricAPIEnvsErr)
			return
		}
	case environments.RemovePowershell:
		returnData, err = environments.QuickRemoveOneLinerPowershell((env.Certificate != ""), env)
		if err != nil {
			apiErrorResponse(w, "error generating ps1 one-liner", http.StatusInternalServerError, err)
			h.Inc(metricAPIEnvsErr)
			return
		}
	default:
		apiErrorResponse(w, "invalid target", http.StatusBadRequest, fmt.Errorf("invalid target %s", targetVar))
		h.Inc(metricAPIEnvsErr)
		return
	}
	// Serialize and serve JSON
	if h.Settings.DebugService(settings.ServiceAPI) {
		log.Debug().Msgf("DebugService: Returned environment %s", types.ApiDataResponse{Data: returnData})
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, env)
	h.Inc(metricAPIEnvsOK)
}

// EnvEnrollActionsHandler - POST Handler to perform actions (extend, expire) in enroll values
func (h *HandlersApi) EnvEnrollActionsHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAPIQueriesReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), false)
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error getting environment", http.StatusBadRequest, nil)
		h.Inc(metricAPIEnvsErr)
		return
	}
	// Get environment by name
	env, err := h.Envs.GetByUUID(envVar)
	if err != nil {
		if err.Error() == "record not found" {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, err)
		}
		h.Inc(metricAPIEnvsErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		h.Inc(metricAPIEnvsErr)
		return
	}
	// Extract action
	actionVar := r.PathValue("action")
	if actionVar == "" {
		apiErrorResponse(w, "error getting action", http.StatusBadRequest, nil)
		h.Inc(metricAPIEnvsErr)
		return
	}
	var e types.ApiActionsRequest
	// Parse request JSON body
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		h.Inc(metricAPIEnvsErr)
		return
	}
	var msgReturn string
	switch actionVar {
	case settings.ActionExtend:
		if err := h.Envs.ExtendEnroll(env.UUID); err != nil {
			apiErrorResponse(w, "error extending enrollment", http.StatusInternalServerError, err)
			h.Inc(metricAPIEnvsErr)
			return
		}
		msgReturn = "enrollment extended successfully"
	case settings.ActionExpire:
		if err := h.Envs.ExpireEnroll(env.UUID); err != nil {
			apiErrorResponse(w, "error expiring enrollment", http.StatusInternalServerError, err)
			h.Inc(metricAPIEnvsErr)
			return
		}
		msgReturn = "enrollment expired successfully"
	case settings.ActionRotate:
		if err := h.Envs.RotateEnroll(env.UUID); err != nil {
			apiErrorResponse(w, "error rotating enrollment", http.StatusInternalServerError, err)
			h.Inc(metricAPIEnvsErr)
			return
		}
		msgReturn = "enrollment rotated successfully"
	case settings.ActionNotexpire:
		if err := h.Envs.NotExpireEnroll(env.UUID); err != nil {
			apiErrorResponse(w, "error setting no expiration", http.StatusInternalServerError, err)
			h.Inc(metricAPIEnvsErr)
			return
		}
		msgReturn = "enrollment set to not expire"
	case settings.SetMacPackage:
		if err := h.Envs.UpdatePkgPackage(env.UUID, e.MacPkgURL); err != nil {
			apiErrorResponse(w, "error setting PKG", http.StatusInternalServerError, err)
			h.Inc(metricAPIEnvsErr)
			return
		}
		msgReturn = "PKG updated successfully"
	case settings.SetMsiPackage:
		if err := h.Envs.UpdateMsiPackage(env.UUID, e.MsiPkgURL); err != nil {
			apiErrorResponse(w, "error setting MSI", http.StatusInternalServerError, err)
			h.Inc(metricAPIEnvsErr)
			return
		}
		msgReturn = "MSI updated successfully"
	case settings.SetDebPackage:
		if err := h.Envs.UpdateDebPackage(env.UUID, e.DebPkgURL); err != nil {
			apiErrorResponse(w, "error setting DEB", http.StatusInternalServerError, err)
			h.Inc(metricAPIEnvsErr)
			return
		}
		msgReturn = "DEB updated successfully"
	case settings.SetRpmPackage:
		if err := h.Envs.UpdateRpmPackage(env.UUID, e.RpmPkgURL); err != nil {
			apiErrorResponse(w, "error setting RPM", http.StatusInternalServerError, err)
			h.Inc(metricAPIEnvsErr)
			return
		}
		msgReturn = "RPM updated successfully"
	default:
		apiErrorResponse(w, "invalid action", http.StatusBadRequest, fmt.Errorf("invalid action %s", actionVar))
		h.Inc(metricAPIEnvsErr)
		return
	}
	// Return query name as serialized response
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiGenericResponse{Message: msgReturn})
	h.Inc(metricAPIEnvsOK)
}

// EnvRemoveActionsHandler - POST Handler to perform actions (extend, expire) in remove values
func (h *HandlersApi) EnvRemoveActionsHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAPIQueriesReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), false)
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error getting environment", http.StatusBadRequest, nil)
		h.Inc(metricAPIEnvsErr)
		return
	}
	// Get environment by name
	env, err := h.Envs.GetByUUID(envVar)
	if err != nil {
		if err.Error() == "record not found" {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, err)
		}
		h.Inc(metricAPIEnvsErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		h.Inc(metricAPIQueriesErr)
		return
	}
	// Extract action
	actionVar := r.PathValue("action")
	if actionVar == "" {
		apiErrorResponse(w, "error getting action", http.StatusBadRequest, nil)
		h.Inc(metricAPIEnvsErr)
		return
	}
	var e types.ApiActionsRequest
	// Parse request JSON body
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		h.Inc(metricAPIEnvsErr)
		return
	}
	var msgReturn string
	switch actionVar {
	case settings.ActionExtend:
		if err := h.Envs.ExtendEnroll(env.UUID); err != nil {
			apiErrorResponse(w, "error extending remove", http.StatusInternalServerError, err)
			h.Inc(metricAPIEnvsErr)
			return
		}
		msgReturn = "remove extended successfully"
	case settings.ActionExpire:
		if err := h.Envs.ExpireEnroll(env.UUID); err != nil {
			apiErrorResponse(w, "error expiring remove", http.StatusInternalServerError, err)
			h.Inc(metricAPIEnvsErr)
			return
		}
	case settings.ActionRotate:
		if err := h.Envs.RotateEnroll(env.UUID); err != nil {
			apiErrorResponse(w, "error rotating remove", http.StatusInternalServerError, err)
			h.Inc(metricAPIEnvsErr)
			return
		}
		msgReturn = "remove rotated successfully"
	case settings.ActionNotexpire:
		if err := h.Envs.NotExpireEnroll(env.UUID); err != nil {
			apiErrorResponse(w, "error setting no remove", http.StatusInternalServerError, err)
			h.Inc(metricAPIEnvsErr)
			return
		}
		msgReturn = "remove set to not expire"
	default:
		apiErrorResponse(w, "invalid action", http.StatusBadRequest, fmt.Errorf("invalid action %s", actionVar))
		h.Inc(metricAPIEnvsErr)
		return
	}
	// Return query name as serialized response
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiGenericResponse{Message: msgReturn})
	h.Inc(metricAPIEnvsOK)
}
