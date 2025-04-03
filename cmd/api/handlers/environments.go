package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
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
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error getting environment", http.StatusBadRequest, nil)
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
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.UserLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	// Serialize and serve JSON
	log.Debug().Msgf("Returned environment %s", env.Name)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, env)
}

// EnvironmentMapHandler - GET Handler to return one environment as JSON
func (h *HandlersApi) EnvironmentMapHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract target
	targetVar := r.PathValue("target")
	if targetVar == "" {
		apiErrorResponse(w, "error getting target", http.StatusBadRequest, nil)
		return
	}
	// Check if target is valid
	if !EnvMapTargets[targetVar] {
		apiErrorResponse(w, "invalid target", http.StatusBadRequest, fmt.Errorf("invalid target %s", targetVar))
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
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
		return
	}
	// Serialize and serve JSON
	log.Debug().Msg("Returned environments map")
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, envMap)
}

// EnvironmentsHandler - GET Handler to return all environments as JSON
func (h *HandlersApi) EnvironmentsHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	// Get platforms
	envAll, err := h.Envs.All()
	if err != nil {
		apiErrorResponse(w, "error getting environments", http.StatusInternalServerError, err)
		return
	}
	// Serialize and serve JSON
	log.Debug().Msg("Returned environments")
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, envAll)
}

// EnvEnrollHandler - GET Handler to return node enrollment values (secret, certificate, one-liner) for an environment as JSON
func (h *HandlersApi) EnvEnrollHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error getting environment", http.StatusBadRequest, nil)
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
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.UserLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	// Extract target
	targetVar := r.PathValue("target")
	if targetVar == "" {
		apiErrorResponse(w, "error getting target", http.StatusBadRequest, nil)
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
			return
		}
	case environments.EnrollPowershell:
		returnData, err = environments.QuickAddOneLinerPowershell((env.Certificate != ""), env)
		if err != nil {
			apiErrorResponse(w, "error generating ps1 one-liner", http.StatusInternalServerError, err)
			return
		}
	default:
		apiErrorResponse(w, "invalid target", http.StatusBadRequest, fmt.Errorf("invalid target %s", targetVar))
		return
	}
	// Serialize and serve JSON
	log.Debug().Msgf("Returned data for environment%s : %s", env.Name, returnData)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiDataResponse{Data: returnData})
}

// EnvRemoveHandler - GET Handler to return node removal values for an environment as JSON
func (h *HandlersApi) EnvRemoveHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error getting environment", http.StatusBadRequest, nil)
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
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.UserLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	// Extract target
	targetVar := r.PathValue("target")
	if targetVar == "" {
		apiErrorResponse(w, "error getting target", http.StatusInternalServerError, nil)
		return
	}
	var returnData string
	switch targetVar {
	case environments.RemoveShell:
		returnData, err = environments.QuickRemoveOneLinerShell((env.Certificate != ""), env)
		if err != nil {
			apiErrorResponse(w, "error generating sh one-liner", http.StatusInternalServerError, err)
			return
		}
	case environments.RemovePowershell:
		returnData, err = environments.QuickRemoveOneLinerPowershell((env.Certificate != ""), env)
		if err != nil {
			apiErrorResponse(w, "error generating ps1 one-liner", http.StatusInternalServerError, err)
			return
		}
	default:
		apiErrorResponse(w, "invalid target", http.StatusBadRequest, fmt.Errorf("invalid target %s", targetVar))
		return
	}
	// Serialize and serve JSON
	log.Debug().Msgf("Returned data for environment%s : %s", env.Name, returnData)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiDataResponse{Data: returnData})
}

// EnvEnrollActionsHandler - POST Handler to perform actions (extend, expire) in enroll values
func (h *HandlersApi) EnvEnrollActionsHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error getting environment", http.StatusBadRequest, nil)
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
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	// Extract action
	actionVar := r.PathValue("action")
	if actionVar == "" {
		apiErrorResponse(w, "error getting action", http.StatusBadRequest, nil)
		return
	}
	var e types.ApiActionsRequest
	// Parse request JSON body
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	var msgReturn string
	switch actionVar {
	case settings.ActionExtend:
		if err := h.Envs.ExtendEnroll(env.UUID); err != nil {
			apiErrorResponse(w, "error extending enrollment", http.StatusInternalServerError, err)
			return
		}
		msgReturn = "enrollment extended successfully"
	case settings.ActionExpire:
		if err := h.Envs.ExpireEnroll(env.UUID); err != nil {
			apiErrorResponse(w, "error expiring enrollment", http.StatusInternalServerError, err)
			return
		}
		msgReturn = "enrollment expired successfully"
	case settings.ActionRotate:
		if err := h.Envs.RotateEnroll(env.UUID); err != nil {
			apiErrorResponse(w, "error rotating enrollment", http.StatusInternalServerError, err)
			return
		}
		msgReturn = "enrollment rotated successfully"
	case settings.ActionNotexpire:
		if err := h.Envs.NotExpireEnroll(env.UUID); err != nil {
			apiErrorResponse(w, "error setting no expiration", http.StatusInternalServerError, err)
			return
		}
		msgReturn = "enrollment set to not expire"
	case settings.SetMacPackage:
		if err := h.Envs.UpdatePkgPackage(env.UUID, e.MacPkgURL); err != nil {
			apiErrorResponse(w, "error setting PKG", http.StatusInternalServerError, err)
			return
		}
		msgReturn = "PKG updated successfully"
	case settings.SetMsiPackage:
		if err := h.Envs.UpdateMsiPackage(env.UUID, e.MsiPkgURL); err != nil {
			apiErrorResponse(w, "error setting MSI", http.StatusInternalServerError, err)
			return
		}
		msgReturn = "MSI updated successfully"
	case settings.SetDebPackage:
		if err := h.Envs.UpdateDebPackage(env.UUID, e.DebPkgURL); err != nil {
			apiErrorResponse(w, "error setting DEB", http.StatusInternalServerError, err)
			return
		}
		msgReturn = "DEB updated successfully"
	case settings.SetRpmPackage:
		if err := h.Envs.UpdateRpmPackage(env.UUID, e.RpmPkgURL); err != nil {
			apiErrorResponse(w, "error setting RPM", http.StatusInternalServerError, err)
			return
		}
		msgReturn = "RPM updated successfully"
	default:
		apiErrorResponse(w, "invalid action", http.StatusBadRequest, fmt.Errorf("invalid action %s", actionVar))
		return
	}
	// Return query name as serialized response
	log.Debug().Msgf("Returned data for environment %s : %s", env.Name, msgReturn)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiGenericResponse{Message: msgReturn})
}

// EnvRemoveActionsHandler - POST Handler to perform actions (extend, expire) in remove values
func (h *HandlersApi) EnvRemoveActionsHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error getting environment", http.StatusBadRequest, nil)
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
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	// Extract action
	actionVar := r.PathValue("action")
	if actionVar == "" {
		apiErrorResponse(w, "error getting action", http.StatusBadRequest, nil)
		return
	}
	var e types.ApiActionsRequest
	// Parse request JSON body
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	var msgReturn string
	switch actionVar {
	case settings.ActionExtend:
		if err := h.Envs.ExtendEnroll(env.UUID); err != nil {
			apiErrorResponse(w, "error extending remove", http.StatusInternalServerError, err)
			return
		}
		msgReturn = "remove extended successfully"
	case settings.ActionExpire:
		if err := h.Envs.ExpireEnroll(env.UUID); err != nil {
			apiErrorResponse(w, "error expiring remove", http.StatusInternalServerError, err)
			return
		}
	case settings.ActionRotate:
		if err := h.Envs.RotateEnroll(env.UUID); err != nil {
			apiErrorResponse(w, "error rotating remove", http.StatusInternalServerError, err)
			return
		}
		msgReturn = "remove rotated successfully"
	case settings.ActionNotexpire:
		if err := h.Envs.NotExpireEnroll(env.UUID); err != nil {
			apiErrorResponse(w, "error setting no remove", http.StatusInternalServerError, err)
			return
		}
		msgReturn = "remove set to not expire"
	default:
		apiErrorResponse(w, "invalid action", http.StatusBadRequest, fmt.Errorf("invalid action %s", actionVar))
		return
	}
	// Return query name as serialized response
	log.Debug().Msgf("Returned data for environment %s : %s", env.Name, msgReturn)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiGenericResponse{Message: msgReturn})
}
