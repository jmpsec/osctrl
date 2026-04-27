package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/tags"
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
	if h.DebugHTTPConfig.EnableHTTP {
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
	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, env)
}

// EnvironmentMapHandler - GET Handler to return one environment as JSON
func (h *HandlersApi) EnvironmentMapHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
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
	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], auditlog.NoEnvironment)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, envMap)
}

// EnvironmentsHandler - GET Handler to return all environments as JSON
func (h *HandlersApi) EnvironmentsHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
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
	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], auditlog.NoEnvironment)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, envAll)
}

// EnvEnrollHandler - GET Handler to return node enrollment values (secret, certificate, one-liner) for an environment as JSON
func (h *HandlersApi) EnvEnrollHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
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
	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiDataResponse{Data: returnData})
}

// EnvRemoveHandler - GET Handler to return node removal values for an environment as JSON
func (h *HandlersApi) EnvRemoveHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
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
	log.Debug().Msgf("Returned data for environment %s : %s", env.Name, returnData)
	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiDataResponse{Data: returnData})
}

// EnvEnrollActionsHandler - POST Handler to perform actions (extend, expire) in enroll values
func (h *HandlersApi) EnvEnrollActionsHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
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
	h.AuditLog.EnvAction(ctx[ctxUser], actionVar+" enrollment for environment "+env.Name, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiGenericResponse{Message: msgReturn})
}

// EnvRemoveActionsHandler - POST Handler to perform actions (extend, expire) in remove values
func (h *HandlersApi) EnvRemoveActionsHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
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
		if err := h.Envs.ExtendRemove(env.UUID); err != nil {
			apiErrorResponse(w, "error extending remove", http.StatusInternalServerError, err)
			return
		}
		msgReturn = "remove extended successfully"
	case settings.ActionExpire:
		if err := h.Envs.ExpireRemove(env.UUID); err != nil {
			apiErrorResponse(w, "error expiring remove", http.StatusInternalServerError, err)
			return
		}
	case settings.ActionRotate:
		if err := h.Envs.RotateRemove(env.UUID); err != nil {
			apiErrorResponse(w, "error rotating remove", http.StatusInternalServerError, err)
			return
		}
		msgReturn = "remove rotated successfully"
	case settings.ActionNotexpire:
		if err := h.Envs.NotExpireRemove(env.UUID); err != nil {
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
	h.AuditLog.EnvAction(ctx[ctxUser], actionVar+" removal for environment "+env.Name, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiGenericResponse{Message: msgReturn})
}

// EnvActionsHandler - POST Handler to perform actions (create, delete, edit) on environments
func (h *HandlersApi) EnvActionsHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	var e types.ApiEnvRequest
	// Parse request JSON body
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	var msgReturn string
	switch e.Action {
	case "create":
		// Verify request fields
		if !environments.VerifyEnvFilters(e.Name, e.Icon, e.Type, e.Hostname) {
			apiErrorResponse(w, "invalid data", http.StatusBadRequest, nil)
			return
		}
		// Check if environment already exists
		if !h.Envs.Exists(e.Name) {
			env := h.Envs.Empty(e.Name, e.Hostname)
			env.Icon = e.Icon
			env.Type = e.Type
			if e.UUID != "" {
				env.UUID = e.UUID
			}
			// Empty configuration
			env.Configuration = h.Envs.GenEmptyConfiguration(true)
			// Generate flags
			flags, err := h.Envs.GenerateFlags(env, "", "", h.OsqueryValues)
			if err != nil {
				apiErrorResponse(w, "error generating flags", http.StatusInternalServerError, err)
				return
			}
			env.Flags = flags
			// Create environment
			if err := h.Envs.Create(&env); err != nil {
				apiErrorResponse(w, "error creating environment", http.StatusInternalServerError, err)
				return
			}
			// Generate full permissions for the user creating the environment
			access := h.Users.GenEnvUserAccess([]string{env.UUID}, true, true, true, true)
			perms := h.Users.GenPermissions(ctx[ctxUser], "osctrl-api", access)
			if err := h.Users.CreatePermissions(perms); err != nil {
				apiErrorResponse(w, "error generating permissions", http.StatusInternalServerError, err)
				return
			}
			// Create a tag for this new environment
			if !h.Tags.Exists(env.Name) {
			if err := h.Tags.NewTag(
				env.Name,
				"Tag for environment "+env.Name,
				"",
				env.Icon,
				ctx[ctxUser],
				env.ID,
				false,
				tags.TagTypeEnv,
				""); err != nil {
				msgReturn = fmt.Sprintf("error generating tag %s ", err.Error())
				return
				}
			}
			msgReturn = "environment created successfully"
		} else {
			apiErrorResponse(w, "environment already exists", http.StatusBadRequest, fmt.Errorf("environment %s already exists", e.Name))
			return
		}
	case "delete":
		// Verify request fields
		if !environments.EnvNameFilter(e.Name) {
			apiErrorResponse(w, "invalid environment name", http.StatusBadRequest, nil)
			return
		}
		if h.Envs.Exists(e.UUID) {
			if err := h.Envs.Delete(e.Name); err != nil {
				apiErrorResponse(w, "error deleting environment", http.StatusInternalServerError, err)
				return
			}
			msgReturn = "environment deleted successfully"
		} else {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, fmt.Errorf("environment %s not found", e.Name))
			return
		}
	case "edit":
		// Verify request fields
		if !environments.EnvUUIDFilter(e.UUID) {
			apiErrorResponse(w, "invalid environment UUID", http.StatusBadRequest, nil)
			return
		}
		if !environments.HostnameFilter(e.Hostname) {
			apiErrorResponse(w, "invalid hostname", http.StatusBadRequest, nil)
			return
		}
		if h.Envs.Exists(e.UUID) {
			if err := h.Envs.UpdateHostname(e.UUID, e.Hostname); err != nil {
				apiErrorResponse(w, "error updating hostname", http.StatusInternalServerError, err)
				return
			}
			msgReturn = "environment updated successfully"
		} else {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, fmt.Errorf("environment %s not found", e.UUID))
			return
		}
	default:
		apiErrorResponse(w, "invalid action", http.StatusBadRequest, fmt.Errorf("invalid action %s", e.Action))
		return
	}
	// Return serialized response
	log.Debug().Msgf("Environment action %s completed: %s", e.Action, msgReturn)
	h.AuditLog.EnvAction(ctx[ctxUser], e.Action+" - "+e.Name, strings.Split(r.RemoteAddr, ":")[0], auditlog.NoEnvironment)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiGenericResponse{Message: msgReturn})
}
