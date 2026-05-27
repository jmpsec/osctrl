package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

// SettingsHandler - GET Handler for all settings including JSON
// @Summary List settings
// @Description Returns settings for all services.
// @Tags settings
// @Produce json
// @Success 200 {array} settings.SettingValue
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/settings [get]
func (h *HandlersApi) SettingsHandler(w http.ResponseWriter, r *http.Request) {
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
	// Get settings
	serviceSettings, err := h.Settings.RetrieveAll()
	if err != nil {
		apiErrorResponse(w, "error getting settings", http.StatusInternalServerError, err)
		return
	}
	// Serialize and serve JSON
	log.Debug().Msg("Returned settings")
	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], auditlog.NoEnvironment)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, serviceSettings)
}

// SettingsServiceHandler - GET Handler for service specific settings excluding JSON
// @Summary List service settings
// @Description Returns settings for a service.
// @Tags settings
// @Produce json
// @Param service path string true "Service name"
// @Success 200 {array} settings.SettingValue
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/settings/{service} [get]
func (h *HandlersApi) SettingsServiceHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract service
	service := r.PathValue("service")
	if service == "" {
		apiErrorResponse(w, "error getting service", http.StatusBadRequest, nil)
		return
	}
	// Make sure service is valid
	if !h.Settings.VerifyService(service) {
		apiErrorResponse(w, "invalid service", http.StatusInternalServerError, nil)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	// Get settings
	serviceSettings, err := h.Settings.RetrieveValues(service, false, settings.NoEnvironmentID)
	if err != nil {
		apiErrorResponse(w, "error getting settings", http.StatusInternalServerError, err)
		return
	}
	// Serialize and serve JSON
	log.Debug().Msg("Returned settings")
	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], auditlog.NoEnvironment)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, serviceSettings)
}

// SettingsServiceEnvHandler - GET Handler for service and environment specific settings excluding JSON
// @Summary List service environment settings
// @Description Returns settings for a service and environment.
// @Tags settings
// @Produce json
// @Param service path string true "Service name"
// @Param env path string true "Environment name or UUID"
// @Success 200 {array} settings.SettingValue
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/settings/{service}/{env} [get]
func (h *HandlersApi) SettingsServiceEnvHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract service
	service := r.PathValue("service")
	if service == "" {
		apiErrorResponse(w, "error getting service", http.StatusBadRequest, nil)
		return
	}
	// Make sure service is valid
	if !h.Settings.VerifyService(service) {
		apiErrorResponse(w, "invalid service", http.StatusInternalServerError, nil)
		return
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error getting environment", http.StatusBadRequest, nil)
		return
	}
	// Get environment by name
	env, err := h.Envs.Get(envVar)
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
	// Get settings scoped to THIS env. Was previously passing
	// NoEnvironmentID and silently returning global settings, which let
	// an env-X admin read another env's values as a side-channel via the
	// env-scoped route.
	serviceSettings, err := h.Settings.RetrieveValues(service, false, env.ID)
	if err != nil {
		apiErrorResponse(w, "error getting settings", http.StatusInternalServerError, err)
		return
	}
	// Serialize and serve JSON
	log.Debug().Msg("Returned settings")
	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, serviceSettings)
}

// SettingsServiceJSONHandler - GET Handler for service specific settings including JSON
// @Summary List service JSON settings
// @Description Returns JSON settings for a service.
// @Tags settings
// @Produce json
// @Param service path string true "Service name"
// @Success 200 {array} settings.SettingValue
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/settings/{service}/json [get]
func (h *HandlersApi) SettingsServiceJSONHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment
	service := r.PathValue("service")
	if service == "" {
		apiErrorResponse(w, "error getting service", http.StatusBadRequest, nil)
		return
	}
	// Make sure service is valid
	if !h.Settings.VerifyService(service) {
		apiErrorResponse(w, "invalid service", http.StatusInternalServerError, nil)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	// Get settings
	serviceSettings, err := h.Settings.RetrieveValues(service, true, settings.NoEnvironmentID)
	if err != nil {
		apiErrorResponse(w, "error getting settings", http.StatusInternalServerError, err)
		return
	}
	// Serialize and serve JSON
	log.Debug().Msg("Returned settings")
	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], auditlog.NoEnvironment)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, serviceSettings)
}

// GET Handler for service and environment specific settings including JSON
// @Summary List service environment JSON settings
// @Description Returns JSON settings for a service and environment.
// @Tags settings
// @Produce json
// @Param service path string true "Service name"
// @Param env path string true "Environment name or UUID"
// @Success 200 {array} settings.SettingValue
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/settings/{service}/json/{env} [get]
func (h *HandlersApi) SettingsServiceEnvJSONHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment
	service := r.PathValue("service")
	if service == "" {
		apiErrorResponse(w, "error getting service", http.StatusBadRequest, nil)
		return
	}
	// Make sure service is valid
	if !h.Settings.VerifyService(service) {
		apiErrorResponse(w, "invalid service", http.StatusInternalServerError, nil)
		return
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error getting environment", http.StatusBadRequest, nil)
		return
	}
	// Get environment by name
	env, err := h.Envs.Get(envVar)
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
	// Get settings scoped to THIS env. Same defense as
	// SettingsServiceEnvHandler above; was silently returning global
	// settings via NoEnvironmentID.
	serviceSettings, err := h.Settings.RetrieveValues(service, true, env.ID)
	if err != nil {
		apiErrorResponse(w, "error getting settings", http.StatusInternalServerError, err)
		return
	}
	// Serialize and serve JSON
	log.Debug().Msg("Returned settings")
	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, serviceSettings)
}
