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
	// Get settings
	serviceSettings, err := h.Settings.RetrieveValues(service, false, settings.NoEnvironmentID)
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
	// Get settings
	serviceSettings, err := h.Settings.RetrieveValues(service, true, settings.NoEnvironmentID)
	if err != nil {
		apiErrorResponse(w, "error getting settings", http.StatusInternalServerError, err)
		return
	}
	// Serialize and serve JSON
	log.Debug().Msg("Returned settings")
	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, serviceSettings)
}
