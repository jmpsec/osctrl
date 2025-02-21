package handlers

import (
	"fmt"
	"net/http"

	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/users"
	"github.com/jmpsec/osctrl/utils"
	"github.com/rs/zerolog/log"
)

// SettingsHandler - GET Handler for all settings including JSON
func (h *HandlersApi) SettingsHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAPISettingsReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), false)
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		h.Inc(metricAPISettingsErr)
		return
	}
	// Get settings
	serviceSettings, err := h.Settings.RetrieveAll()
	if err != nil {
		apiErrorResponse(w, "error getting settings", http.StatusInternalServerError, err)
		h.Inc(metricAPISettingsErr)
		return
	}
	// Serialize and serve JSON
	if h.Settings.DebugService(settings.ServiceAPI) {
		log.Debug().Msg("DebugService: Returned settings")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, serviceSettings)
	h.Inc(metricAPISettingsOK)
}

// SettingsServiceHandler - GET Handler for service specific settings excluding JSON
func (h *HandlersApi) SettingsServiceHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAPISettingsReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), false)
	// Extract service
	service := r.PathValue("service")
	if service == "" {
		apiErrorResponse(w, "error getting service", http.StatusBadRequest, nil)
		h.Inc(metricAPISettingsErr)
		return
	}
	// Make sure service is valid
	if !h.Settings.VerifyType(service) {
		apiErrorResponse(w, "invalid service", http.StatusInternalServerError, nil)
		h.Inc(metricAPISettingsErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		h.Inc(metricAPISettingsErr)
		return
	}
	// Get settings
	serviceSettings, err := h.Settings.RetrieveValues(service, false, settings.NoEnvironmentID)
	if err != nil {
		apiErrorResponse(w, "error getting settings", http.StatusInternalServerError, err)
		h.Inc(metricAPISettingsErr)
		return
	}
	// Serialize and serve JSON
	if h.Settings.DebugService(settings.ServiceAPI) {
		log.Debug().Msg("DebugService: Returned settings")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, serviceSettings)
	h.Inc(metricAPISettingsOK)
}

// SettingsServiceEnvHandler - GET Handler for service and environment specific settings excluding JSON
func (h *HandlersApi) SettingsServiceEnvHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAPISettingsReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), false)
	// Extract service
	service := r.PathValue("service")
	if service == "" {
		apiErrorResponse(w, "error getting service", http.StatusBadRequest, nil)
		h.Inc(metricAPISettingsErr)
		return
	}
	// Make sure service is valid
	if !h.Settings.VerifyType(service) {
		apiErrorResponse(w, "invalid service", http.StatusInternalServerError, nil)
		h.Inc(metricAPISettingsErr)
		return
	}
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
		h.Inc(metricAPISettingsErr)
		return
	}
	// Get settings
	serviceSettings, err := h.Settings.RetrieveValues(service, false, settings.NoEnvironmentID)
	if err != nil {
		apiErrorResponse(w, "error getting settings", http.StatusInternalServerError, err)
		h.Inc(metricAPISettingsErr)
		return
	}
	// Serialize and serve JSON
	if h.Settings.DebugService(settings.ServiceAPI) {
		log.Debug().Msg("DebugService: Returned settings")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, serviceSettings)
	h.Inc(metricAPISettingsOK)
}

// SettingsServiceJSONHandler - GET Handler for service specific settings including JSON
func (h *HandlersApi) SettingsServiceJSONHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAPISettingsReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), false)
	// Extract environment
	service := r.PathValue("service")
	if service == "" {
		apiErrorResponse(w, "error getting service", http.StatusBadRequest, nil)
		h.Inc(metricAPISettingsErr)
		return
	}
	// Make sure service is valid
	if !h.Settings.VerifyType(service) {
		apiErrorResponse(w, "invalid service", http.StatusInternalServerError, nil)
		h.Inc(metricAPISettingsErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		h.Inc(metricAPISettingsErr)
		return
	}
	// Get settings
	serviceSettings, err := h.Settings.RetrieveValues(service, true, settings.NoEnvironmentID)
	if err != nil {
		apiErrorResponse(w, "error getting settings", http.StatusInternalServerError, err)
		h.Inc(metricAPISettingsErr)
		return
	}
	// Serialize and serve JSON
	if h.Settings.DebugService(settings.ServiceAPI) {
		log.Debug().Msg("DebugService: Returned settings")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, serviceSettings)
	h.Inc(metricAPISettingsOK)
}

// GET Handler for service and environment specific settings including JSON
func (h *HandlersApi) SettingsServiceEnvJSONHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAPISettingsReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), false)
	// Extract environment
	service := r.PathValue("service")
	if service == "" {
		apiErrorResponse(w, "error getting service", http.StatusBadRequest, nil)
		h.Inc(metricAPISettingsErr)
		return
	}
	// Make sure service is valid
	if !h.Settings.VerifyType(service) {
		apiErrorResponse(w, "invalid service", http.StatusInternalServerError, nil)
		h.Inc(metricAPISettingsErr)
		return
	}
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
		h.Inc(metricAPISettingsErr)
		return
	}
	// Get settings
	serviceSettings, err := h.Settings.RetrieveValues(service, true, settings.NoEnvironmentID)
	if err != nil {
		apiErrorResponse(w, "error getting settings", http.StatusInternalServerError, err)
		h.Inc(metricAPISettingsErr)
		return
	}
	// Serialize and serve JSON
	if h.Settings.DebugService(settings.ServiceAPI) {
		log.Debug().Msg("DebugService: Returned settings")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, serviceSettings)
	h.Inc(metricAPISettingsOK)
}
