package handlers

import (
	"fmt"
	"net/http"

	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/utils"
	"github.com/rs/zerolog/log"
)

// PlatformsHandler - GET Handler for multiple JSON platforms
func (h *HandlersApi) PlatformsHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAPIPlatformsReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), false)
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		h.Inc(metricAPIPlatformsErr)
		return
	}
	// Get platforms
	platforms, err := h.Nodes.GetAllPlatforms()
	if err != nil {
		apiErrorResponse(w, "error getting platforms", http.StatusInternalServerError, err)
		h.Inc(metricAPIPlatformsErr)
		return
	}
	// Serialize and serve JSON
	if h.Settings.DebugService(settings.ServiceAPI) {
		log.Debug().Msg("DebugService: Returned platforms")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, platforms)
	h.Inc(metricAPIPlatformsOK)
}

// PlatformsEnvHandler - GET Handler to return platforms for one environment as JSON
func (h *HandlersApi) PlatformsEnvHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAPIPlatformsReq)
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
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		h.Inc(metricAPIPlatformsErr)
		return
	}
	// Get platforms
	platforms, err := h.Nodes.GetEnvPlatforms(env.UUID)
	if err != nil {
		apiErrorResponse(w, "error getting platforms", http.StatusInternalServerError, err)
		h.Inc(metricAPIPlatformsErr)
		return
	}
	// Serialize and serve JSON
	if h.Settings.DebugService(settings.ServiceAPI) {
		log.Debug().Msg("DebugService: Returned platforms")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, platforms)
	h.Inc(metricAPIPlatformsOK)
}
