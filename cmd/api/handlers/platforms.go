package handlers

import (
	"fmt"
	"net/http"

	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

// PlatformsHandler - GET Handler for multiple JSON platforms
func (h *HandlersApi) PlatformsHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissionsContext(r.Context(), ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	// Get platforms
	platforms, err := h.Nodes.GetAllPlatforms()
	if err != nil {
		apiErrorResponse(w, "error getting platforms", http.StatusInternalServerError, err)
		return
	}
	// Serialize and serve JSON
	log.Debug().Msg("Returned platforms")
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, platforms)
}

// PlatformsEnvHandler - GET Handler to return platforms for one environment as JSON
// @Summary List platforms
// @Description Returns platform counts for an environment.
// @Tags platforms
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Success 200 {array} nodes.PlatformCounts
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/platforms/{env} [get]
func (h *HandlersApi) PlatformsEnvHandler(w http.ResponseWriter, r *http.Request) {
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
	if !h.Users.CheckPermissionsContext(r.Context(), ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	// Get platforms
	platforms, err := h.Nodes.GetEnvPlatforms(env.UUID)
	if err != nil {
		apiErrorResponse(w, "error getting platforms", http.StatusInternalServerError, err)
		return
	}
	// Serialize and serve JSON
	log.Debug().Msg("Returned platforms")
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, platforms)
}
