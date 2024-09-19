package handlers

import (
	"fmt"
	"log"
	"net/http"

	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/users"
	"github.com/jmpsec/osctrl/utils"
)

// TagsHandler - GET Handler for multiple JSON tags
func (h *HandlersApi) AllTagsHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAPITagsReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), false)
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		h.Inc(metricAPITagsErr)
		return
	}
	// Get tags
	tags, err := h.Tags.All()
	if err != nil {
		apiErrorResponse(w, "error getting tags", http.StatusInternalServerError, err)
		h.Inc(metricAPITagsErr)
		return
	}
	// Serialize and serve JSON
	if h.Settings.DebugService(settings.ServiceAPI) {
		log.Println("DebugService: Returned tags")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, tags)
	h.Inc(metricAPITagsOK)
}

// TagsEnvHandler - GET Handler to return tags for one environment as JSON
func (h *HandlersApi) TagsEnvHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAPITagsReq)
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
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		h.Inc(metricAPITagsErr)
		return
	}
	// Get tags
	tags, err := h.Tags.GetByEnv(env.ID)
	if err != nil {
		apiErrorResponse(w, "error getting tags", http.StatusInternalServerError, err)
		h.Inc(metricAPITagsErr)
		return
	}
	// Serialize and serve JSON
	if h.Settings.DebugService(settings.ServiceAPI) {
		log.Println("DebugService: Returned tags")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, tags)
	h.Inc(metricAPITagsOK)
}
