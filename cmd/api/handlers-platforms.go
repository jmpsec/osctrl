package main

import (
	"log"
	"net/http"

	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/utils"
)

// GET Handler for multiple JSON platforms
func apiPlatformsHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPIReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI), false)
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !apiUsers.IsAdmin(ctx["user"]) {
		log.Printf("attempt to use API by user %s", ctx["user"])
		apiErrorResponse(w, "no access", http.StatusForbidden, nil)
		return
	}
	// Get platforms
	platforms, err := nodesmgr.GetAllPlatforms()
	if err != nil {
		incMetric(metricAPIErr)
		apiErrorResponse(w, "error getting platforms", http.StatusInternalServerError, err)
		return
	}
	// Serialize and serve JSON
	apiHTTPResponse(w, JSONApplicationUTF8, http.StatusOK, platforms)
	incMetric(metricAPIOK)
}
