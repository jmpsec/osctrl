package main

import (
	"log"
	"net/http"

	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/utils"
)

const (
	metricAPIPlatformsReq = "platforms-req"
	metricAPIPlatformsErr = "platforms-err"
	metricAPIPlatformsOK  = "platforms-ok"
)

// GET Handler for multiple JSON platforms
func apiPlatformsHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPIPlatformsReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI), false)
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !apiUsers.IsAdmin(ctx["user"]) {
		incMetric(metricAPIPlatformsErr)
		log.Printf("attempt to use API by user %s", ctx["user"])
		apiErrorResponse(w, "no access", http.StatusForbidden, nil)
		return
	}
	// Get platforms
	platforms, err := nodesmgr.GetAllPlatforms()
	if err != nil {
		incMetric(metricAPIPlatformsErr)
		apiErrorResponse(w, "error getting platforms", http.StatusInternalServerError, err)
		return
	}
	// Serialize and serve JSON
	if settingsmgr.DebugService(settings.ServiceAPI) {
		log.Println("DebugService: Returned platforms")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, platforms)
	incMetric(metricAPIPlatformsOK)
}
