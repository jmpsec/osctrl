package main

import (
	"net/http"

	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/utils"
)

// GET Handler for multiple JSON platforms
func apiPlatformsHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPIReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI), false)
	// Get platforms
	platforms, err := nodesmgr.GetAllPlatforms()
	if err != nil {
		incMetric(metricAPIErr)
		apiErrorResponse(w, "error getting platforms", err)
		return
	}
	// Serialize and serve JSON
	apiHTTPResponse(w, JSONApplicationUTF8, http.StatusOK, platforms)
	incMetric(metricAPIOK)
}
