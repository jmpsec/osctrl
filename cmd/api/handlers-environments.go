package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/utils"
)

// GET Handler for single JSON environment
func apiEnvironmentHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPIReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI), false)
	vars := mux.Vars(r)
	// Extract name
	name, ok := vars["name"]
	if !ok {
		incMetric(metricAPIErr)
		apiErrorResponse(w, "error getting name", nil)
		return
	}
	// Get environment by name
	env, err := envs.Get(name)
	if err != nil {
		incMetric(metricAPIErr)
		if err.Error() == "record not found" {
			log.Printf("environment not found: %s", name)
			apiHTTPResponse(w, JSONApplicationUTF8, http.StatusNotFound, ApiErrorResponse{Error: "environment not found"})
		} else {
			apiErrorResponse(w, "error getting environment", err)
		}
		return
	}
	// Header to serve JSON
	apiHTTPResponse(w, JSONApplicationUTF8, http.StatusOK, env)
	incMetric(metricAPIOK)
}

// GET Handler for multiple JSON environments
func apiEnvironmentsHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPIReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI), false)
	// Get platforms
	envAll, err := envs.All()
	if err != nil {
		incMetric(metricAPIErr)
		apiErrorResponse(w, "error getting environments", err)
		return
	}
	// Header to serve JSON
	apiHTTPResponse(w, JSONApplicationUTF8, http.StatusOK, envAll)
	incMetric(metricAPIOK)
}
