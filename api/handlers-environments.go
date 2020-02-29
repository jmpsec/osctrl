package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/utils"
)

const (
	metricAPIEnvsReq = "envs-req"
	metricAPIEnvsErr = "envs-err"
	metricAPIEnvsOK  = "envs-ok"
)

// GET Handler to return one environment as JSON
func apiEnvironmentHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPIEnvsReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI), false)
	vars := mux.Vars(r)
	// Extract name
	name, ok := vars["name"]
	if !ok {
		incMetric(metricAPIEnvsErr)
		apiErrorResponse(w, "error getting name", http.StatusInternalServerError, nil)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !apiUsers.IsAdmin(ctx["user"]) {
		log.Printf("attempt to use API by user %s", ctx["user"])
		apiErrorResponse(w, "no access", http.StatusForbidden, nil)
		return
	}
	// Get environment by name
	env, err := envs.Get(name)
	if err != nil {
		incMetric(metricAPIEnvsErr)
		if err.Error() == "record not found" {
			log.Printf("environment not found: %s", name)
			apiErrorResponse(w, "environment not found", http.StatusNotFound, nil)
		} else {
			apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, err)
		}
		return
	}
	// Header to serve JSON
	apiHTTPResponse(w, JSONApplicationUTF8, http.StatusOK, env)
	incMetric(metricAPIEnvsOK)
	if settingsmgr.DebugService(settings.ServiceAPI) {
		log.Printf("DebugService: Returned environment %s", name)
	}
}

// GET Handler to return all environments as JSON
func apiEnvironmentsHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPIEnvsReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI), false)
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !apiUsers.IsAdmin(ctx["user"]) {
		log.Printf("attempt to use API by user %s", ctx["user"])
		apiErrorResponse(w, "no access", http.StatusForbidden, nil)
		return
	}
	// Get platforms
	envAll, err := envs.All()
	if err != nil {
		incMetric(metricAPIEnvsErr)
		apiErrorResponse(w, "error getting environments", http.StatusInternalServerError, err)
		return
	}
	// Header to serve JSON
	apiHTTPResponse(w, JSONApplicationUTF8, http.StatusOK, envAll)
	incMetric(metricAPIEnvsOK)
	if settingsmgr.DebugService(settings.ServiceAPI) {
		log.Println("DebugService: Returned environments")
	}
}
