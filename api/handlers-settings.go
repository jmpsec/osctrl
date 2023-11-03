package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/users"
	"github.com/jmpsec/osctrl/utils"
)

const (
	metricAPISettingsReq = "settings-req"
	metricAPISettingsErr = "settings-err"
	metricAPISettingsOK  = "settings-ok"
)

// GET Handler for all settings including JSON
func apiSettingsHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPISettingsReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI, settings.NoEnvironment), false)
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !apiUsers.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		incMetric(metricAPISettingsErr)
		return
	}
	// Get settings
	serviceSettings, err := settingsmgr.RetrieveAll()
	if err != nil {
		apiErrorResponse(w, "error getting settings", http.StatusInternalServerError, err)
		incMetric(metricAPISettingsErr)
		return
	}
	// Serialize and serve JSON
	if settingsmgr.DebugService(settings.ServiceAPI) {
		log.Println("DebugService: Returned settings")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, serviceSettings)
	incMetric(metricAPISettingsOK)
}

// GET Handler for service specific settings excluding JSON
func apiSettingsServiceHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPISettingsReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI, settings.NoEnvironment), false)
	vars := mux.Vars(r)
	// Extract service
	service, ok := vars["service"]
	if !ok {
		apiErrorResponse(w, "error getting service", http.StatusInternalServerError, nil)
		incMetric(metricAPISettingsErr)
		return
	}
	// Make sure service is valid
	if !settingsmgr.VerifyType(service) {
		apiErrorResponse(w, "invalid service", http.StatusInternalServerError, nil)
		incMetric(metricAPISettingsErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !apiUsers.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		incMetric(metricAPISettingsErr)
		return
	}
	// Get settings
	serviceSettings, err := settingsmgr.RetrieveValues(service, false, settings.NoEnvironment)
	if err != nil {
		apiErrorResponse(w, "error getting settings", http.StatusInternalServerError, err)
		incMetric(metricAPISettingsErr)
		return
	}
	// Serialize and serve JSON
	if settingsmgr.DebugService(settings.ServiceAPI) {
		log.Println("DebugService: Returned settings")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, serviceSettings)
	incMetric(metricAPISettingsOK)
}

// GET Handler for service and environment specific settings excluding JSON
func apiSettingsServiceEnvHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPISettingsReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI, settings.NoEnvironment), false)
	vars := mux.Vars(r)
	// Extract service
	service, ok := vars["service"]
	if !ok {
		apiErrorResponse(w, "error getting service", http.StatusInternalServerError, nil)
		incMetric(metricAPISettingsErr)
		return
	}
	// Make sure service is valid
	if !settingsmgr.VerifyType(service) {
		apiErrorResponse(w, "invalid service", http.StatusInternalServerError, nil)
		incMetric(metricAPISettingsErr)
		return
	}
	// Extract environment
	envVar, ok := vars["env"]
	if !ok {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		incMetric(metricAPIEnvsErr)
		return
	}
	// Get environment by name
	env, err := envs.Get(envVar)
	if err != nil {
		if err.Error() == "record not found" {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, err)
		}
		incMetric(metricAPIEnvsErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !apiUsers.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		incMetric(metricAPISettingsErr)
		return
	}
	// Get settings
	serviceSettings, err := settingsmgr.RetrieveValues(service, false, settings.NoEnvironment)
	if err != nil {
		apiErrorResponse(w, "error getting settings", http.StatusInternalServerError, err)
		incMetric(metricAPISettingsErr)
		return
	}
	// Serialize and serve JSON
	if settingsmgr.DebugService(settings.ServiceAPI) {
		log.Println("DebugService: Returned settings")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, serviceSettings)
	incMetric(metricAPISettingsOK)
}

// GET Handler for service specific settings including JSON
func apiSettingsServiceJSONHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPISettingsReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI, settings.NoEnvironment), false)
	vars := mux.Vars(r)
	// Extract environment
	service, ok := vars["service"]
	if !ok {
		apiErrorResponse(w, "error getting service", http.StatusInternalServerError, nil)
		incMetric(metricAPISettingsErr)
		return
	}
	// Make sure service is valid
	if !settingsmgr.VerifyType(service) {
		apiErrorResponse(w, "invalid service", http.StatusInternalServerError, nil)
		incMetric(metricAPISettingsErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !apiUsers.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		incMetric(metricAPISettingsErr)
		return
	}
	// Get settings
	serviceSettings, err := settingsmgr.RetrieveValues(service, true, settings.NoEnvironment)
	if err != nil {
		apiErrorResponse(w, "error getting settings", http.StatusInternalServerError, err)
		incMetric(metricAPISettingsErr)
		return
	}
	// Serialize and serve JSON
	if settingsmgr.DebugService(settings.ServiceAPI) {
		log.Println("DebugService: Returned settings")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, serviceSettings)
	incMetric(metricAPISettingsOK)
}

// GET Handler for service and environment specific settings including JSON
func apiSettingsServiceEnvJSONHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPISettingsReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI, settings.NoEnvironment), false)
	vars := mux.Vars(r)
	// Extract environment
	service, ok := vars["service"]
	if !ok {
		apiErrorResponse(w, "error getting service", http.StatusInternalServerError, nil)
		incMetric(metricAPISettingsErr)
		return
	}
	// Make sure service is valid
	if !settingsmgr.VerifyType(service) {
		apiErrorResponse(w, "invalid service", http.StatusInternalServerError, nil)
		incMetric(metricAPISettingsErr)
		return
	}
	// Extract environment
	envVar, ok := vars["env"]
	if !ok {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		incMetric(metricAPIEnvsErr)
		return
	}
	// Get environment by name
	env, err := envs.Get(envVar)
	if err != nil {
		if err.Error() == "record not found" {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, err)
		}
		incMetric(metricAPIEnvsErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !apiUsers.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		incMetric(metricAPISettingsErr)
		return
	}
	// Get settings
	serviceSettings, err := settingsmgr.RetrieveValues(service, true, settings.NoEnvironment)
	if err != nil {
		apiErrorResponse(w, "error getting settings", http.StatusInternalServerError, err)
		incMetric(metricAPISettingsErr)
		return
	}
	// Serialize and serve JSON
	if settingsmgr.DebugService(settings.ServiceAPI) {
		log.Println("DebugService: Returned settings")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, serviceSettings)
	incMetric(metricAPISettingsOK)
}
