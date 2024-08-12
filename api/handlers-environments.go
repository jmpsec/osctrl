package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jmpsec/osctrl/environments"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/types"
	"github.com/jmpsec/osctrl/users"
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
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), false)
	vars := mux.Vars(r)
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
	if !apiUsers.CheckPermissions(ctx[ctxUser], users.UserLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		incMetric(metricAPIEnvsErr)
		return
	}
	// Serialize and serve JSON
	if settingsmgr.DebugService(settings.ServiceAPI) {
		log.Printf("DebugService: Returned environment %s", env.Name)
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, env)
	incMetric(metricAPIEnvsOK)
}

// GET Handler to return all environments as JSON
func apiEnvironmentsHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPIEnvsReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), false)
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !apiUsers.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		incMetric(metricAPIEnvsErr)
		return
	}
	// Get platforms
	envAll, err := envs.All()
	if err != nil {
		apiErrorResponse(w, "error getting environments", http.StatusInternalServerError, err)
		incMetric(metricAPIEnvsErr)
		return
	}
	// Serialize and serve JSON
	if settingsmgr.DebugService(settings.ServiceAPI) {
		log.Println("DebugService: Returned environments")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, envAll)
	incMetric(metricAPIEnvsOK)
}

// GET Handler to return node enrollment values (secret, certificate, one-liner) for an environment as JSON
func apiEnvEnrollHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPIEnvsReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), false)
	vars := mux.Vars(r)
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
	if !apiUsers.CheckPermissions(ctx[ctxUser], users.UserLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		incMetric(metricAPIEnvsErr)
		return
	}
	// Extract target
	targetVar, ok := vars["target"]
	if !ok {
		apiErrorResponse(w, "error getting target", http.StatusInternalServerError, nil)
		incMetric(metricAPIEnvsErr)
		return
	}
	var returnData string
	switch targetVar {
	case settings.DownloadSecret:
		returnData = env.Secret
	case settings.DownloadCert:
		returnData = env.Certificate
	case settings.DownloadFlags:
		returnData = env.Flags
	case environments.EnrollShell:
		returnData, err = environments.QuickAddOneLinerShell((env.Certificate != ""), env)
		if err != nil {
			apiErrorResponse(w, "error generating sh one-liner", http.StatusInternalServerError, err)
			incMetric(metricAPIEnvsErr)
			return
		}
	case environments.EnrollPowershell:
		returnData, err = environments.QuickAddOneLinerPowershell((env.Certificate != ""), env)
		if err != nil {
			apiErrorResponse(w, "error generating ps1 one-liner", http.StatusInternalServerError, err)
			incMetric(metricAPIEnvsErr)
			return
		}
	default:
		apiErrorResponse(w, "invalid target", http.StatusBadRequest, fmt.Errorf("invalid target %s", targetVar))
		incMetric(metricAPIEnvsErr)
		return
	}
	// Serialize and serve JSON
	if settingsmgr.DebugService(settings.ServiceAPI) {
		log.Printf("DebugService: Returned environment %s", returnData)
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiDataResponse{Data: returnData})
	incMetric(metricAPIEnvsOK)
}

// GET Handler to return node removal values for an environment as JSON
func apiEnvRemoveHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPIEnvsReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), false)
	vars := mux.Vars(r)
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
	if !apiUsers.CheckPermissions(ctx[ctxUser], users.UserLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		incMetric(metricAPIEnvsErr)
		return
	}
	// Extract target
	targetVar, ok := vars["target"]
	if !ok {
		apiErrorResponse(w, "error getting target", http.StatusInternalServerError, nil)
		incMetric(metricAPIEnvsErr)
		return
	}
	var returnData string
	switch targetVar {
	case environments.RemoveShell:
		returnData, err = environments.QuickRemoveOneLinerShell((env.Certificate != ""), env)
		if err != nil {
			apiErrorResponse(w, "error generating sh one-liner", http.StatusInternalServerError, err)
			incMetric(metricAPIEnvsErr)
			return
		}
	case environments.RemovePowershell:
		returnData, err = environments.QuickRemoveOneLinerPowershell((env.Certificate != ""), env)
		if err != nil {
			apiErrorResponse(w, "error generating ps1 one-liner", http.StatusInternalServerError, err)
			incMetric(metricAPIEnvsErr)
			return
		}
	default:
		apiErrorResponse(w, "invalid target", http.StatusBadRequest, fmt.Errorf("invalid target %s", targetVar))
		incMetric(metricAPIEnvsErr)
		return
	}
	// Serialize and serve JSON
	if settingsmgr.DebugService(settings.ServiceAPI) {
		log.Printf("DebugService: Returned environment %s", types.ApiDataResponse{Data: returnData})
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, env)
	incMetric(metricAPIEnvsOK)
}
