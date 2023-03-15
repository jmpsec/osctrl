package main

import (
	"net/http"

	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/utils"
)

const (
	metricAPIReq    = "api-req"
	metricAPIErr    = "api-err"
	metricAPIOK     = "api-ok"
	metricHealthReq = "health-req"
	metricHealthOK  = "health-ok"
)

const errorContent = "❌"
const okContent = "✅"

// Handle health requests
func healthHTTPHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricHealthReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI, settings.NoEnvironment), true)
	// Send response
	utils.HTTPResponse(w, "", http.StatusOK, []byte(okContent))
	incMetric(metricHealthOK)
}

// Handle root requests
func rootHTTPHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricHealthReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI, settings.NoEnvironment), true)
	// Send response
	utils.HTTPResponse(w, "", http.StatusOK, []byte(okContent))
	incMetric(metricAPIOK)
}

// Handle error requests
func errorHTTPHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPIReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI, settings.NoEnvironment), true)
	// Send response
	utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(errorContent))
	incMetric(metricAPIErr)
}

// Handle forbidden error requests
func forbiddenHTTPHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPIReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironment), true)
	// Send response
	utils.HTTPResponse(w, "", http.StatusForbidden, []byte(errorContent))
	incMetric(metricAPIErr)
}
