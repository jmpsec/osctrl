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

var errorContent = []byte("❌")
var okContent = []byte("✅")

// Handle health requests
func healthHTTPHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricHealthReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI), true)
	// Send response
	utils.HTTPResponse(w, "", http.StatusOK, okContent)
	incMetric(metricHealthOK)
}

// Handle root requests
func rootHTTPHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricHealthReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI), true)
	// Send response
	utils.HTTPResponse(w, "", http.StatusOK, okContent)
	incMetric(metricHealthOK)
}

// Handle error requests
func errorHTTPHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPIReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI), true)
	// Send response
	utils.HTTPResponse(w, "", http.StatusInternalServerError, errorContent)
	incMetric(metricAPIErr)
}

// Handle forbidden error requests
func forbiddenHTTPHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPIReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), true)
	// Send response
	utils.HTTPResponse(w, "", http.StatusForbidden, errorContent)
	incMetric(metricAPIErr)
}
