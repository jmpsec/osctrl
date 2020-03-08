package main

import (
	"net/http"

	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/utils"
)

const (
	metricJSONReq   = "admin-json-req"
	metricJSONErr   = "admin-json-err"
	metricJSONOK    = "admin-json-ok"
	metricHealthReq = "health-req"
	metricHealthOK  = "health-ok"
)

// Empty default osquery configuration
const emptyConfiguration string = "data/osquery-empty.json"

const errorContent = "❌"
const okContent = "✅"

// Handle health requests
func healthHTTPHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricHealthReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), true)
	// Send response
	utils.HTTPResponse(w, "", http.StatusOK, okContent)
	incMetric(metricHealthOK)
}

// Handle error requests
func errorHTTPHandler(w http.ResponseWriter, r *http.Request) {
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), true)
	// Send response
	utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte("oh no..."))
}

// Handle forbidden error requests
func forbiddenHTTPHandler(w http.ResponseWriter, r *http.Request) {
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), true)
	// Send response
	utils.HTTPResponse(w, "", http.StatusForbidden, errorContent)
}

// Handler for the favicon
func faviconHandler(w http.ResponseWriter, r *http.Request) {
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	w.Header().Set("Content-Type", "image/png")
	http.ServeFile(w, r, "./static/favicon.png")
}
