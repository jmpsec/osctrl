package handlers

import (
	"net/http"

	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/utils"
)

// HealthHandler - Handle health requests
func (h *HandlersApi) HealthHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricHealthReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), true)
	// Send response
	utils.HTTPResponse(w, "", http.StatusOK, []byte(okContent))
	h.Inc(metricHealthOK)
}

// RootHandler - Handle root requests
func (h *HandlersApi) RootHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricHealthReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), true)
	// Send response
	utils.HTTPResponse(w, "", http.StatusOK, []byte(okContent))
	h.Inc(metricAPIOK)
}

// ErrorHandler - Handle error requests
func (h *HandlersApi) ErrorHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAPIReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), true)
	// Send response
	utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(errorContent))
	h.Inc(metricAPIErr)
}

// ForbiddenHandler - Handle forbidden error requests
func (h *HandlersApi) ForbiddenHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAPIReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironmentID), true)
	// Send response
	utils.HTTPResponse(w, "", http.StatusForbidden, []byte(errorContent))
	h.Inc(metricAPIErr)
}
