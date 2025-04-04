package handlers

import (
	"net/http"

	"github.com/jmpsec/osctrl/pkg/utils"
)

// HealthHandler - Handle health requests
func (h *HandlersApi) HealthHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Send response
	utils.HTTPResponse(w, "", http.StatusOK, []byte(okContent))
}

// RootHandler - Handle root requests
func (h *HandlersApi) RootHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Send response
	utils.HTTPResponse(w, "", http.StatusOK, []byte(okContent))
}

// ErrorHandler - Handle error requests
func (h *HandlersApi) ErrorHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Send response
	utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(errorContent))
}

// ForbiddenHandler - Handle forbidden error requests
func (h *HandlersApi) ForbiddenHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Send response
	utils.HTTPResponse(w, "", http.StatusForbidden, []byte(errorContent))
}
