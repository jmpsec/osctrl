package handlers

import (
	"net/http"

	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

// HealthHandler - Handle health requests
func (h *HandlersApi) HealthHandler(w http.ResponseWriter, r *http.Request) {
	if log.Debug().Enabled() {
		utils.DebugHTTPDump(r, true)
	}
	// Send response
	utils.HTTPResponse(w, "", http.StatusOK, []byte(okContent))
}

// RootHandler - Handle root requests
func (h *HandlersApi) RootHandler(w http.ResponseWriter, r *http.Request) {
	if log.Debug().Enabled() {
		utils.DebugHTTPDump(r, true)
	}
	// Send response
	utils.HTTPResponse(w, "", http.StatusOK, []byte(okContent))
}

// ErrorHandler - Handle error requests
func (h *HandlersApi) ErrorHandler(w http.ResponseWriter, r *http.Request) {
	if log.Debug().Enabled() {
		utils.DebugHTTPDump(r, true)
	}
	// Send response
	utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(errorContent))
}

// ForbiddenHandler - Handle forbidden error requests
func (h *HandlersApi) ForbiddenHandler(w http.ResponseWriter, r *http.Request) {
	if log.Debug().Enabled() {
		utils.DebugHTTPDump(r, true)
	}
	// Send response
	utils.HTTPResponse(w, "", http.StatusForbidden, []byte(errorContent))
}
