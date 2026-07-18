package handlers

import (
	"net/http"

	"github.com/jmpsec/osctrl/pkg/utils"
)

// FeaturesResponse advertises server-side feature switches consumed by the SPA.
type FeaturesResponse struct {
	Posture bool `json:"posture"`
}

// FeaturesHandler — GET /api/v1/features.
func (h *HandlersApi) FeaturesHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, FeaturesResponse{
		Posture: h.PostureEnabled,
	})
}
