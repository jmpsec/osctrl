package handlers

import (
	"net/http"

	"github.com/jmpsec/osctrl/pkg/utils"
)

// FeaturesResponse advertises server-side feature switches consumed by the SPA.
type FeaturesResponse struct {
	Posture bool `json:"posture"`
	// ServiceConfig gates the whole Service Config section in the SPA. When
	// false the /api/v1/service-config routes are not registered at all.
	ServiceConfig bool `json:"service_config"`
	Accelerated   bool `json:"accelerated"`
	FileExplorer  bool `json:"file_explorer"`
}

// FeaturesHandler — GET /api/v1/features.
func (h *HandlersApi) FeaturesHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, FeaturesResponse{
		Posture:       h.PostureEnabled,
		ServiceConfig: h.ServiceConfigEnabled,
		Accelerated:   h.OsqueryValues.Accelerated,
		FileExplorer:  h.OsqueryValues.Query && h.OsqueryValues.Accelerated && h.OsqueryValues.FileExplorer,
	})
}
