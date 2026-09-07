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
	// LogSinks gates the Log Sinks section in the SPA. Tied to the same
	// flag as ServiceConfig — the log_sinks routes are registered
	// alongside the service-config routes.
	LogSinks      bool `json:"log_sinks"`
	AuthProviders bool `json:"auth_providers"`
	// Alerts gates the Alerts section in the SPA. Tied to
	// --alerts-enabled — when false the /api/v1/alerts routes are not
	// registered and the alert tables are not created.
	Alerts       bool `json:"alerts"`
	Accelerated  bool `json:"accelerated"`
	Console      bool `json:"console"`
	FileExplorer bool `json:"file_explorer"`
	// Health gates the Health section in the SPA. Tied to --health-enabled —
	// when false the /api/v1/health routes are not registered.
	Health bool `json:"health"`
}

// FeaturesHandler — GET /api/v1/features.
func (h *HandlersApi) FeaturesHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, FeaturesResponse{
		Posture:       h.PostureEnabled,
		ServiceConfig: h.ServiceConfigEnabled,
		LogSinks:      h.LogSinksEnabled,
		AuthProviders: h.AuthProvidersEnabled,
		Alerts:        h.Alerts != nil,
		Accelerated:   h.OsqueryValues.Accelerated,
		Console:       h.OsqueryValues.Query && h.OsqueryValues.Console,
		FileExplorer:  h.OsqueryValues.Query && h.OsqueryValues.FileExplorer,
		Health:        h.Health != nil,
	})
}
