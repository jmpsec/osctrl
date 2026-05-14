package handlers

import (
	"net/http"

	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/utils"
)

// QuerySamplesHandler - GET /api/v1/queries/samples
//
// Returns the static starter library of osquery SQL templates so the SPA's
// queries/new form can populate its QuickTemplates row. Intentionally
// unauthenticated: the samples are read-only data shipped with the binary,
// they aren't tenant- or env-scoped, and exposing them pre-auth lets the
// login screen lazy-load them without circular dependencies.
//
// Shares the per-IP loginRateLimit registered in main.go so this endpoint
// can't be turned into a low-effort scanning probe.
func (h *HandlersApi) QuerySamplesHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, queries.QuerySamples)
}

// CarveSamplesHandler - GET /api/v1/carves/samples
//
// Returns the static starter library of common carve-target file paths
// (e.g., /etc/passwd, C:\Windows\System32\config\SAM). Same auth posture as
// QuerySamplesHandler: pre-auth, rate-limited.
func (h *HandlersApi) CarveSamplesHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, carves.CarveSamples)
}
