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
// queries/new form can populate its QuickTemplates row. Authenticated.
//
// History: an earlier revision exposed this pre-auth on the rationale that
// the data is static and ships with the binary. Even read-only data
// fingerprints the deployment as osctrl and reveals the SQL-template
// starter pack to anonymous callers — neither of which the only
// consumer (the post-login queries/new form) requires at pre-auth time.
// Moved behind handlerAuthCheck in cmd/api/main.go.
// @Summary List query samples
// @Description Returns sample query templates.
// @Tags queries
// @Produce json
// @Success 200 {array} queries.QuerySample
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/queries/samples [get]
func (h *HandlersApi) QuerySamplesHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, queries.QuerySamples)
}

// CarveSamplesHandler - GET /api/v1/carves/samples
//
// Returns the static starter library of common carve-target file paths
// (e.g., /etc/passwd, C:\Windows\System32\config\SAM). Same auth posture
// as QuerySamplesHandler. The path list is the set of high-value
// exfiltration locations osctrl is provisioned to carve; surfacing it
// to anonymous callers was a free recon gift to attackers.
// @Summary List carve samples
// @Description Returns sample carve path templates.
// @Tags carves
// @Produce json
// @Success 200 {array} carves.CarveSample
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/carves/samples [get]
func (h *HandlersApi) CarveSamplesHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, carves.CarveSamples)
}
