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
// the data is static and ships with the binary. A pentest finding (May 2026)
// noted that even read-only data fingerprints the deployment as osctrl and
// reveals the SQL-template starter pack to anonymous callers — neither of
// which the SPA's only consumer (the post-login queries/new form) requires
// at pre-auth time. Moved behind handlerAuthCheck in cmd/api/main.go.
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
// as QuerySamplesHandler. The path list is exactly the set of high-value
// exfiltration locations osctrl is provisioned to carve; surfacing it to
// anonymous callers (pre-May 2026) was a free recon gift to attackers.
func (h *HandlersApi) CarveSamplesHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, carves.CarveSamples)
}
