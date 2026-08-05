package handlers

import (
	"net/http"

	"github.com/jmpsec/osctrl/pkg/utils"
)

// RootHandler to be used as health check
func (h *HandlersTLS) RootHandler(w http.ResponseWriter, r *http.Request) {
	// Send response
	utils.HTTPResponse(w, "", http.StatusOK, []byte("💥"))
}

// HealthHandler for health requests. Returns HTTP 200 when the
// backend is healthy (or no DB health monitor is wired), and HTTP
// 204 when the DB health monitor reports the backend as degraded.
// 204 — rather than 503 — is used because the service is still
// serving osquery nodes from stale-serve caches; the non-200 code
// lets load balancers / operators distinguish the degraded state
// without dropping traffic.
func (h *HandlersTLS) HealthHandler(w http.ResponseWriter, r *http.Request) {
	if h.DBHealth != nil && h.DBHealth.IsDegraded() {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// Send response
	utils.HTTPResponse(w, "", http.StatusOK, []byte("✅"))
}

// ErrorHandler for error requests
func (h *HandlersTLS) ErrorHandler(w http.ResponseWriter, r *http.Request) {
	// Send response
	utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte("uh oh..."))
}
