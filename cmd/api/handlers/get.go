package handlers

import (
	"fmt"
	"net/http"

	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
)

// HealthHandler - Handle health requests
func (h *HandlersApi) HealthHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Send response
	utils.HTTPResponse(w, "", http.StatusOK, []byte(okContent))
}

// CheckHandlerNoAuth - Handle unauthenticated check requests
func (h *HandlersApi) CheckHandlerNoAuth(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Send response
	utils.HTTPResponse(w, "Checked", http.StatusOK, []byte(okContent))
}

// CheckHandlerAuth - Handle authenticated check requests
func (h *HandlersApi) CheckHandlerAuth(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.UserLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	// Send response
	utils.HTTPResponse(w, "Checked", http.StatusOK, []byte(okContent))
}

// RootHandler - Handle root requests.
//
// `GET /` is registered as the api's liveness check (returns "✅"
// with 200). Go's ServeMux uses `/` as a wildcard match for any GET
// request the mux doesn't have a more-specific pattern for, which
// means typos like `GET /api/v1/totally-fake-endpoint` would land
// here and return 200 — confusing for clients debugging an
// integration. We tighten the contract: respond 200 ONLY when the
// request actually targets `/`. Other GETs that fall through fall
// out as 404.
//
// Returning 404 here doesn't leak endpoint structure beyond what's
// already in the public OpenAPI; it just stops the api from silently
// claiming success on misrouted requests.
func (h *HandlersApi) RootHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	utils.HTTPResponse(w, "", http.StatusOK, []byte(okContent))
}

// ErrorHandler - Handle error requests
func (h *HandlersApi) ErrorHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Send response
	utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(errorContent))
}

// ForbiddenHandler - Handle forbidden error requests
func (h *HandlersApi) ForbiddenHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Send response
	utils.HTTPResponse(w, "", http.StatusForbidden, []byte(errorContent))
}
