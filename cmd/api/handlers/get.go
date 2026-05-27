package handlers

import (
	"fmt"
	"net/http"

	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
)

// HealthHandler - Handle health requests
// @Summary API health check
// @Description Returns the API health response.
// @Tags system
// @Produce json
// @Success 200 {string} string
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Router /health [get]
func (h *HandlersApi) HealthHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Send response
	utils.HTTPResponse(w, "", http.StatusOK, []byte(okContent))
}

// CheckHandlerNoAuth - Handle unauthenticated check requests
// @Summary Unauthenticated API check
// @Description Returns API availability without requiring authentication.
// @Tags checks
// @Produce json
// @Success 200 {string} string
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Router /api/v1/checks-no-auth [get]
func (h *HandlersApi) CheckHandlerNoAuth(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Send response
	utils.HTTPResponse(w, "Checked", http.StatusOK, []byte(okContent))
}

// CheckHandlerAuth - Handle authenticated check requests
// @Summary Authenticated API check
// @Description Returns API availability for an authenticated user.
// @Tags checks
// @Produce json
// @Success 200 {string} string
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/checks-auth [get]
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
// @Summary API root liveness check
// @Description Returns the API root liveness response.
// @Tags system
// @Produce json
// @Success 200 {string} string
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Router / [get]
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
// @Summary API error response
// @Description Returns a generic API error response.
// @Tags system
// @Produce json
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {string} string "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Router /error [get]
func (h *HandlersApi) ErrorHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Send response
	utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(errorContent))
}

// ForbiddenHandler - Handle forbidden error requests
// @Summary API forbidden response
// @Description Returns a generic forbidden response.
// @Tags system
// @Produce json
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Router /forbidden [get]
func (h *HandlersApi) ForbiddenHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Send response
	utils.HTTPResponse(w, "", http.StatusForbidden, []byte(errorContent))
}
