package handlers

import (
	"net/http"

	"github.com/jmpsec/osctrl/pkg/utils"
)

// AuthMethod describes one auth surface advertised to the SPA.
// `type` is the discriminator; clients render the appropriate UI based
// on it. We avoid leaking the issuer URL, client id, or any other
// IdP-specific detail at this layer — those are the IdP's responsibility
// to reveal once the user is redirected.
type AuthMethod struct {
	Type string `json:"type"`
	// LoginURL is the relative URL the SPA should redirect the
	// browser to when this method is chosen. For "password" this
	// is "/api/v1/login/{env}" (env is interpolated client-side
	// from the env switcher). For "oidc" this is the global
	// "/api/v1/auth/oidc/login" — env is irrelevant for federated
	// login because the federated user resolves to a single
	// AdminUser row regardless of which env tab they were viewing.
	LoginURL string `json:"loginUrl"`
}

// AuthMethodsResponse is the JSON shape returned by
// GET /api/v1/auth/methods. Always returns at least the "password"
// method; OIDC is added only when --oidc-enabled is true AND the
// provider validated at startup. The SPA renders one button per
// method in stable order; we don't promise stable order beyond
// "password always first."
type AuthMethodsResponse struct {
	Methods []AuthMethod `json:"methods"`
}

// AuthMethodsHandler — GET /api/v1/auth/methods (no env path).
//
// Unauthenticated by design: the SPA calls this BEFORE the user has
// logged in to decide which login UI to render. The response leaks
// only the *list* of auth shapes; no per-user, per-env, or per-IdP
// detail. The endpoint exists so the SPA never has to ship a
// "is OIDC compiled in?" build-time flag — operators toggle it
// server-side without re-deploying the SPA.
//
// Rate-limited at the route layer (same preAuthRateLimit as the
// env/sample endpoints) to keep this from being a free metadata
// scrape vector.
// @Summary List authentication methods
// @Description Returns the authentication methods enabled for the API login UI.
// @Tags auth
// @Produce json
// @Success 200 {object} AuthMethodsResponse
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Router /api/v1/auth/methods [get]
func (h *HandlersApi) AuthMethodsHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	methods := []AuthMethod{
		{Type: "password", LoginURL: "/api/v1/login"},
	}
	if h.OIDCEnabled {
		methods = append(methods, AuthMethod{
			Type:     "oidc",
			LoginURL: "/api/v1/auth/oidc/login",
		})
	}
	if h.SAMLEnabled {
		methods = append(methods, AuthMethod{
			Type:     "saml",
			LoginURL: "/api/v1/auth/saml/login",
		})
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, AuthMethodsResponse{Methods: methods})
}
