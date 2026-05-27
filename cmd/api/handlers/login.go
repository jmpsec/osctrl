package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
)

// LoginHandler - POST Handler for API login request
//
// Registered on both POST /api/v1/login and POST /api/v1/login/{env}.
// When {env} is present, the handler additionally verifies that the
// user has AdminLevel access to that specific environment before
// issuing a token. When {env} is absent (the SPA's default), the
// handler authenticates the user and issues a token without an
// env-scoped permission check — per-request authorization on
// every subsequent endpoint enforces env access anyway.
// @Summary Log in
// @Description Authenticates an API user and returns a JWT token.
// @Tags auth
// @Accept json
// @Produce json
// @Param env path string false "Environment name or UUID"
// @Param request body types.ApiLoginRequest true "Request body"
// @Success 200 {object} types.ApiLoginResponse
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Router /api/v1/login [post]
// @Router /api/v1/login/{env} [post]
func (h *HandlersApi) LoginHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled, never log the body for login
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	var l types.ApiLoginRequest
	// Parse request JSON body
	if err := json.NewDecoder(r.Body).Decode(&l); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	// Check credentials. Audit-log every credential failure so SoC tooling
	// has a stream to alert on (brute-force, password spray). The IP comes
	// from utils.GetIP so X-Real-IP / X-Forwarded-For behind a reverse
	// proxy is honored.
	access, user := h.Users.CheckLoginCredentials(l.Username, l.Password)
	if !access {
		h.AuditLog.FailedLogin(l.Username, utils.GetIP(r), "invalid credentials")
		apiErrorResponse(w, "invalid credentials", http.StatusForbidden, nil)
		return
	}
	// Optional env-scoped permission check (backward compat for CLI callers
	// that POST to /api/v1/login/{env}).
	envVar := r.PathValue("env")
	if envVar != "" {
		env, err := h.Envs.Get(envVar)
		if err != nil {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, nil)
			return
		}
		if !h.Users.CheckPermissions(l.Username, users.AdminLevel, env.UUID) {
			h.AuditLog.FailedLogin(l.Username, utils.GetIP(r), fmt.Sprintf("no admin access to env %s", env.UUID))
			apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use %s by user %s", h.ServiceName, l.Username))
			return
		}
	}
	// Always mint a fresh JWT on successful login and overwrite the stored
	// APIToken. The auth middleware in cmd/api/auth.go compares every
	// presented JWT against the stored APIToken (constant-time), so once
	// UpdateToken overwrites, any previously-issued JWT for this user
	// immediately fails 401 — even though it is still cryptographically
	// valid against the secret. This is the revocation primitive that
	// makes re-login (and logout, below) capable of invalidating a
	// stolen token. The previous "reuse if >60s of life left" optimisation
	// silently undid that revocation: re-login from a new device returned
	// the SAME JWT, leaving the stolen copy valid.
	token, tokenExp, err := h.Users.CreateToken(l.Username, h.ServiceName, l.ExpHours)
	if err != nil {
		apiErrorResponse(w, "error creating token", http.StatusInternalServerError, err)
		return
	}
	if err = h.Users.UpdateToken(l.Username, token, tokenExp); err != nil {
		apiErrorResponse(w, "error updating token", http.StatusInternalServerError, err)
		return
	}
	user.APIToken = token
	// Generate a CSRF token: 16 random bytes encoded as 32 hex chars.
	// This cookie is NOT HttpOnly so the SPA can read it and echo it back
	// via the X-CSRF-Token header on mutating requests.
	csrfBytes := make([]byte, 16)
	if _, err = rand.Read(csrfBytes); err != nil {
		apiErrorResponse(w, "error generating csrf token", http.StatusInternalServerError, err)
		return
	}
	csrfToken := hex.EncodeToString(csrfBytes)
	// Persist the CSRF token alongside the user so the auth middleware can
	// verify subsequent X-CSRF-Token headers. Without this write the SPA's
	// double-submit pattern is purely cosmetic.
	// IP comes from utils.GetIP so it matches the format every other site
	// writes to last_ip_address (clean IP, X-Real-IP / X-Forwarded-For aware).
	clientIP := utils.GetIP(r)
	if err := h.Users.UpdateMetadata(clientIP, r.UserAgent(), l.Username, csrfToken); err != nil {
		apiErrorResponse(w, "error persisting csrf token", http.StatusInternalServerError, err)
		return
	}
	// Compute cookie Max-Age from token expiry.
	maxAge := int(time.Until(tokenExp).Seconds())
	if maxAge <= 0 {
		apiErrorResponse(w, "token already expired", http.StatusInternalServerError, fmt.Errorf("token expiry in past or zero: %v", tokenExp))
		return
	}
	// Set the httpOnly session cookie. The SPA reads the JWT via the cookie;
	// it never needs to access this cookie from JS.
	// Secure: true requires HTTPS. If TLS is terminated at a proxy that speaks
	// plain HTTP to this service, set Secure:false in the proxy's cookie rewrite
	// rule — do not add an --insecure-cookies flag to keep the surface small.
	http.SetCookie(w, &http.Cookie{
		Name:     "osctrl_token",
		Value:    user.APIToken,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	// Set the CSRF cookie (not HttpOnly — SPA must read it).
	http.SetCookie(w, &http.Cookie{
		Name:     "osctrl_csrf",
		Value:    csrfToken,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: false,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	h.AuditLog.NewLogin(l.Username, clientIP)
	// Serialize and serve JSON. Token stays in the body for backward compat
	// with CLI consumers that do not use cookies.
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiLoginResponse{
		Token:     user.APIToken,
		CSRFToken: csrfToken,
	})
}
