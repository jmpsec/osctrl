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
func (h *HandlersApi) LoginHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled, never log the body for login
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	// Extract environment. A missing env path-param still flows through
	// the normal failure path below so a probe of POST /api/v1/login//
	// returns the same opaque response as a successful URL with bad
	// creds; pre-May 2026 a missing env returned 400 with a distinct
	// "error with environment" message which let an attacker tell
	// "you used the wrong URL shape" apart from "you used a valid env
	// name but wrong creds."
	envVar := r.PathValue("env")
	var l types.ApiLoginRequest
	// Parse request JSON body. Body-parse failures are honest 4xx —
	// they cannot be used to enumerate env names (the failure mode is
	// independent of envVar).
	if err := json.NewDecoder(r.Body).Decode(&l); err != nil {
		apiErrorResponse(w, "invalid request", http.StatusBadRequest, err)
		return
	}
	// Resolve environment by name OR UUID. The SPA login form lets users
	// type the env name ("dev", "prod") because UUIDs are not memorable;
	// the API must accept either. Get() uses `name = ? OR uuid = ?` so
	// both shapes resolve to the same row.
	//
	// Env-not-found and bad-credentials and missing-env-permission ALL
	// produce the SAME response: 403 "invalid credentials". Pre-May 2026
	// the three paths had distinct status codes / messages, letting an
	// anonymous attacker enumerate valid env names by observing 404 vs
	// 403, and then enumerate valid usernames by observing which
	// (env+username) pair got "no access" vs "invalid credentials".
	// We always run CheckLoginCredentials first so the bcrypt-cost
	// timing equalization (see pkg/users.dummyHash) also covers the
	// env-miss branch — without it, env-miss would short-circuit at
	// 5ms while bad-creds takes ~210ms (10–40× timing oracle on env
	// existence). The actual env row, if any, is looked up only after
	// credentials pass; the failure path doesn't care.
	access, user := h.Users.CheckLoginCredentials(l.Username, l.Password)
	if !access {
		// Audit-log distinguishes the cause server-side so SoC tooling
		// still gets actionable signal; the client always sees the
		// same opaque error.
		h.AuditLog.FailedLogin(l.Username, utils.GetIP(r), "invalid credentials")
		apiErrorResponse(w, "invalid credentials", http.StatusForbidden, nil)
		return
	}
	if envVar == "" {
		// Missing env path-param: indistinguishable from bad creds
		// to the client. Internal log records the cause.
		h.AuditLog.FailedLogin(l.Username, utils.GetIP(r), "missing env in URL")
		apiErrorResponse(w, "invalid credentials", http.StatusForbidden, nil)
		return
	}
	env, err := h.Envs.Get(envVar)
	if err != nil {
		// Non-existent env: same opaque response. Logged distinctly.
		h.AuditLog.FailedLogin(l.Username, utils.GetIP(r), fmt.Sprintf("env not found: %q", envVar))
		apiErrorResponse(w, "invalid credentials", http.StatusForbidden, nil)
		return
	}
	// Env exists and creds passed. Check env permission.
	if !h.Users.CheckPermissions(l.Username, users.AdminLevel, env.UUID) {
		h.AuditLog.FailedLogin(l.Username, utils.GetIP(r), fmt.Sprintf("no admin access to env %s", env.UUID))
		apiErrorResponse(w, "invalid credentials", http.StatusForbidden, nil)
		return
	}
	// Decide whether to reuse the stored token or mint a fresh one. Re-issue
	// when there's no token, when the stored token has already expired (the
	// reuse path used to return 500 "token already expired" — a regression
	// that locked users out after their first session expired), or when the
	// stored token is within 60s of expiring so we don't hand out something
	// that will fail mid-request.
	var tokenExp time.Time
	now := time.Now()
	const freshnessWindow = 60 * time.Second
	needsRefresh := user.APIToken == "" || user.TokenExpire.Before(now.Add(freshnessWindow))
	if needsRefresh {
		var token string
		token, tokenExp, err = h.Users.CreateToken(l.Username, h.ServiceName, l.ExpHours)
		if err != nil {
			apiErrorResponse(w, "error creating token", http.StatusInternalServerError, err)
			return
		}
		if err = h.Users.UpdateToken(l.Username, token, tokenExp); err != nil {
			apiErrorResponse(w, "error updating token", http.StatusInternalServerError, err)
			return
		}
		user.APIToken = token
	} else {
		tokenExp = user.TokenExpire
	}
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
