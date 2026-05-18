package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/utils"
)

// LoginHandler — POST /api/v1/login.
//
// Credentials-only login: takes username + password, returns a JWT + CSRF
// cookie pair. NO env path-param, NO env permission check at this layer.
// Matches legacy admin's posture (cmd/admin/handlers/post.go
// LoginPOSTHandler), which never accepted an env on login. A user who
// authenticates successfully but has zero env permissions still gets a
// session — the SPA renders an empty env switcher and a "contact your
// administrator" message; trying to access any env-scoped route hits the
// regular CheckPermissions gate at the handler level.
//
// Pre-May 2026 the route was POST /api/v1/login/{env} with an env
// permission check at this layer, plus a separate pre-auth
// GET /api/v1/login/environments to populate the SPA's env dropdown.
// Pentest finding: that combination enumerated valid environments and
// (env, username) permission pairs to anonymous callers. Reverting to
// legacy admin's posture closes both leaks without any UX regression —
// the SPA picks an env after login via the existing env switcher.
//
// Failure modes are deliberately indistinguishable to the client:
//
//   - bad credentials (no such user OR wrong password) → 403 "invalid credentials"
//   - JSON body parse failure                          → 400 "invalid request"
//
// Internal audit log records the actual cause so SoC tooling still gets
// the signal it needs.
func (h *HandlersApi) LoginHandler(w http.ResponseWriter, r *http.Request) {
	// Never show the body in debug HTTP — it contains the password.
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	var l types.ApiLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&l); err != nil {
		apiErrorResponse(w, "invalid request", http.StatusBadRequest, err)
		return
	}
	// CheckLoginCredentials runs bcrypt against a dummyHash when the
	// user doesn't exist, so the timing of "no such user" matches the
	// timing of "wrong password" (pkg/users.dummyHash, closes the
	// username-enumeration timing leak — commit 0a598b79).
	access, user := h.Users.CheckLoginCredentials(l.Username, l.Password)
	if !access {
		h.AuditLog.FailedLogin(l.Username, utils.GetIP(r), "invalid credentials")
		apiErrorResponse(w, "invalid credentials", http.StatusForbidden, nil)
		return
	}
	// Decide whether to reuse the stored token or mint a fresh one.
	// Re-issue when there's no token, when the stored token has already
	// expired (the reuse path used to return 500 "token already expired"
	// — a regression that locked users out after their first session
	// expired), or when the stored token is within 60s of expiring so we
	// don't hand out something that will fail mid-request.
	var (
		tokenExp time.Time
		err      error
	)
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
	// Persist the CSRF token alongside the user so the auth middleware
	// can verify subsequent X-CSRF-Token headers. Without this write the
	// SPA's double-submit pattern is purely cosmetic.
	// IP comes from utils.GetIP so it matches the format every other
	// site writes to last_ip_address (clean IP, X-Real-IP /
	// X-Forwarded-For aware).
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
	// Set the httpOnly session cookie. The SPA reads the JWT via the
	// cookie; it never needs to access this cookie from JS.
	//
	// Secure: true requires HTTPS. If TLS is terminated at a proxy that
	// speaks plain HTTP to this service, set Secure:false in the proxy's
	// cookie rewrite rule — do not add an --insecure-cookies flag to keep
	// the surface small.
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
	// Token stays in the body for backward compat with CLI consumers
	// that do not use cookies.
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiLoginResponse{
		Token:     user.APIToken,
		CSRFToken: csrfToken,
	})
}
