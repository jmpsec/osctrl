package main

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/jmpsec/osctrl/cmd/api/handlers"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

const (
	// Key to identify request context
	contextAPI string = "osctrl-api-context"
)

// Cookie + header names — kept in sync with cmd/api/handlers/login.go.
const (
	cookieNameToken = "osctrl_token"
	cookieNameCSRF  = "osctrl_csrf"
	headerNameCSRF  = "X-CSRF-Token"
)

// Helper to extract token from the Authorization header first (CLI clients),
// falling back to the SPA's HttpOnly osctrl_token cookie.
func extractHeaderToken(r *http.Request) string {
	if v := r.Header.Get("Authorization"); v != "" {
		splitToken := strings.Split(v, "Bearer")
		if len(splitToken) == 2 {
			if t := strings.TrimSpace(splitToken[1]); t != "" {
				return t
			}
		}
	}
	if c, err := r.Cookie(cookieNameToken); err == nil {
		return strings.TrimSpace(c.Value)
	}
	return ""
}

// mutatingMethods is the set of HTTP verbs that must carry a valid CSRF token.
// GET/HEAD/OPTIONS are read-only and exempt.
var mutatingMethods = map[string]bool{
	http.MethodPost:   true,
	http.MethodPut:    true,
	http.MethodPatch:  true,
	http.MethodDelete: true,
}

// checkCSRF enforces the double-submit CSRF pattern on mutating requests.
// The SPA reads the non-HttpOnly osctrl_csrf cookie and echoes it via the
// X-CSRF-Token header on every mutation; we constant-time-compare:
//  1. header == cookie value (classic double-submit), AND
//  2. cookie value == AdminUser.CSRFToken (defeats a cookie-tossing
//     attacker who can set both header and cookie without DB write access).
//
// CLI clients that authenticate purely via Authorization: Bearer (no cookie)
// are exempt — there is no browser to ride a cross-site request from.
//
// Note: AdminUser.CSRFToken rotates on every successful /login (see
// LoginHandler ↦ Users.UpdateMetadata). Concurrent logins of the same user
// race; the loser keeps a cookie that no longer matches the stored value
// and gets 403 on the next mutation. APIToken refresh / clear also clear
// CSRFToken (see pkg/users.UpdateToken / ClearToken) so a stale CSRF
// cookie cannot outlive its session.
func checkCSRF(r *http.Request, username string) bool {
	// r.Cookie returns ErrNoCookie only when the cookie name is absent;
	// an empty-value cookie returns (cookie, nil). Treating the empty case
	// as "Bearer client" would bypass CSRF — instead, the call to
	// extractHeaderToken upstream rejects empty-value cookies before we
	// reach this function (the trimmed value falls through to "" return).
	if _, err := r.Cookie(cookieNameToken); err != nil {
		// No session cookie ⇒ Bearer-only client (CLI/CI). Nothing to CSRF.
		return true
	}
	headerToken := strings.TrimSpace(r.Header.Get(headerNameCSRF))
	cookie, err := r.Cookie(cookieNameCSRF)
	if err != nil || headerToken == "" {
		return false
	}
	cookieValue := strings.TrimSpace(cookie.Value)
	if subtle.ConstantTimeCompare([]byte(headerToken), []byte(cookieValue)) != 1 {
		return false
	}
	user, err := apiUsers.Get(username)
	if err != nil || user.CSRFToken == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookieValue), []byte(user.CSRFToken)) == 1
}

// Handler to check access to a resource based on the authentication enabled
func handlerAuthCheck(h http.Handler, auth, jwtSecret string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch auth {
		case config.AuthNone:
			// Set middleware values
			s := make(handlers.ContextValue)
			s["user"] = "admin"
			ctx := context.WithValue(r.Context(), handlers.ContextKey(contextAPI), s)
			// Access granted
			h.ServeHTTP(w, r.WithContext(ctx))
		case config.AuthJWT:
			// Set middleware values
			token := extractHeaderToken(r)
			if token == "" {
				if utils.AcceptsJSON(r) {
					utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusUnauthorized,
						types.ApiErrorResponse{Error: "unauthorized", Code: "unauthorized"})
					return
				}
				// 302 is required by http.Redirect; the legacy 403 didn't actually trigger
				// a redirect in any browser since http.Redirect demands a 3xx status.
				http.Redirect(w, r, forbiddenPath, http.StatusFound)
				return
			}
			claims, valid := apiUsers.CheckToken(jwtSecret, token)
			if !valid {
				if utils.AcceptsJSON(r) {
					utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusUnauthorized,
						types.ApiErrorResponse{Error: "unauthorized", Code: "unauthorized"})
					return
				}
				// 302 is required by http.Redirect; the legacy 403 didn't actually trigger
				// a redirect in any browser since http.Redirect demands a 3xx status.
				http.Redirect(w, r, forbiddenPath, http.StatusFound)
				return
			}
			// Match the presented token against the user's currently-stored APIToken
			// so that refresh/delete on /users/{username}/token invalidates old JWTs.
			// (CheckToken above only validates the signature.) Service users with no
			// stored token are rejected immediately. Constant-time comparison guards
			// against timing-side-channel leaks of the stored token.
			user, uerr := apiUsers.Get(claims.Username)
			tokenMatches := uerr == nil && user.APIToken != "" &&
				subtle.ConstantTimeCompare([]byte(user.APIToken), []byte(token)) == 1
			if !tokenMatches {
				if utils.AcceptsJSON(r) {
					utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusUnauthorized,
						types.ApiErrorResponse{Error: "unauthorized", Code: "unauthorized"})
					return
				}
				http.Redirect(w, r, forbiddenPath, http.StatusFound)
				return
			}
			// CSRF guard for cookie-authenticated mutating requests. CLI Bearer
			// clients are exempt via the cookieNameToken probe inside checkCSRF.
			//
			if mutatingMethods[r.Method] && !checkCSRF(r, claims.Username) {
				utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusForbidden,
					types.ApiErrorResponse{Error: "csrf token missing or invalid", Code: "csrf"})
				return
			}
			// Update metadata for the user
			if err := apiUsers.UpdateTokenIPAddress(utils.GetIP(r), claims.Username); err != nil {
				log.Err(err).Msgf("error updating token for user %s", claims.Username)
			}
			// Set middleware values
			s := make(handlers.ContextValue)
			s["user"] = claims.Username
			ctx := context.WithValue(r.Context(), handlers.ContextKey(contextAPI), s)
			// Access granted
			h.ServeHTTP(w, r.WithContext(ctx))
		}
	})
}
