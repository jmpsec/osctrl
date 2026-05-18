package handlers

import (
	"net/http"

	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

// LogoutResponse is the JSON payload returned by POST /api/v1/logout.
//
// AuthSource carries which provider issued the active session
// ("oidc" / "saml" / ""). The SPA uses it to decide which
// IdP-logout flow to run — sending a SAML user to the OIDC
// end-session URL with a stale id_token_hint just produces a
// confusing Keycloak error page.
//
// IdPLogoutURL is non-empty when AuthSource=="oidc" AND the OIDC
// provider advertised an end_session_endpoint in its discovery
// document — the SPA navigates the browser there to terminate the
// IdP session. Empty for SAML users (SLO deferred to v2 per spec)
// and for password users.
//
// IdPClientID is the OIDC client_id registered with the IdP. Some
// IdPs (Keycloak) accept it as an alternative to id_token_hint
// when the operator chains post_logout_redirect_uri. The SPA
// appends it as ?client_id=...
//
// IdPIDTokenHint is the raw id_token from the user's most recent
// federated login. Okta REQUIRES this on /v1/logout when chaining a
// post-logout redirect; without it Okta returns "Missing parameter:
// id_token_hint". Non-empty when the osctrl_id_token cookie was
// present and valid; empty for password-only operators or after a
// fresh login from a cookie-stripped browser. The SPA appends it
// as ?id_token_hint=... — the IdP verifies the token's signature
// before terminating the session, so this is safe to expose to the
// browser (we set it back into the URL the browser navigates to).
type LogoutResponse struct {
	AuthSource     string `json:"auth_source,omitempty"`
	IdPLogoutURL   string `json:"idp_logout_url,omitempty"`
	IdPClientID    string `json:"idp_client_id,omitempty"`
	IdPIDTokenHint string `json:"idp_id_token_hint,omitempty"`
}

// LogoutHandler — POST /api/v1/logout.
//
// Three-tier teardown:
//
//  1. Clear osctrl_token + osctrl_csrf cookies on the response
//     (Max-Age=0 expires them immediately client-side).
//
//  2. Clear the user's APIToken in the DB so any cached copy of the
//     JWT — including the same JWT in another browser tab — fails
//     the handlerAuthCheck APIToken-match guard on its next request.
//     This is the server-side revocation half: cookie expiry alone
//     is client-honor-system; APIToken=="" turns the token into a
//     no-op even if the bytes are reused.
//
//  3. Return the IdP's end_session_endpoint URL so the SPA can
//     navigate to it. Keycloak's logout page in turn redirects the
//     browser to post_logout_redirect_uri (here, the SPA's /login
//     route). Without this step, the next "Continue with SSO" would
//     silently re-auth against the still-valid IdP session cookie
//     and the user would never see a credential prompt.
//
// Idempotent: a request with no auth context (already-logged-out
// user) still emits cookie-clearing headers and an end-session URL,
// returns 200. We do not gate the endpoint behind handlerAuthCheck
// for this reason — logging out from an expired session should not
// require a fresh login first.
//
// Username derivation: pulled from the in-memory CSRF cookie pair
// rather than re-parsing the JWT. The osctrl_token cookie + the
// stored APIToken match each other in handlerAuthCheck; here we
// trust the token cookie at face value because the worst case is
// "someone forged a logout request" — the only consequence is
// invalidating the legitimate user's token, which is exactly what
// logout is supposed to do. No privilege gain.
func (h *HandlersApi) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}

	// Best-effort APIToken revocation. We have to recover the
	// username; the cleanest source is the JWT cookie. authenticated
	// is set true when the caller presented a syntactically-valid
	// JWT — we use it below to decide whether to surface the IdP
	// fields. Anonymous callers (no/invalid token) get an empty
	// LogoutResponse so a drive-by curl cannot scrape the IdP
	// tenant URL + client_id without an actual session to terminate
	// (pentest finding: unauthenticated IdP metadata disclosure).
	//
	// userAuthSource carries the value of AdminUser.AuthSource — set
	// to "oidc" or "saml" by JIT-provisioning, empty for password-
	// auth users. We use it below to pick the right IdP-side logout
	// flow (or skip it entirely for password users) so we don't send
	// a SAML user to the OIDC end-session URL with a stale
	// id_token_hint.
	var (
		authenticated  bool
		userAuthSource string
	)
	tokenCookie, err := r.Cookie("osctrl_token")
	if err == nil && tokenCookie.Value != "" && len(h.JWTSecret) > 0 {
		claims, valid := h.Users.CheckToken(string(h.JWTSecret), tokenCookie.Value)
		if valid {
			authenticated = true
			if exists, u := h.Users.ExistsGet(claims.Username); exists {
				userAuthSource = u.AuthSource
			}
			if cerr := h.Users.ClearToken(claims.Username); cerr != nil {
				// Non-fatal — we still want to clear the
				// client-side cookies and return the IdP URL.
				log.Warn().Err(cerr).Str("user", claims.Username).Msg("logout: ClearToken failed")
			}
		}
	}

	// Clear both cookies. Server-issued Set-Cookie with Max-Age=0 is
	// the only way to nuke an HttpOnly cookie (osctrl_token).
	http.SetCookie(w, &http.Cookie{
		Name:     "osctrl_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "osctrl_csrf",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: false,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	// Read + clear the osctrl_id_token cookie (set at OIDC callback).
	// We surface its value as id_token_hint in the response so the
	// SPA can pass it to the IdP's /logout endpoint. Cookie is
	// HttpOnly so only the server can read or expire it; the value
	// IS the same token the IdP issued, so handing it back to the
	// browser doesn't leak anything the IdP doesn't already
	// honor.
	var idTokenHint string
	if idTokenCookie, ierr := r.Cookie("osctrl_id_token"); ierr == nil {
		idTokenHint = idTokenCookie.Value
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "osctrl_id_token",
		Value:    "",
		Path:     "/api/v1/auth/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	// Surface IdP fields based on which provider issued the current
	// session. Anonymous callers always get the empty response
	// (pentest finding T-IDP-DISCLOSURE: no IdP scrape without auth).
	//
	// OIDC users → emit the OIDC end-session URL, client_id, and
	//   id_token_hint so the SPA can chain a clean RP-initiated
	//   logout that also terminates the Keycloak/Auth0 SP session.
	// SAML users → emit auth_source="saml" so the SPA knows to skip
	//   the IdP-side logout and just bounce to /login. SAML SLO is
	//   deferred to v2 per docs/proposals/osctrl-auth-providers-v0.1
	//   §"What's deferred"; sending a SAML user to the OIDC
	//   end-session URL with a stale (or wrong-protocol) id_token_hint
	//   was the symptom that surfaced this bug — Keycloak rejects
	//   the request and the user lands on an error page.
	// Password users → empty response, SPA bounces to /login.
	resp := LogoutResponse{}
	if authenticated {
		resp.AuthSource = userAuthSource
		if userAuthSource == "oidc" && oidcProvider != nil {
			resp.IdPLogoutURL = oidcProvider.EndSessionURL()
			resp.IdPClientID = oidcClientID
			resp.IdPIDTokenHint = idTokenHint
		}
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, resp)
}
