package handlers

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jmpsec/osctrl/pkg/auth"
	authoidc "github.com/jmpsec/osctrl/pkg/auth/oidc"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

// oidcProvider holds the global OIDC provider for osctrl-api. nil
// until InitOIDC succeeds at startup; when nil, all OIDC routes
// short-circuit to 503 so a misconfigured deploy fails closed rather
// than silently accepting any login.
//
// Package-global to match cmd/admin/oidc.go's existing style. Set
// once at startup via InitOIDC; never written thereafter, so concurrent
// reads from request handlers are safe without a mutex.
var oidcProvider *authoidc.Provider

// oidcJITProvision and oidcUsePKCE mirror the config flags at the
// time InitOIDC runs. Held separately so the request hot-path never
// reaches back into the Config struct (which is by-value-copied into
// the Provider, with no public accessors).
//
// oidcClientID is the IdP-registered client_id; the logout flow
// echoes it back to the SPA so the browser can append it to the
// IdP's end-session URL (Keycloak 26+ requires it alongside
// post_logout_redirect_uri). Not a secret — it's already in every
// authorize URL the SPA renders.
var (
	oidcJITProvision bool
	oidcUsePKCE      bool
	oidcClientID     string
)

// InitOIDC constructs the global OIDC provider for osctrl-api from the
// YAML/CLI config. Returns a non-nil error on:
//
//   - Config.Validate failure (missing issuer, client id, etc.)
//   - OIDC discovery failure (IdP unreachable, malformed metadata)
//
// The caller (cmd/api/main.go) should treat any error as fatal during
// startup — we want loud failures so misconfigured deployments don't
// run silently with federated login broken.
//
// Username sanitization defaults to STRICT for cmd/api (no
// LegacyPermissiveUsername shim). osctrl-api is greenfield; we don't
// have pre-existing email-format usernames to preserve.
func InitOIDC(ctx context.Context, cfg config.YAMLConfigurationOIDC) error {
	p, err := authoidc.NewOIDCProvider(ctx, authoidc.Config{
		IssuerURL:      cfg.IssuerURL,
		ClientID:       cfg.ClientID,
		ClientSecret:   cfg.ClientSecret,
		RedirectURL:    cfg.RedirectURL,
		Scopes:         cfg.Scopes,
		UsernameClaim:  cfg.UsernameClaim,
		GroupsClaim:    cfg.GroupsClaim,
		RequiredGroups: cfg.RequiredGroups,
		JITProvision:   cfg.JITProvision,
		UsePKCE:        cfg.UsePKCE,
	})
	if err != nil {
		return err
	}
	oidcProvider = p
	oidcJITProvision = cfg.JITProvision
	oidcUsePKCE = cfg.UsePKCE
	oidcClientID = cfg.ClientID
	return nil
}

// OIDCLoginHandler — GET /api/v1/auth/oidc/login.
//
// Starts the Authorization Code flow:
//
//  1. Mint a fresh 256-bit nonce (and, if PKCE is enabled, a verifier).
//  2. Issue the state JWT cookie (Path=/api/v1/auth/, HttpOnly, Secure,
//     SameSite=Lax, 10-minute TTL).
//  3. Build the IdP authorize URL with state=<nonce>, nonce=<nonce>,
//     and (when PKCE on) code_challenge=S256(verifier).
//  4. 302-redirect the browser to the IdP.
//
// Unauthenticated: the user is logging IN, so they cannot have a
// session yet. The state cookie is the only thing tying the eventual
// callback back to this request.
//
// EnvUUID on the State is a fixed sentinel ("api") because osctrl-api
// has no per-env IdP concept — see auth-providers spec § "OIDC is
// global." The legacy admin uses "admin" for the same reason.
func (h *HandlersApi) OIDCLoginHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	if oidcProvider == nil {
		apiErrorResponse(w, "oidc not configured", http.StatusServiceUnavailable, nil)
		return
	}
	if len(h.JWTSecret) == 0 {
		apiErrorResponse(w, "oidc state secret missing", http.StatusInternalServerError, errors.New("HandlersApi.JWTSecret is empty"))
		return
	}
	nonce, err := auth.NewNonce()
	if err != nil {
		apiErrorResponse(w, "oidc nonce error", http.StatusInternalServerError, err)
		return
	}
	state := auth.State{
		EnvUUID: "api", // osctrl-api is single-tenant for OIDC; sentinel value only
		Nonce:   nonce,
	}
	if oidcUsePKCE {
		verifier, err := auth.NewNonce()
		if err != nil {
			apiErrorResponse(w, "oidc pkce error", http.StatusInternalServerError, err)
			return
		}
		state.Verifier = verifier
	}
	if err := auth.IssueStateCookie(w, h.JWTSecret, state); err != nil {
		apiErrorResponse(w, "oidc state cookie error", http.StatusInternalServerError, err)
		return
	}
	loginURL, err := oidcProvider.LoginURL(r.Context(), state)
	if err != nil {
		apiErrorResponse(w, "oidc login url error", http.StatusInternalServerError, err)
		return
	}
	http.Redirect(w, r, loginURL, http.StatusFound)
}

// OIDCCallbackHandler — GET /api/v1/auth/oidc/callback.
//
// Consumes the IdP's callback URL:
//
//  1. Parse + verify the state JWT cookie (audience, expiry, signature).
//  2. Clear the state cookie immediately — single-use semantics.
//  3. Run Provider.HandleCallback (the full 10-step verification chain
//     including signature, iss, aud, exp, nonce, group gate, username
//     sanitization).
//  4. Resolve the identity to an AdminUser (existing row or JIT
//     provision per oidcJITProvision).
//  5. Mint user JWT + CSRF cookies via userJWTSessionTokens.
//  6. 302-redirect to "/" — the SPA root takes over from there.
//
// All failure paths redirect to "/" too (no error param leak). The
// server-side log records WHY; the client gets a generic outcome.
// This is the timing-oracle defense (threat T31): every failure mode
// produces an indistinguishable client-visible response.
func (h *HandlersApi) OIDCCallbackHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	if oidcProvider == nil {
		apiErrorResponse(w, "oidc not configured", http.StatusServiceUnavailable, nil)
		return
	}
	if len(h.JWTSecret) == 0 {
		apiErrorResponse(w, "oidc state secret missing", http.StatusInternalServerError, errors.New("HandlersApi.JWTSecret is empty"))
		return
	}
	state, err := auth.ParseStateCookie(r, h.JWTSecret)
	if err != nil {
		log.Warn().Err(err).Msg("oidc: state cookie missing or invalid")
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	// Single-use: clear the cookie before anything else can fail.
	// If a later step rejects the callback, the user must restart
	// the flow from /login — preventing state cookie replay (T9).
	auth.ClearStateCookie(w)

	identity, err := oidcProvider.HandleCallback(r.Context(), r, state)
	if err != nil {
		// Log the sentinel error class; the wrapped IdP error string
		// may contain attacker-controlled text (audit-log poisoning
		// T26) and stays at WARN with the raw error.
		log.Warn().Err(err).Msg("oidc: callback rejected")
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	user, err := h.resolveFederatedUser(identity, oidcJITProvision)
	if err != nil {
		// resolveFederatedUser already wraps with ErrAuthUserRejected.
		log.Warn().Err(err).Str("preferred_username", identity.PreferredUsername).Msg("oidc: user resolution failed")
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// expHours=0 → use JWTConfig.HoursToExpire default.
	if _, err := h.userJWTSessionTokens(w, user, 0, utils.GetIP(r), r.UserAgent()); err != nil {
		// userJWTSessionTokens has already written an
		// apiErrorResponse on failure. Don't write again — but
		// note that the user is now in an undefined state (no
		// cookies, no redirect). 500 to the IdP redirect is the
		// honest answer.
		return
	}

	// Persist the raw id_token in an HttpOnly cookie so the logout
	// handler can return it as id_token_hint on RP-initiated
	// logout. Okta REQUIRES the hint on /v1/logout; Keycloak accepts
	// either id_token_hint OR client_id. Keeping the cookie HttpOnly
	// + Secure means JS can't read the IdP token — it travels only
	// browser→our /logout endpoint, never to the SPA's JS bundle.
	// Path=/api/v1/auth/ scopes it to auth endpoints, matching the
	// state cookie's scope.
	if identity.IDToken != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "osctrl_id_token",
			Value:    identity.IDToken,
			Path:     "/api/v1/auth/",
			MaxAge:   int(8 * time.Hour / time.Second),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})
	}

	if h.AuditLog != nil {
		h.AuditLog.NewLogin(user.Username, utils.GetIP(r))
	}
	http.Redirect(w, r, "/", http.StatusFound)
}
