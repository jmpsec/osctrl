package handlers

import (
	"context"
	"errors"
	"net/http"

	"github.com/jmpsec/osctrl/pkg/auth"
	authsaml "github.com/jmpsec/osctrl/pkg/auth/saml"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

// samlProvider holds the global SAML provider for osctrl-api. nil until
// InitSAML succeeds at startup; when nil, every SAML route short-circuits
// to 503 so a misconfigured deploy fails closed.
//
// Package-global to match oidcProvider's style (auth_oidc.go). Set once
// at startup, never written thereafter — concurrent reads from request
// handlers are safe without a mutex.
var samlProvider *authsaml.Provider

// samlJITProvision mirrors the config flag at InitSAML time so the
// request hot-path doesn't reach back into the Config struct.
//
// samlLogoutURL is the IdP's generic session-termination endpoint
// (e.g. Auth0's /v2/logout). When set, the logout handler returns it
// for SAML-session users so the SPA can navigate the browser there
// and kill the IdP session — preventing silent re-auth on the next
// "Continue with SSO" click.
var (
	samlJITProvision bool
	samlLogoutURL    string
)

// InitSAML constructs the global SAML provider for osctrl-api from the
// YAML/CLI config. Returns a non-nil error on:
//
//   - Config.Validate failure (missing metadata, required fields, etc.)
//   - SAML metadata fetch / parse failure
//
// The caller (cmd/api/main.go) treats any error as fatal during
// startup — loud failures over silent broken-SSO.
//
// Username sanitization defaults to STRICT for cmd/api (no
// LegacyPermissiveUsername shim). osctrl-api is greenfield; no
// pre-existing email-format usernames to preserve.
func InitSAML(ctx context.Context, cfg config.YAMLConfigurationSAML, entityID, acsURL string) error {
	p, err := authsaml.NewSAMLProvider(ctx, authsaml.Config{
		IDPMetadataURL:         cfg.MetaDataURL,
		EntityID:               entityID,
		ACSURL:                 acsURL,
		UsernameAttribute:      cfg.UsernameAttribute,
		JITProvision:           cfg.JITProvision,
		ForceAuthn:             cfg.ForceAuthn,
		SigningCertPath:        cfg.SigningCertPath,
		SigningKeyPath:         cfg.SigningKeyPath,
		RequireAssertionSigned: true,
	})
	if err != nil {
		return err
	}
	samlProvider = p
	samlJITProvision = cfg.JITProvision
	samlLogoutURL = cfg.LogoutURL
	return nil
}

// SAMLLoginHandler — GET /api/v1/auth/saml/login.
//
// Starts the SAML SP-initiated SSO flow:
//
//  1. Mint a fresh 256-bit nonce + OAuthState (defense-in-depth split,
//     same shape as the OIDC handler).
//  2. Issue the state JWT cookie (Path=/api/v1/auth/, HttpOnly, Secure,
//     SameSite=Lax, 10-minute TTL).
//  3. Build the IdP SSO URL with RelayState=<OAuthState>. The IdP
//     echoes RelayState verbatim on the ACS POST; SAMLACSHandler
//     validates the echo against the state cookie.
//  4. 302-redirect the browser to the IdP.
//
// Unauthenticated by design: the user is logging IN. The state cookie
// is the only thing tying the eventual ACS POST back to this request.
//
// EnvUUID on the State is a fixed sentinel ("api") because osctrl-api
// is single-tenant for federated login. Matches the OIDC handler's
// posture.
func (h *HandlersApi) SAMLLoginHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	if samlProvider == nil {
		apiErrorResponse(w, "saml not configured", http.StatusServiceUnavailable, nil)
		return
	}
	if len(h.JWTSecret) == 0 {
		apiErrorResponse(w, "saml state secret missing", http.StatusInternalServerError, errors.New("HandlersApi.JWTSecret is empty"))
		return
	}
	nonce, err := auth.NewNonce()
	if err != nil {
		apiErrorResponse(w, "saml nonce error", http.StatusInternalServerError, err)
		return
	}
	oauthState, err := auth.NewNonce()
	if err != nil {
		apiErrorResponse(w, "saml state error", http.StatusInternalServerError, err)
		return
	}
	state := auth.State{
		EnvUUID:    "api",
		Nonce:      nonce,
		OAuthState: oauthState,
	}
	// Build the IdP URL FIRST so we can capture the AuthnRequest ID;
	// then issue the cookie with that ID baked in. The ID rides back
	// via state.SAMLRequestID on the ACS POST so ParseResponse can
	// match InResponseTo against it (threat S7).
	loginURL, requestID, err := samlProvider.LoginURLWithRequestID(state)
	if err != nil {
		apiErrorResponse(w, "saml login url error", http.StatusInternalServerError, err)
		return
	}
	state.SAMLRequestID = requestID
	if err := auth.IssueStateCookie(w, h.JWTSecret, state); err != nil {
		apiErrorResponse(w, "saml state cookie error", http.StatusInternalServerError, err)
		return
	}
	http.Redirect(w, r, loginURL, http.StatusFound)
}

// SAMLACSHandler — POST /api/v1/auth/saml/acs.
//
// Consumes the IdP's signed SAMLResponse POST:
//
//  1. Parse + verify the state JWT cookie (audience, expiry, signature).
//  2. Clear the state cookie immediately — single-use semantics.
//  3. Run Provider.HandleCallback (RelayState match, signature, audience,
//     NotBefore/NotOnOrAfter, recipient, InResponseTo, replay cache,
//     groups gate, username sanitization).
//  4. Resolve the identity to an AdminUser (existing row or JIT
//     provision per samlJITProvision).
//  5. Mint user JWT + CSRF cookies via userJWTSessionTokens.
//  6. 302-redirect to "/" — the SPA root takes over.
//
// Failure paths redirect to "/" too (no error param leak). Server-side
// log records WHY; client sees a generic outcome. Timing-oracle defense
// matches the OIDC handler.
func (h *HandlersApi) SAMLACSHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	if samlProvider == nil {
		apiErrorResponse(w, "saml not configured", http.StatusServiceUnavailable, nil)
		return
	}
	if len(h.JWTSecret) == 0 {
		apiErrorResponse(w, "saml state secret missing", http.StatusInternalServerError, errors.New("HandlersApi.JWTSecret is empty"))
		return
	}
	state, err := auth.ParseStateCookie(r, h.JWTSecret)
	if err != nil {
		log.Warn().Err(err).Msg("saml: state cookie missing or invalid")
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	auth.ClearStateCookie(w)

	identity, err := samlProvider.HandleCallback(r.Context(), r, state)
	if err != nil {
		// crewjam ParseResponse errors can include attacker-controlled
		// text from the assertion (audit-log poisoning); keep them
		// at WARN level and never echo to the client.
		log.Warn().Err(err).Msg("saml: ACS callback rejected")
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	user, err := h.resolveFederatedUser(identity, samlJITProvision, auth.TypeSAML)
	if err != nil {
		log.Warn().Err(err).Str("preferred_username", identity.PreferredUsername).Msg("saml: user resolution failed")
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if _, err := h.userJWTSessionTokens(w, user, 0, utils.GetIP(r), r.UserAgent()); err != nil {
		// userJWTSessionTokens has already written an apiErrorResponse.
		return
	}

	if h.AuditLog != nil {
		h.AuditLog.NewLogin(user.Username, utils.GetIP(r))
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// SAMLMetadataHandler — GET /api/v1/auth/saml/metadata.
//
// Serves the SP metadata XML for IdP-side registration. The IdP
// administrator points their config at this URL (or downloads the XML
// and uploads it) so the IdP knows our EntityID + ACS URL + supported
// NameID formats.
//
// Public by design — SP metadata is meant to be machine-readable by
// anyone who wants to federate with us. The information it carries is
// the same information the IdP would learn via the AuthnRequest URL
// during the first login attempt.
//
// Rate-limited at the route layer like the other unauth endpoints.
func (h *HandlersApi) SAMLMetadataHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	if samlProvider == nil {
		apiErrorResponse(w, "saml not configured", http.StatusServiceUnavailable, nil)
		return
	}
	md, err := samlProvider.Metadata()
	if err != nil {
		apiErrorResponse(w, "saml metadata error", http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	_, _ = w.Write(md)
}
