package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/jmpsec/osctrl/pkg/auth"
	authoidc "github.com/jmpsec/osctrl/pkg/auth/oidc"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

// oidcCallbackPath is the legacy admin's callback URL. The path is
// retained verbatim so existing IdP registrations don't break across
// the refactor.
const oidcCallbackPath = "/oidc/callback"

// oidcProvider is the legacy admin's OIDC provider, constructed once
// at startup from the YAML config. nil when --auth != "oidc".
//
// Kept as a package-global to match the existing admin code's style
// (sessionsmgr, oidcRT, etc. are all package-globals). New code should
// avoid this pattern, but the refactor's goal is "zero behavior
// change," not "redesign admin."
var oidcProvider *authoidc.Provider

// oidcStateSecret is the HMAC key used to sign state cookies. We use
// flagParams.Admin.SessionKey rather than introducing a new field;
// the audience claim segregates state JWTs from user-auth JWTs so
// sharing the underlying secret is safe (threat T19).
//
// Cached at init time to avoid reaching into flagParams on every
// request.
var oidcStateSecret []byte

// fromYAMLConfig translates the legacy YAML config struct into the
// provider-agnostic authoidc.Config. Centralized here so cmd/admin
// stays the only translator; cmd/api uses its own translator off a
// DB row.
//
// LegacyPermissiveUsername is set to true: existing osctrl-admin
// operators may have pre-existing AdminUser rows whose usernames
// contain `.`, `@`, or spaces because their IdP emits
// `preferred_username` as an email. The pre-refactor cmd/admin code
// did no character-class validation on OIDC usernames, so deployments
// in the wild rely on that behavior. cmd/api gets the stricter
// default; this shim is for legacy admin only.
func fromYAMLConfig(c config.YAMLConfigurationOIDC) authoidc.Config {
	return authoidc.Config{
		IssuerURL:                c.IssuerURL,
		ClientID:                 c.ClientID,
		ClientSecret:             c.ClientSecret,
		RedirectURL:              c.RedirectURL,
		Scopes:                   c.Scopes,
		UsernameClaim:            c.UsernameClaim,
		GroupsClaim:              c.GroupsClaim,
		RequiredGroups:           c.RequiredGroups,
		JITProvision:             c.JITProvision,
		UsePKCE:                  c.UsePKCE,
		LegacyPermissiveUsername: true,
	}
}

// initOIDC bootstraps the OIDC provider for legacy admin. Matches the
// pre-refactor signature so cmd/admin/main.go's call site doesn't
// need to change.
func initOIDC(ctx context.Context, cfg config.YAMLConfigurationOIDC) error {
	prov, err := authoidc.NewOIDCProvider(ctx, fromYAMLConfig(cfg))
	if err != nil {
		return err
	}
	oidcProvider = prov
	oidcStateSecret = []byte(flagParams.Admin.SessionKey)
	if len(oidcStateSecret) == 0 {
		return errors.New("oidc: flagParams.Admin.SessionKey is empty — required for state-cookie signing")
	}
	return nil
}

// oidcLoginHandler kicks off the Authorization Code flow. Issues the
// state cookie, then redirects the browser to the IdP's authorize
// endpoint.
//
// Legacy admin runs as a single-tenant binary, so the EnvUUID claim
// on the state cookie is a constant placeholder ("admin"). cmd/api's
// version pulls the env from the URL.
func oidcLoginHandler(w http.ResponseWriter, r *http.Request) {
	if oidcProvider == nil {
		http.Error(w, "oidc not initialized", http.StatusInternalServerError)
		return
	}
	nonce, err := auth.NewNonce()
	if err != nil {
		log.Err(err).Msg("oidc: nonce gen failed")
		http.Error(w, "oidc nonce error", http.StatusInternalServerError)
		return
	}
	// Independent random value for the OAuth2 `state` parameter
	// (defense-in-depth split — May 2026 pentest finding).
	oauthState, err := auth.NewNonce()
	if err != nil {
		log.Err(err).Msg("oidc: state gen failed")
		http.Error(w, "oidc state error", http.StatusInternalServerError)
		return
	}
	state := auth.State{
		EnvUUID:    "admin", // legacy admin is single-tenant; no env scoping
		Nonce:      nonce,
		OAuthState: oauthState,
	}
	if oidcProvider != nil && shouldUsePKCE() {
		verifier, err := auth.NewNonce()
		if err != nil {
			log.Err(err).Msg("oidc: pkce verifier gen failed")
			http.Error(w, "oidc pkce error", http.StatusInternalServerError)
			return
		}
		state.Verifier = verifier
	}
	if err := auth.IssueStateCookie(w, oidcStateSecret, state); err != nil {
		log.Err(err).Msg("oidc: state cookie issue failed")
		http.Error(w, "oidc state error", http.StatusInternalServerError)
		return
	}
	url, err := oidcProvider.LoginURL(r.Context(), state)
	if err != nil {
		log.Err(err).Msg("oidc: LoginURL failed")
		http.Error(w, "oidc login url error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, url, http.StatusFound)
}

// shouldUsePKCE peeks at the configured Config to decide whether to
// generate a PKCE verifier. The provider's HandleCallback already
// rejects mismatched PKCE state, so this is a UX correctness signal
// rather than a security one.
//
// We keep it as a separate function so the test suite can override
// the behavior if needed; today it just reflects the config.
func shouldUsePKCE() bool {
	// We have no public accessor on Provider for the config; the
	// boolean is the same one the caller set in fromYAMLConfig.
	// Re-read it from flagParams (single source of truth).
	if flagParams == nil || flagParams.OIDC == nil {
		return false
	}
	return flagParams.OIDC.UsePKCE
}

// oidcCallbackHandler consumes the callback URL, runs the provider's
// HandleCallback, then performs the legacy admin's user-resolve +
// session-create + audit-log steps.
//
// All redirect targets on failure are the existing forbiddenPath
// (legacy admin's standard error page). No information about WHY the
// auth failed leaks to the client (timing-oracle defense, threat T31).
func oidcCallbackHandler(w http.ResponseWriter, r *http.Request) {
	if oidcProvider == nil {
		http.Error(w, "oidc not initialized", http.StatusInternalServerError)
		return
	}
	state, err := auth.ParseStateCookie(r, oidcStateSecret)
	if err != nil {
		log.Err(err).Msg("oidc: state cookie missing or invalid")
		http.Redirect(w, r, forbiddenPath, http.StatusFound)
		return
	}
	// Clear the cookie immediately — single-use state (threat T9).
	auth.ClearStateCookie(w)

	identity, err := oidcProvider.HandleCallback(r.Context(), r, state)
	if err != nil {
		// Log the specific failure server-side. We log the
		// sentinel type rather than the wrapped IdP error string
		// because the latter can contain attacker-controlled
		// text (threat T26).
		log.Err(err).Msg("oidc: callback rejected")
		http.Redirect(w, r, forbiddenPath, http.StatusFound)
		return
	}

	user, err := resolveOIDCUser(identity)
	if err != nil {
		log.Err(err).Msgf("oidc: cannot resolve user %s", identity.PreferredUsername)
		http.Redirect(w, r, forbiddenPath, http.StatusFound)
		return
	}
	if _, err := sessionsmgr.Save(r, w, user); err != nil {
		log.Err(err).Msg("oidc: session save error")
		http.Redirect(w, r, forbiddenPath, http.StatusFound)
		return
	}
	if auditLog != nil {
		auditLog.NewLogin(user.Username, utils.GetIP(r))
	}
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// resolveOIDCUser returns the existing AdminUser or JIT-provisions a
// new non-admin user. Matches the legacy admin's pre-refactor policy
// exactly: lookup by username; on miss, create with no permissions
// if JITProvision is enabled; reject otherwise. Threat T16, T25.
func resolveOIDCUser(identity auth.ResolvedIdentity) (users.AdminUser, error) {
	if exists, existing := adminUsers.ExistsGet(identity.PreferredUsername); exists {
		if existing.AuthSource != "" && existing.AuthSource != "oidc" {
			return users.AdminUser{}, fmt.Errorf("username %q belongs to auth source %q, not oidc", identity.PreferredUsername, existing.AuthSource)
		}
		if existing.AuthSource == "" {
			return users.AdminUser{}, fmt.Errorf("username %q is a local account and cannot be claimed by federated login", identity.PreferredUsername)
		}
		return existing, nil
	}
	if flagParams == nil || flagParams.OIDC == nil || !flagParams.OIDC.JITProvision {
		return users.AdminUser{}, fmt.Errorf("user %s not provisioned and JITProvision disabled", identity.PreferredUsername)
	}
	// Compose display name from identity. The package-level
	// sanitizer already vetted PreferredUsername; Name/Email are
	// not used as identifiers and are stored as-is.
	u, err := adminUsers.New(identity.PreferredUsername, "", identity.Email, identity.Name, false, false)
	if err != nil {
		return users.AdminUser{}, fmt.Errorf("new user: %w", err)
	}
	u.AuthSource = "oidc"
	if err := adminUsers.Create(u); err != nil {
		return users.AdminUser{}, fmt.Errorf("create user: %w", err)
	}
	return u, nil
}
