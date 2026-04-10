package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/securecookie"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

const (
	defaultOIDCUsernameClaim = "preferred_username"
	oidcCallbackPath         = "/oidc/callback"
	oidcStateCookieName      = "osctrl-admin-oidc-state"
	oidcStateCookieTTL       = 10 * time.Minute
)

type oidcRuntime struct {
	provider *gooidc.Provider
	verifier *gooidc.IDTokenVerifier
	oauth2   *oauth2.Config
	cfg      config.YAMLConfigurationOIDC
}

type idTokenClaims struct {
	Subject           string `json:"sub"`
	PreferredUsername string `json:"preferred_username"`
	Email             string `json:"email"`
	Name              string `json:"name"`
	GivenName         string `json:"given_name"`
	FamilyName        string `json:"family_name"`
}

func initOIDC(ctx context.Context, cfg config.YAMLConfigurationOIDC) (*oidcRuntime, error) {
	if cfg.IssuerURL == "" {
		return nil, errors.New("oidc: issuerUrl is required")
	}
	if cfg.ClientID == "" {
		return nil, errors.New("oidc: clientId is required")
	}
	if cfg.ClientSecret == "" && !cfg.UsePKCE {
		return nil, errors.New("oidc: clientSecret is required when PKCE is disabled")
	}
	if cfg.RedirectURL == "" {
		return nil, errors.New("oidc: redirectUrl is required")
	}
	provider, err := gooidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery failed for %s: %w", cfg.IssuerURL, err)
	}
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{gooidc.ScopeOpenID, "profile", "email"}
	} else if !slices.Contains(scopes, gooidc.ScopeOpenID) {
		scopes = append([]string{gooidc.ScopeOpenID}, scopes...)
	}
	return &oidcRuntime{
		provider: provider,
		verifier: provider.Verifier(&gooidc.Config{ClientID: cfg.ClientID}),
		oauth2: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.RedirectURL,
			Scopes:       scopes,
		},
		cfg: cfg,
	}, nil
}

// oidcLoginHandler kicks off the Authorization Code flow by redirecting to the IdP.
func oidcLoginHandler(w http.ResponseWriter, r *http.Request) {
	if oidcRT == nil {
		http.Error(w, "oidc not initialized", http.StatusInternalServerError)
		return
	}
	state, err := randomToken()
	if err != nil {
		log.Err(err).Msg("oidc: failed to generate state")
		http.Error(w, "oidc state error", http.StatusInternalServerError)
		return
	}
	nonce, err := randomToken()
	if err != nil {
		log.Err(err).Msg("oidc: failed to generate nonce")
		http.Error(w, "oidc nonce error", http.StatusInternalServerError)
		return
	}
	var verifier string
	if oidcRT.cfg.UsePKCE {
		verifier, err = randomToken()
		if err != nil {
			log.Err(err).Msg("oidc: failed to generate pkce verifier")
			http.Error(w, "oidc pkce error", http.StatusInternalServerError)
			return
		}
	}
	if err := setOIDCStateCookie(w, state, nonce, verifier); err != nil {
		log.Err(err).Msg("oidc: failed to encode state cookie")
		http.Error(w, "oidc state error", http.StatusInternalServerError)
		return
	}
	opts := []oauth2.AuthCodeOption{gooidc.Nonce(nonce)}
	if verifier != "" {
		opts = append(opts, oauth2.S256ChallengeOption(verifier))
	}
	http.Redirect(w, r, oidcRT.oauth2.AuthCodeURL(state, opts...), http.StatusFound)
}

// oidcCallbackHandler validates the callback, exchanges the code for tokens,
// verifies the ID token, JIT-provisions the user if needed, and creates an
// osctrl session cookie.
func oidcCallbackHandler(w http.ResponseWriter, r *http.Request) {
	if oidcRT == nil {
		http.Error(w, "oidc not initialized", http.StatusInternalServerError)
		return
	}
	expectedState, expectedNonce, verifier, err := readOIDCStateCookie(r)
	if err != nil {
		log.Err(err).Msg("oidc: state cookie missing or invalid")
		http.Redirect(w, r, forbiddenPath, http.StatusFound)
		return
	}
	if oidcRT.cfg.UsePKCE && verifier == "" {
		log.Error().Msg("oidc: pkce enabled but no verifier in state cookie")
		http.Redirect(w, r, forbiddenPath, http.StatusFound)
		return
	}
	clearOIDCStateCookie(w)
	if r.URL.Query().Get("state") != expectedState {
		log.Error().Msg("oidc: state mismatch")
		http.Redirect(w, r, forbiddenPath, http.StatusFound)
		return
	}
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		log.Error().Msgf("oidc: idp returned error %s: %s", errParam, r.URL.Query().Get("error_description"))
		http.Redirect(w, r, forbiddenPath, http.StatusFound)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		log.Error().Msg("oidc: missing authorization code")
		http.Redirect(w, r, forbiddenPath, http.StatusFound)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	var exchangeOpts []oauth2.AuthCodeOption
	if verifier != "" {
		exchangeOpts = append(exchangeOpts, oauth2.VerifierOption(verifier))
	}
	token, err := oidcRT.oauth2.Exchange(ctx, code, exchangeOpts...)
	if err != nil {
		log.Err(err).Msg("oidc: code exchange failed")
		http.Redirect(w, r, forbiddenPath, http.StatusFound)
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		log.Error().Msg("oidc: id_token missing from token response")
		http.Redirect(w, r, forbiddenPath, http.StatusFound)
		return
	}
	idToken, err := oidcRT.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		log.Err(err).Msg("oidc: id_token verification failed")
		http.Redirect(w, r, forbiddenPath, http.StatusFound)
		return
	}
	if idToken.Nonce != expectedNonce {
		log.Error().Msg("oidc: nonce mismatch")
		http.Redirect(w, r, forbiddenPath, http.StatusFound)
		return
	}
	var claims idTokenClaims
	if err := idToken.Claims(&claims); err != nil {
		log.Err(err).Msg("oidc: failed to decode claims")
		http.Redirect(w, r, forbiddenPath, http.StatusFound)
		return
	}
	if len(oidcRT.cfg.RequiredGroups) > 0 {
		if !hasRequiredGroup(idToken, oidcRT.cfg) {
			log.Error().Msg("oidc: user does not belong to any required group")
			http.Redirect(w, r, forbiddenPath, http.StatusFound)
			return
		}
	}
	username := pickUsername(claims, oidcRT.cfg)
	if username == "" {
		log.Error().Msg("oidc: no username claim available on id_token")
		http.Redirect(w, r, forbiddenPath, http.StatusFound)
		return
	}
	fullname := claims.Name
	if fullname == "" {
		fullname = strings.TrimSpace(claims.GivenName + " " + claims.FamilyName)
	}
	user, err := resolveOIDCUser(username, claims.Email, fullname)
	if err != nil {
		log.Err(err).Msgf("oidc: cannot resolve user %s", username)
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

// oidcLogoutHandler clears the osctrl session and redirects to /login.
func oidcLogoutHandler(w http.ResponseWriter, r *http.Request) {
	username := ""
	if _, s := sessionsmgr.CheckAuth(r); s.Username != "" {
		username = s.Username
	}
	if err := sessionsmgr.Destroy(r); err != nil {
		log.Err(err).Msg("oidc: error destroying session")
	}
	if auditLog != nil && username != "" {
		auditLog.NewLogout(username, utils.GetIP(r))
	}
	http.Redirect(w, r, loginPath, http.StatusFound)
}

// resolveOIDCUser returns the existing user or JIT-provisions a new non-admin
// user (parity with SAML).
func resolveOIDCUser(username, email, fullname string) (users.AdminUser, error) {
	if exists, existing := adminUsers.ExistsGet(username); exists {
		return existing, nil
	}
	if !oidcRT.cfg.JITProvision {
		return users.AdminUser{}, fmt.Errorf("user %s not provisioned and jitProvision disabled", username)
	}
	u, err := adminUsers.New(username, "", email, fullname, false, false)
	if err != nil {
		return users.AdminUser{}, fmt.Errorf("new user: %w", err)
	}
	if err := adminUsers.Create(u); err != nil {
		return users.AdminUser{}, fmt.Errorf("create user: %w", err)
	}
	return u, nil
}

func hasRequiredGroup(idToken *gooidc.IDToken, cfg config.YAMLConfigurationOIDC) bool {
	claimName := cfg.GroupsClaim
	if claimName == "" {
		claimName = "groups"
	}
	var allClaims map[string]interface{}
	if err := idToken.Claims(&allClaims); err != nil {
		log.Err(err).Msg("oidc: failed to decode claims for group check")
		return false
	}
	raw, ok := allClaims[claimName]
	if !ok {
		log.Error().Msgf("oidc: groups claim %q not present in id_token", claimName)
		return false
	}
	groups, ok := raw.([]interface{})
	if !ok {
		log.Error().Msgf("oidc: groups claim %q is not an array", claimName)
		return false
	}
	for _, g := range groups {
		name, ok := g.(string)
		if !ok {
			continue
		}
		if slices.Contains(cfg.RequiredGroups, name) {
			return true
		}
	}
	return false
}

func pickUsername(c idTokenClaims, cfg config.YAMLConfigurationOIDC) string {
	claim := strings.ToLower(strings.TrimSpace(cfg.UsernameClaim))
	if claim == "" {
		claim = defaultOIDCUsernameClaim
	}
	switch claim {
	case defaultOIDCUsernameClaim:
		if c.PreferredUsername != "" {
			return c.PreferredUsername
		}
	case "email":
		if c.Email != "" {
			return c.Email
		}
	case "sub":
		return c.Subject
	}
	return c.Subject
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func setOIDCStateCookie(w http.ResponseWriter, state, nonce, verifier string) error {
	if sessionsmgr == nil || len(sessionsmgr.Codecs) == 0 {
		return errors.New("session manager not initialized")
	}
	payload := map[string]string{"state": state, "nonce": nonce}
	if verifier != "" {
		payload["verifier"] = verifier
	}
	encoded, err := securecookie.EncodeMulti(oidcStateCookieName, payload, sessionsmgr.Codecs...)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookieName,
		Value:    encoded,
		Path:     "/",
		MaxAge:   int(oidcStateCookieTTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func readOIDCStateCookie(r *http.Request) (state, nonce, verifier string, err error) {
	c, err := r.Cookie(oidcStateCookieName)
	if err != nil {
		return "", "", "", err
	}
	if sessionsmgr == nil || len(sessionsmgr.Codecs) == 0 {
		return "", "", "", errors.New("session manager not initialized")
	}
	var payload map[string]string
	if err := securecookie.DecodeMulti(oidcStateCookieName, c.Value, &payload, sessionsmgr.Codecs...); err != nil {
		return "", "", "", err
	}
	state, ok1 := payload["state"]
	nonce, ok2 := payload["nonce"]
	if !ok1 || !ok2 {
		return "", "", "", errors.New("oidc: state cookie missing fields")
	}
	return state, nonce, payload["verifier"], nil
}

func clearOIDCStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}
