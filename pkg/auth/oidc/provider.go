package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/jmpsec/osctrl/pkg/auth"
)

// httpExchangeTimeout caps how long the token endpoint exchange and
// id_token verification can take. Independent of any request-level
// context the caller passes — this is an upper bound applied
// regardless, to prevent a slow/malicious IdP from holding a
// connection open indefinitely.
const httpExchangeTimeout = 30 * time.Second

// Errors returned by HandleCallback. Callers map these to HTTP status
// codes. The strings are stable across versions; logging may use
// them, but client-facing responses should be a single generic
// "authentication failed" message (timing-oracle defense, threat T31).
var (
	// ErrStateMismatch covers any mismatch between the State the
	// caller transported (cookie) and the parameters the IdP
	// returned (query). Specifically, the OAuth2 state-param check
	// (T6, CSRF). The id_token nonce check has its own sentinel
	// (ErrNonceMismatch).
	ErrStateMismatch = errors.New("oidc: state mismatch")

	// ErrIdPError is returned when the IdP itself signaled an
	// error via the OAuth2 `error` query parameter on the
	// callback. Common values: access_denied, login_required.
	ErrIdPError = errors.New("oidc: identity provider returned error")

	// ErrTokenExchange wraps any failure during the
	// code-for-token exchange (network, IdP rejection, etc.).
	ErrTokenExchange = errors.New("oidc: token exchange failed")

	// ErrIDTokenVerify wraps verification failures (bad sig,
	// wrong iss/aud, expired, etc.). Threats T1–T5.
	ErrIDTokenVerify = errors.New("oidc: id_token verification failed")

	// ErrNonceMismatch is the specific id_token-vs-state nonce
	// failure (threat T1 narrow case). Distinguishable in logs;
	// callers still map to the same generic client response.
	ErrNonceMismatch = errors.New("oidc: nonce mismatch")

	// ErrGroupNotAllowed surfaces RequiredGroups-gate denials.
	// Threat T17.
	ErrGroupNotAllowed = errors.New("oidc: user not in required group")

	// ErrUsernameInvalid is returned when the resolved username
	// contains characters that violate sanitizeUsername. Threat
	// T23 + audit-log poisoning T26.
	ErrUsernameInvalid = errors.New("oidc: username failed character validation")

	// ErrMissingCode catches the OAuth2 callback edge case where
	// `code` is absent (some IdPs do this when the user
	// cancels). Distinct so the handler logs cleanly.
	ErrMissingCode = errors.New("oidc: authorization code missing from callback")
)

// Provider is the concrete OIDC implementation of auth.Provider.
// Constructed once at startup (or once per env, when loaded from DB)
// and reused across requests. Safe for concurrent use.
type Provider struct {
	cfg      Config
	provider *gooidc.Provider
	verifier *gooidc.IDTokenVerifier
	oauth2   *oauth2.Config
}

// Compile-time check that Provider implements auth.Provider.
var _ auth.Provider = (*Provider)(nil)

// NewOIDCProvider constructs a Provider from the given Config. The
// context is used for OIDC discovery (fetching the IdP's metadata
// document and JWKS); pass a context with a deadline so a hung IdP
// during init doesn't wedge startup.
//
// Returns a non-nil error and a nil Provider on:
//   - Config validation failure
//   - OIDC discovery failure (IdP unreachable, malformed metadata,
//     etc.)
//
// The returned Provider's verifier pins the audience to cfg.ClientID
// — id_tokens issued for a different audience will fail verification
// (threat T3).
func NewOIDCProvider(ctx context.Context, cfg Config) (*Provider, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	prov, err := gooidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery failed for %s: %w", cfg.IssuerURL, err)
	}
	return &Provider{
		cfg:      cfg,
		provider: prov,
		verifier: prov.Verifier(&gooidc.Config{ClientID: cfg.ClientID}),
		oauth2: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     prov.Endpoint(),
			RedirectURL:  cfg.RedirectURL,
			Scopes:       cfg.effectiveScopes(),
		},
	}, nil
}

// Type identifies this provider as OIDC.
func (p *Provider) Type() string { return auth.TypeOIDC }

// EndSessionURL returns the IdP's RP-initiated logout endpoint URL,
// or "" if the IdP didn't advertise one in its discovery document.
// Callers append `?post_logout_redirect_uri=...&id_token_hint=...`
// when they redirect the user — Keycloak and most IdPs accept those
// query params per the OIDC RP-Initiated Logout spec.
//
// Best-effort: a discovery doc without end_session_endpoint yields
// an empty string, and the caller falls back to client-only cookie
// clearing (no IdP session termination).
func (p *Provider) EndSessionURL() string {
	var claims struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	// p.provider.Claims unmarshals the cached discovery doc; this
	// is a memory read, not a network call.
	if err := p.provider.Claims(&claims); err != nil {
		return ""
	}
	return claims.EndSessionEndpoint
}

// LoginURL builds the authorize-endpoint URL that the user's browser
// should be redirected to. The state argument carries the nonce and
// (optionally) PKCE verifier that HandleCallback will validate
// against the IdP's response.
//
// The OAuth2 state parameter sent in the authorize URL is set to
// state.Nonce (a 256-bit cryptorandom value), NOT to State.EnvUUID.
// This is the load-bearing CSRF defense: an attacker cannot guess
// the value, so they cannot craft a callback URL that the verifier
// would accept. The OIDC nonce parameter (separate from OAuth2 state)
// carries the same value into the id_token, where go-oidc.Verifier
// checks it as the protocol's replay-defense layer. Same value
// transported via two protocol parameters — both must match the
// cookie's nonce for HandleCallback to succeed.
//
// State.EnvUUID is informational only at this layer: it must be
// non-empty (so the state cookie has stable shape) but its value
// isn't checked against anything in the callback URL. Callers that
// want env-scoping above the protocol layer use the EnvUUID
// out-of-band (legacy admin sets it to "admin"; cmd/api sets it to
// "global" or similar; whatever the operator-side code wants).
func (p *Provider) LoginURL(ctx context.Context, state auth.State) (string, error) {
	if state.EnvUUID == "" {
		return "", fmt.Errorf("oidc: LoginURL: empty State.EnvUUID")
	}
	if state.Nonce == "" {
		return "", fmt.Errorf("oidc: LoginURL: empty State.Nonce")
	}
	opts := []oauth2.AuthCodeOption{gooidc.Nonce(state.Nonce)}
	if p.cfg.UsePKCE {
		if state.Verifier == "" {
			return "", fmt.Errorf("oidc: LoginURL: PKCE enabled but State.Verifier is empty")
		}
		opts = append(opts, oauth2.S256ChallengeOption(state.Verifier))
	}
	return p.oauth2.AuthCodeURL(state.Nonce, opts...), nil
}

// HandleCallback consumes the callback request and returns a
// ResolvedIdentity. Validates, in order:
//
//  1. r.URL contains no `error` parameter (ErrIdPError)
//  2. `state` query param matches state.Nonce (ErrStateMismatch — T6, CSRF)
//  3. `code` query param non-empty (ErrMissingCode)
//  4. If PKCE enabled, state.Verifier non-empty (T10 defense in depth;
//     LoginURL already enforces it)
//  5. Code-for-token exchange succeeds (ErrTokenExchange)
//  6. id_token present on token response (ErrIDTokenVerify)
//  7. id_token signature + iss + aud + exp + nbf all valid via
//     go-oidc.Verifier.Verify (ErrIDTokenVerify; covers T1-T5)
//  8. id_token nonce matches state.Nonce (ErrNonceMismatch — T1 narrow)
//  9. Required-groups gate satisfied if configured (ErrGroupNotAllowed — T17)
// 10. Resolved username passes sanitizeUsername (ErrUsernameInvalid — T23)
//
// Implementations of HandleCallback MUST NOT trust the caller to
// pre-verify any of the above. This is the security perimeter.
func (p *Provider) HandleCallback(parentCtx context.Context, r *http.Request, state auth.State) (auth.ResolvedIdentity, error) {
	ctx, cancel := context.WithTimeout(parentCtx, httpExchangeTimeout)
	defer cancel()

	// (1) IdP-signaled error.
	if e := r.URL.Query().Get("error"); e != "" {
		// Note: we deliberately do NOT include the description
		// in the returned error — it can come from the IdP
		// without sanitization and might contain control chars
		// (audit-log poisoning T26). The structured log captures
		// it server-side.
		return auth.ResolvedIdentity{}, fmt.Errorf("%w: %s", ErrIdPError, e)
	}

	// (2) State parameter must echo the cookie's Nonce. This is the
	// load-bearing CSRF check: an unguessable 256-bit value tied to
	// the browser via a signed cookie. Only a browser that received
	// our IssueStateCookie response can satisfy it.
	if got := r.URL.Query().Get("state"); got != state.Nonce {
		return auth.ResolvedIdentity{}, ErrStateMismatch
	}

	// (3) Code must be present.
	code := r.URL.Query().Get("code")
	if code == "" {
		return auth.ResolvedIdentity{}, ErrMissingCode
	}

	// (4) PKCE sanity (LoginURL already enforced this; defense in
	// depth because state cookie tampering or alternate LoginURL
	// implementations could theoretically violate the invariant).
	if p.cfg.UsePKCE && state.Verifier == "" {
		return auth.ResolvedIdentity{}, fmt.Errorf("%w: pkce verifier missing", ErrStateMismatch)
	}

	// (5) Code-for-token exchange.
	var exchOpts []oauth2.AuthCodeOption
	if state.Verifier != "" {
		exchOpts = append(exchOpts, oauth2.VerifierOption(state.Verifier))
	}
	tok, err := p.oauth2.Exchange(ctx, code, exchOpts...)
	if err != nil {
		// Wrap, don't merge — callers may want to log err
		// server-side without exposing it to clients.
		return auth.ResolvedIdentity{}, fmt.Errorf("%w: %v", ErrTokenExchange, err)
	}

	// (6) id_token present.
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return auth.ResolvedIdentity{}, fmt.Errorf("%w: id_token missing from token response", ErrIDTokenVerify)
	}

	// (7) Verify signature + iss + aud + exp + nbf.
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return auth.ResolvedIdentity{}, fmt.Errorf("%w: %v", ErrIDTokenVerify, err)
	}

	// (8) Nonce match.
	if idToken.Nonce != state.Nonce {
		return auth.ResolvedIdentity{}, ErrNonceMismatch
	}

	// Decode the claims we care about.
	var claims idTokenClaims
	if err := idToken.Claims(&claims); err != nil {
		return auth.ResolvedIdentity{}, fmt.Errorf("%w: claims decode: %v", ErrIDTokenVerify, err)
	}

	// (9) Required-groups gate.
	if len(p.cfg.RequiredGroups) > 0 {
		if !hasRequiredGroup(idToken, p.cfg.effectiveGroupsClaim(), p.cfg.RequiredGroups) {
			return auth.ResolvedIdentity{}, ErrGroupNotAllowed
		}
	}

	// Resolve preferred username from configured claim.
	username := pickUsername(claims, p.cfg.effectiveUsernameClaim())
	if username == "" {
		// Should be impossible after a successful verify (sub is
		// always present), but belt and braces.
		return auth.ResolvedIdentity{}, ErrUsernameInvalid
	}

	// (10) Character-class validation. ANY username that doesn't
	// fit the safe shape is rejected with an opaque error — we
	// never log or echo the bad value at INFO level.
	//
	// When Config.LegacyPermissiveUsername is true, the strict
	// regex is bypassed and the trimmed claim is used as-is. Only
	// the legacy admin shim sets this; new callers leave it false.
	var clean string
	if p.cfg.LegacyPermissiveUsername {
		clean = strings.TrimSpace(username)
		if clean == "" {
			return auth.ResolvedIdentity{}, ErrUsernameInvalid
		}
	} else {
		clean = sanitizeUsername(username)
		if clean == "" {
			// Log at DEBUG only; the unsanitized value never
			// leaves the server.
			return auth.ResolvedIdentity{}, ErrUsernameInvalid
		}
	}

	// Compose display name if `name` claim absent.
	fullname := strings.TrimSpace(claims.Name)
	if fullname == "" {
		fullname = strings.TrimSpace(claims.GivenName + " " + claims.FamilyName)
	}

	// Extract groups for the protocol-neutral output. Use the raw
	// claims map so a malformed groups claim (object, string, etc.)
	// doesn't crash the decode — hasRequiredGroup is responsible
	// for shape rejection at the gate; here we just best-effort
	// surface the groups for downstream use.
	groups := decodeGroups(idToken, p.cfg.effectiveGroupsClaim())

	// Raw claims for downstream debugging. The map is not
	// authoritative — callers must read from the typed fields
	// (Subject, PreferredUsername, etc.) to ensure validation has
	// passed.
	var raw map[string]any
	if err := idToken.Claims(&raw); err != nil {
		raw = nil // non-fatal, the typed claims are authoritative
	}

	return auth.ResolvedIdentity{
		Subject:           claims.Subject,
		PreferredUsername: clean,
		Email:             claims.Email,
		Name:              fullname,
		Groups:            groups,
		Raw:               raw,
	}, nil
}

// decodeGroups extracts the groups claim into a []string if the
// shape is the expected []string-of-names. Returns nil on any
// shape mismatch — caller treats nil and empty-slice equivalently.
func decodeGroups(idToken *gooidc.IDToken, claim string) []string {
	var all map[string]any
	if err := idToken.Claims(&all); err != nil {
		return nil
	}
	raw, ok := all[claim]
	if !ok {
		return nil
	}
	arr, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, g := range arr {
		if s, ok := g.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
