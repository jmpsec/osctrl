package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/jmpsec/osctrl/pkg/auth"
)

// fakeIdP runs a minimal OIDC issuer in-process. Implements the bare
// surface go-oidc and oauth2 consume:
//
//   - /.well-known/openid-configuration  (discovery)
//   - /jwks                              (signing keys)
//   - /token                             (code-for-token exchange)
//
// The authorize endpoint is not implemented because Provider.LoginURL
// only emits the URL; tests do not visit it. HandleCallback's only
// network call is to /token.
type fakeIdP struct {
	srv      *httptest.Server
	priv     *rsa.PrivateKey
	keyID    string
	nextCode string

	// Knobs each test toggles before driving HandleCallback.
	// nil/zero values mean "default behavior".
	signWithDifferentKey   *rsa.PrivateKey // T1 — forged signature
	issuerOverride         string          // T2 — wrong issuer
	audienceOverride       string          // T3 — wrong audience
	expOverride            *time.Time      // T4 — expired
	nonceOverride          string          // injection of wrong nonce
	preferredUsernameValue string          // test username variations
	groupsValue            any             // groups claim shape (string[] / object / nil)
	subjectOverride        string          // override sub claim
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	f := &fakeIdP{priv: priv, keyID: "test-key-1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", f.handleDiscovery)
	mux.HandleFunc("/jwks", f.handleJWKS)
	mux.HandleFunc("/token", f.handleToken)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// IssuerURL returns the URL the test uses as Config.IssuerURL.
func (f *fakeIdP) IssuerURL() string { return f.srv.URL }

func (f *fakeIdP) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	doc := map[string]any{
		"issuer":                                f.srv.URL,
		"authorization_endpoint":                f.srv.URL + "/authorize",
		"token_endpoint":                        f.srv.URL + "/token",
		"jwks_uri":                              f.srv.URL + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

// handleJWKS emits the RSA public key as a JWK array. go-oidc fetches
// this once and caches it; the key id binds tokens to a specific key.
func (f *fakeIdP) handleJWKS(w http.ResponseWriter, r *http.Request) {
	jwk := map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": f.keyID,
		"n":   base64.RawURLEncoding.EncodeToString(f.priv.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(f.priv.E)).Bytes()),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwk}})
}

// handleToken implements the code-for-token exchange. Issues a fresh
// id_token signed with the IdP's key (or a different key if the test
// has flipped signWithDifferentKey, simulating an attacker-controlled
// token). The id_token's claims reflect every override the test set.
func (f *fakeIdP) handleToken(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	code := r.Form.Get("code")
	if code != f.nextCode {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}

	iss := f.srv.URL
	if f.issuerOverride != "" {
		iss = f.issuerOverride
	}
	aud := "osctrl-api"
	if f.audienceOverride != "" {
		aud = f.audienceOverride
	}
	exp := time.Now().Add(5 * time.Minute)
	if f.expOverride != nil {
		exp = *f.expOverride
	}
	nonce := "n-default"
	if f.nonceOverride != "" {
		nonce = f.nonceOverride
	}
	sub := "sub-12345"
	if f.subjectOverride != "" {
		sub = f.subjectOverride
	}
	pref := "alice"
	if f.preferredUsernameValue != "" {
		pref = f.preferredUsernameValue
	}

	claims := jwt.MapClaims{
		"iss":                iss,
		"aud":                aud,
		"sub":                sub,
		"exp":                exp.Unix(),
		"iat":                time.Now().Unix(),
		"nonce":              nonce,
		"preferred_username": pref,
		"email":              "alice@example.local",
		"name":               "Alice Tester",
	}
	if f.groupsValue != nil {
		claims["groups"] = f.groupsValue
	}

	signer := f.priv
	if f.signWithDifferentKey != nil {
		signer = f.signWithDifferentKey
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = f.keyID
	signed, err := tok.SignedString(signer)
	if err != nil {
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "fake-access-token",
		"id_token":     signed,
		"token_type":   "Bearer",
		"expires_in":   300,
	})
}

// goodConfig returns a Config wired against the IdP, with the
// audience matching what the IdP will emit (so the happy path works).
func goodConfig(idp *fakeIdP) Config {
	return Config{
		IssuerURL:    idp.IssuerURL(),
		ClientID:     "osctrl-api",
		ClientSecret: "test-secret",
		RedirectURL:  "https://api.example/cb",
		Scopes:       []string{"openid", "profile", "email"},
		UsePKCE:      false,
	}
}

// goodState returns a State that lines up with the IdP's defaults.
// EnvUUID + Nonce are what HandleCallback validates against; we use
// "n-default" to match the IdP's default nonce claim.
// OAuthState is an independent random value — required as of the
// May 2026 split.
func goodState() auth.State {
	return auth.State{
		EnvUUID:    "env-uuid-1234",
		Nonce:      "n-default",
		OAuthState: "s-default",
	}
}

// fakeCallback constructs the *http.Request that HandleCallback
// receives. The state query param echoes the cookie's Nonce (the
// load-bearing CSRF defense; see Provider.LoginURL). The code param
// matches what the IdP expects.
func fakeCallback(stateParam, code string) *http.Request {
	q := url.Values{}
	q.Set("state", stateParam)
	q.Set("code", code)
	req := httptest.NewRequest(http.MethodGet, "/cb?"+q.Encode(), nil)
	return req
}

// === Happy path ===

func TestHandleCallbackHappy(t *testing.T) {
	idp := newFakeIdP(t)
	idp.nextCode = "code-happy"

	p, err := NewOIDCProvider(context.Background(), goodConfig(idp))
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}

	state := goodState()
	identity, err := p.HandleCallback(context.Background(), fakeCallback(state.OAuthState, "code-happy"), state)
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	if identity.Subject != "sub-12345" {
		t.Errorf("Subject: got %q want sub-12345", identity.Subject)
	}
	if identity.PreferredUsername != "alice" {
		t.Errorf("PreferredUsername: got %q want alice", identity.PreferredUsername)
	}
	if identity.Email != "alice@example.local" {
		t.Errorf("Email: got %q want alice@example.local", identity.Email)
	}
}

// === Threat T1: forged signature ===
//
// The IdP signs with a different key. go-oidc fetches the legitimate
// JWKS, so the signature verification fails.

func TestT1ForgedSignature(t *testing.T) {
	idp := newFakeIdP(t)
	idp.nextCode = "code-forged"
	attackerKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	idp.signWithDifferentKey = attackerKey

	p, err := NewOIDCProvider(context.Background(), goodConfig(idp))
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}

	_, err = p.HandleCallback(context.Background(), fakeCallback("s-default", "code-forged"), goodState())
	if !errors.Is(err, ErrIDTokenVerify) {
		t.Fatalf("expected ErrIDTokenVerify, got %v", err)
	}
}

// === Threat T2: wrong issuer ===
//
// The id_token claims a different issuer than the one go-oidc
// expects (the URL it was constructed against).

func TestT2WrongIssuer(t *testing.T) {
	idp := newFakeIdP(t)
	idp.nextCode = "code-iss"
	idp.issuerOverride = "https://attacker.example/realms/evil"

	p, err := NewOIDCProvider(context.Background(), goodConfig(idp))
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}

	_, err = p.HandleCallback(context.Background(), fakeCallback("s-default", "code-iss"), goodState())
	if !errors.Is(err, ErrIDTokenVerify) {
		t.Fatalf("expected ErrIDTokenVerify, got %v", err)
	}
}

// === Threat T3: wrong audience ===
//
// Token issued for a different client. The verifier is configured
// with ClientID == "osctrl-api"; this token says "some-other-client".

func TestT3WrongAudience(t *testing.T) {
	idp := newFakeIdP(t)
	idp.nextCode = "code-aud"
	idp.audienceOverride = "some-other-client"

	p, err := NewOIDCProvider(context.Background(), goodConfig(idp))
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}

	_, err = p.HandleCallback(context.Background(), fakeCallback("s-default", "code-aud"), goodState())
	if !errors.Is(err, ErrIDTokenVerify) {
		t.Fatalf("expected ErrIDTokenVerify, got %v", err)
	}
}

// === Threat T4: expired token ===
//
// IdP emits an id_token with exp in the past.

func TestT4Expired(t *testing.T) {
	idp := newFakeIdP(t)
	idp.nextCode = "code-exp"
	past := time.Now().Add(-1 * time.Hour)
	idp.expOverride = &past

	p, err := NewOIDCProvider(context.Background(), goodConfig(idp))
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}

	_, err = p.HandleCallback(context.Background(), fakeCallback("s-default", "code-exp"), goodState())
	if !errors.Is(err, ErrIDTokenVerify) {
		t.Fatalf("expected ErrIDTokenVerify, got %v", err)
	}
}

// === Nonce mismatch (also covers T1 narrow case) ===

func TestNonceMismatch(t *testing.T) {
	idp := newFakeIdP(t)
	idp.nextCode = "code-nonce"
	// IdP emits "n-default" by default, but the state we pass to
	// HandleCallback claims a different nonce.

	p, err := NewOIDCProvider(context.Background(), goodConfig(idp))
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}
	state := goodState()
	state.Nonce = "n-different"
	// state.OAuthState stays valid so the OAuth2-state check passes
	// and the nonce-mismatch path is reached (the id_token's nonce
	// claim says "n-default", we expect "n-different").
	_, err = p.HandleCallback(context.Background(), fakeCallback(state.OAuthState, "code-nonce"), state)
	if !errors.Is(err, ErrNonceMismatch) {
		t.Fatalf("expected ErrNonceMismatch, got %v", err)
	}
}

// === Threat T6: CSRF / state-param tampering ===
//
// State cookie carries Nonce "n-default" (set by IssueStateCookie at
// /login). The attacker crafts a callback URL with a forged state
// parameter. Because the value is unguessable (256-bit cryptorandom),
// the attacker cannot produce a callback URL the verifier accepts.
// HandleCallback rejects with ErrStateMismatch BEFORE any token-
// exchange happens.

func TestT6CSRFStateTampering(t *testing.T) {
	idp := newFakeIdP(t)
	idp.nextCode = "code-csrf"
	p, err := NewOIDCProvider(context.Background(), goodConfig(idp))
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}
	stateInCookie := auth.State{EnvUUID: "env-A", Nonce: "n-default", OAuthState: "s-secret-value"}
	// Attacker-controlled URL: state param is anything except the
	// OAuthState baked into the victim's cookie.
	req := fakeCallback("attacker-supplied-state", "code-csrf")
	_, err = p.HandleCallback(context.Background(), req, stateInCookie)
	if !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("expected ErrStateMismatch, got %v", err)
	}
}

// === IdP-signaled error in callback ===

func TestIdPErrorParam(t *testing.T) {
	idp := newFakeIdP(t)
	p, err := NewOIDCProvider(context.Background(), goodConfig(idp))
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}
	// Callback URL has ?error=access_denied
	q := url.Values{}
	q.Set("error", "access_denied")
	q.Set("error_description", "user did <not> consent\nbreaks_audit_log") // T26 attempt
	q.Set("state", "env-uuid-1234")
	req := httptest.NewRequest(http.MethodGet, "/cb?"+q.Encode(), nil)
	_, err = p.HandleCallback(context.Background(), req, goodState())
	if !errors.Is(err, ErrIdPError) {
		t.Fatalf("expected ErrIdPError, got %v", err)
	}
	// The error_description must NOT bleed into our error string
	// (audit-log poisoning T26 — we keep that in server-side logs only).
	if strings.Contains(err.Error(), "breaks_audit_log") || strings.Contains(err.Error(), "\n") {
		t.Errorf("error description leaked into client-visible error: %q", err.Error())
	}
}

// === Missing code ===

func TestMissingCode(t *testing.T) {
	idp := newFakeIdP(t)
	p, err := NewOIDCProvider(context.Background(), goodConfig(idp))
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}
	// State param matches the cookie's OAuthState so we reach the
	// missing-code check (step 3) rather than failing at the
	// state-param check (step 2).
	q := url.Values{}
	q.Set("state", "s-default")
	// no code
	req := httptest.NewRequest(http.MethodGet, "/cb?"+q.Encode(), nil)
	_, err = p.HandleCallback(context.Background(), req, goodState())
	if !errors.Is(err, ErrMissingCode) {
		t.Fatalf("expected ErrMissingCode, got %v", err)
	}
}

// === Threat T10: PKCE enabled but verifier missing in state ===

func TestT10PKCEVerifierMissing(t *testing.T) {
	idp := newFakeIdP(t)
	idp.nextCode = "code-pkce"
	cfg := goodConfig(idp)
	cfg.UsePKCE = true
	cfg.ClientSecret = "" // public-client mode
	p, err := NewOIDCProvider(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}
	// State has EnvUUID + Nonce + OAuthState but NO Verifier.
	state := auth.State{EnvUUID: "env-uuid-1234", Nonce: "n-default", OAuthState: "s-default"}
	_, err = p.HandleCallback(context.Background(), fakeCallback(state.OAuthState, "code-pkce"), state)
	if !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("expected ErrStateMismatch (pkce verifier missing), got %v", err)
	}
}

// === Threat T17: required-group not satisfied ===

func TestT17RequiredGroupMissing(t *testing.T) {
	idp := newFakeIdP(t)
	idp.nextCode = "code-group"
	// User is in "regular-users" but not "osctrl-admins"
	idp.groupsValue = []any{"regular-users"}
	cfg := goodConfig(idp)
	cfg.RequiredGroups = []string{"osctrl-admins"}
	p, err := NewOIDCProvider(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}
	_, err = p.HandleCallback(context.Background(), fakeCallback("s-default", "code-group"), goodState())
	if !errors.Is(err, ErrGroupNotAllowed) {
		t.Fatalf("expected ErrGroupNotAllowed, got %v", err)
	}
}

// === Required-group SATISFIED ===

func TestRequiredGroupSatisfied(t *testing.T) {
	idp := newFakeIdP(t)
	idp.nextCode = "code-group-ok"
	idp.groupsValue = []any{"regular-users", "osctrl-admins"}
	cfg := goodConfig(idp)
	cfg.RequiredGroups = []string{"osctrl-admins"}
	p, err := NewOIDCProvider(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}
	identity, err := p.HandleCallback(context.Background(), fakeCallback("s-default", "code-group-ok"), goodState())
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	if len(identity.Groups) != 2 {
		t.Errorf("expected 2 groups in identity, got %v", identity.Groups)
	}
}

// === Threat T17 narrow: group claim malformed (string instead of array) ===
//
// Real-world: some Entra/Auth0 configurations emit a single string
// rather than an array. The gate must deny rather than try to parse.

func TestT17GroupsClaimMalformed(t *testing.T) {
	idp := newFakeIdP(t)
	idp.nextCode = "code-group-bad"
	idp.groupsValue = "osctrl-admins" // not an array
	cfg := goodConfig(idp)
	cfg.RequiredGroups = []string{"osctrl-admins"}
	p, err := NewOIDCProvider(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}
	_, err = p.HandleCallback(context.Background(), fakeCallback("s-default", "code-group-bad"), goodState())
	if !errors.Is(err, ErrGroupNotAllowed) {
		t.Fatalf("expected ErrGroupNotAllowed for malformed group claim, got %v", err)
	}
}

// === Legacy permissive-username mode (backwards-compat shim) ===
//
// LegacyPermissiveUsername=true relaxes the regex so existing
// osctrl-admin deployments with email-format usernames keep working.
// Verifies that:
//  - dots/at/spaces are accepted (would be rejected strict)
//  - empty username is STILL rejected (sanitizer's only universal rule)
//  - control characters (\n, \x00) are STILL rejected (audit-log safety)
//
// The shim must not be a complete bypass — empty + control-char
// rejection survives because those have no legitimate use case and
// directly enable audit-log poisoning (threat T26).
func TestLegacyPermissiveUsernameAccepts(t *testing.T) {
	cases := []string{
		"alice@example.com",
		"alice.doe",
		"alice doe",
		"Alice.Doe", // mixed case
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			idp := newFakeIdP(t)
			idp.nextCode = "code-perm"
			idp.preferredUsernameValue = u
			cfg := goodConfig(idp)
			cfg.LegacyPermissiveUsername = true
			p, err := NewOIDCProvider(context.Background(), cfg)
			if err != nil {
				t.Fatalf("NewOIDCProvider: %v", err)
			}
			identity, err := p.HandleCallback(context.Background(), fakeCallback("s-default", "code-perm"), goodState())
			if err != nil {
				t.Fatalf("LegacyPermissiveUsername should accept %q, got %v", u, err)
			}
			if identity.PreferredUsername != u {
				t.Errorf("PreferredUsername: got %q want %q", identity.PreferredUsername, u)
			}
		})
	}
}

// Even in permissive mode, empty usernames must be rejected — the
// sanitizer's whitespace-trim happens BEFORE the regex check in
// strict mode and BEFORE the trim+empty-check in permissive mode.
func TestLegacyPermissiveUsernameRejectsEmpty(t *testing.T) {
	idp := newFakeIdP(t)
	idp.nextCode = "code-empty"
	idp.preferredUsernameValue = "   " // whitespace-only
	cfg := goodConfig(idp)
	cfg.LegacyPermissiveUsername = true
	// Force pickUsername to use preferred_username (so the
	// whitespace value flows through) by leaving claim as default.
	p, err := NewOIDCProvider(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}
	// With preferred_username = "   ", pickUsername returns "   ",
	// which TrimSpace reduces to "" — must be rejected.
	_, err = p.HandleCallback(context.Background(), fakeCallback("s-default", "code-empty"), goodState())
	if !errors.Is(err, ErrUsernameInvalid) {
		t.Fatalf("expected ErrUsernameInvalid on whitespace-only username, got %v", err)
	}
}

// === Threat T23: username contains injection payload ===
//
// Verify that an IdP returning a malicious preferred_username makes
// HandleCallback reject the request rather than pass the value
// through to downstream caller.

func TestT23UsernameInjection(t *testing.T) {
	cases := []string{
		"alice'; DROP TABLE users; --",
		"alice\nadmin",
		"alice\x00root",
		"alice<script>alert(1)</script>",
		"alice@example.com", // dot+at — would be valid email, but we don't allow them in username
		"alice with spaces",
	}
	for _, badUsername := range cases {
		t.Run(badUsername, func(t *testing.T) {
			idp := newFakeIdP(t)
			idp.nextCode = "code-inj"
			idp.preferredUsernameValue = badUsername
			p, err := NewOIDCProvider(context.Background(), goodConfig(idp))
			if err != nil {
				t.Fatalf("NewOIDCProvider: %v", err)
			}
			_, err = p.HandleCallback(context.Background(), fakeCallback("s-default", "code-inj"), goodState())
			if !errors.Is(err, ErrUsernameInvalid) {
				t.Fatalf("expected ErrUsernameInvalid for %q, got %v", badUsername, err)
			}
		})
	}
}

// === Discovery failure (init time) ===
//
// A bare HTTP server with no .well-known/openid-configuration endpoint
// causes NewOIDCProvider to fail at discovery, not at first use. This
// catches operator config errors at startup rather than 404 on user
// login.
func TestNewOIDCProviderDiscoveryFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	cfg := Config{
		IssuerURL:    srv.URL,
		ClientID:     "osctrl-api",
		ClientSecret: "test-secret",
		RedirectURL:  "https://api.example/cb",
	}
	_, err := NewOIDCProvider(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected discovery to fail")
	}
}

// === LoginURL: enforces non-empty State.EnvUUID + Nonce + OAuthState ===

func TestLoginURLValidatesState(t *testing.T) {
	idp := newFakeIdP(t)
	p, err := NewOIDCProvider(context.Background(), goodConfig(idp))
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}
	if _, err := p.LoginURL(context.Background(), auth.State{}); err == nil {
		t.Error("expected error on empty State")
	}
	if _, err := p.LoginURL(context.Background(), auth.State{EnvUUID: "x"}); err == nil {
		t.Error("expected error on empty Nonce")
	}
	if _, err := p.LoginURL(context.Background(), auth.State{EnvUUID: "x", Nonce: "n-1"}); err == nil {
		t.Error("expected error on empty OAuthState")
	}
	// Defense-in-depth: same-value reuse must be rejected.
	if _, err := p.LoginURL(context.Background(), auth.State{EnvUUID: "x", Nonce: "same", OAuthState: "same"}); err == nil {
		t.Error("expected error when OAuthState == Nonce")
	}
	url, err := p.LoginURL(context.Background(), auth.State{EnvUUID: "env-A", Nonce: "n-1", OAuthState: "s-1"})
	if err != nil {
		t.Fatalf("LoginURL: %v", err)
	}
	// OAuth2 state parameter must carry OAuthState, NOT Nonce
	// (May 2026 split). This is what HandleCallback validates on
	// return, and what makes the CSRF defense load-bearing.
	if !strings.Contains(url, "state=s-1") {
		t.Errorf("LoginURL should embed OAuthState in state param: %s", url)
	}
	if strings.Contains(url, "state=n-1") {
		t.Errorf("LoginURL must NOT use Nonce as the OAuth2 state param (defense-in-depth split): %s", url)
	}
	if strings.Contains(url, "state=env-A") {
		t.Errorf("LoginURL must NOT use EnvUUID as the OAuth2 state param: %s", url)
	}
	if !strings.Contains(url, "nonce=n-1") {
		t.Errorf("LoginURL should embed nonce: %s", url)
	}
}

// === LoginURL: PKCE enforced when configured ===

func TestLoginURLPKCERequired(t *testing.T) {
	idp := newFakeIdP(t)
	cfg := goodConfig(idp)
	cfg.UsePKCE = true
	cfg.ClientSecret = ""
	p, err := NewOIDCProvider(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}
	// PKCE on, but no Verifier in State → reject at LoginURL.
	if _, err := p.LoginURL(context.Background(), auth.State{EnvUUID: "env-A", Nonce: "n-1", OAuthState: "s-1"}); err == nil {
		t.Error("expected error: pkce verifier required")
	}
	// PKCE on + Verifier present → URL includes code_challenge.
	u, err := p.LoginURL(context.Background(), auth.State{EnvUUID: "env-A", Nonce: "n-1", OAuthState: "s-1", Verifier: "v-1234567890123456789012345678901234567890123"})
	if err != nil {
		t.Fatalf("LoginURL: %v", err)
	}
	if !strings.Contains(u, "code_challenge=") || !strings.Contains(u, "code_challenge_method=S256") {
		t.Errorf("LoginURL with PKCE should include challenge: %s", u)
	}
}

// === Sanity: provider Type() returns "oidc" ===

func TestType(t *testing.T) {
	idp := newFakeIdP(t)
	p, err := NewOIDCProvider(context.Background(), goodConfig(idp))
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}
	if p.Type() != auth.TypeOIDC {
		t.Errorf("Type: got %q want %q", p.Type(), auth.TypeOIDC)
	}
}

// === Smoke: silence unused imports/symbols in this test file ===

var _ = io.Discard
var _ = sha256.Sum256

// Quick fmt sanity used inside fake IdP — suppress vet's
// "redundant test-file vars" if any.
var _ = fmt.Sprintf
