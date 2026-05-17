package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/auth"
	"github.com/jmpsec/osctrl/pkg/config"
)

// === Fake IdP harness ===
//
// A trimmed cousin of the harness in pkg/auth/oidc/provider_test.go.
// We only need the discovery + JWKS endpoints to exercise the cmd/api
// OIDC handlers' init + LoginURL paths; the callback's full
// happy-path verification is already covered by the pkg-level tests,
// so we don't need a working /token endpoint here.
type fakeIdP struct {
	srv     *httptest.Server
	key     *rsa.PrivateKey
	keyID   string
	issuer  string // overridden after srv.URL is known
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	idp := &fakeIdP{key: key, keyID: "k1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"issuer":"%s",
			"authorization_endpoint":"%s/authorize",
			"token_endpoint":"%s/token",
			"jwks_uri":"%s/jwks",
			"response_types_supported":["code"],
			"id_token_signing_alg_values_supported":["RS256"]
		}`, idp.issuer, idp.issuer, idp.issuer, idp.issuer)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"keys":[{"kty":"RSA","kid":"%s","alg":"RS256","use":"sig","n":"%s","e":"%s"}]}`,
			idp.keyID, n, e)
	})
	idp.srv = httptest.NewServer(mux)
	idp.issuer = idp.srv.URL
	t.Cleanup(idp.srv.Close)
	return idp
}

// initOIDCWithFake is a test helper that points the package globals
// (oidcProvider, oidcJITProvision, oidcUsePKCE) at a freshly-built
// provider against `idp`. Restores nil-state via t.Cleanup so
// subsequent tests aren't tainted.
func initOIDCWithFake(t *testing.T, idp *fakeIdP, usePKCE bool) {
	t.Helper()
	// Snapshot + reset.
	prevProv := oidcProvider
	prevJIT := oidcJITProvision
	prevPKCE := oidcUsePKCE
	t.Cleanup(func() {
		oidcProvider = prevProv
		oidcJITProvision = prevJIT
		oidcUsePKCE = prevPKCE
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := InitOIDC(ctx, config.YAMLConfigurationOIDC{
		Enabled:      true,
		IssuerURL:    idp.issuer,
		ClientID:     "osctrl-api-test",
		ClientSecret: "test-secret",
		RedirectURL:  "https://api.example/api/v1/auth/oidc/callback",
		UsePKCE:      usePKCE,
	})
	if err != nil {
		t.Fatalf("InitOIDC: %v", err)
	}
}

func newTestHandlers() *HandlersApi {
	return &HandlersApi{
		DebugHTTPConfig: &config.YAMLConfigurationDebug{},
		JWTSecret:       []byte("test-jwt-secret-must-be-non-empty"),
		OIDCEnabled:     true,
	}
}

// === OIDCLoginHandler tests ===

// TestOIDCLoginRedirectsToIdP is the happy-path assertion: with a
// configured provider, the handler issues a state cookie and 302s
// to the IdP's authorize endpoint with the right OAuth2 + OIDC
// parameters.
//
// The state parameter must equal the nonce parameter (the 5A fix
// — see pkg/auth/oidc/provider.go). If a future refactor decouples
// them, the CSRF defense becomes guessable; this test guards that
// invariant at the wire level.
func TestOIDCLoginRedirectsToIdP(t *testing.T) {
	idp := newFakeIdP(t)
	initOIDCWithFake(t, idp, false)
	h := newTestHandlers()

	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil)
	w := httptest.NewRecorder()

	h.OIDCLoginHandler(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status: got %d want 302 (body=%s)", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	if loc == "" {
		t.Fatal("missing Location header on redirect")
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if !strings.HasPrefix(loc, idp.issuer+"/authorize") {
		t.Errorf("Location should target IdP authorize endpoint, got %s", loc)
	}
	q := u.Query()
	state := q.Get("state")
	nonce := q.Get("nonce")
	if state == "" {
		t.Error("state query param missing")
	}
	if nonce == "" {
		t.Error("nonce query param missing")
	}
	if state != nonce {
		t.Errorf("state must equal nonce (5A CSRF invariant): state=%q nonce=%q", state, nonce)
	}
	if q.Get("client_id") != "osctrl-api-test" {
		t.Errorf("client_id: got %q want %q", q.Get("client_id"), "osctrl-api-test")
	}
	if q.Get("response_type") != "code" {
		t.Errorf("response_type: got %q want code", q.Get("response_type"))
	}
	// State cookie must be set on the response.
	var sawStateCookie bool
	for _, c := range w.Result().Cookies() {
		if c.Name == auth.StateCookieName {
			sawStateCookie = true
			if !c.HttpOnly {
				t.Error("state cookie must be HttpOnly")
			}
			if !c.Secure {
				t.Error("state cookie must be Secure")
			}
			if c.SameSite != http.SameSiteLaxMode {
				t.Errorf("state cookie SameSite: got %v want Lax", c.SameSite)
			}
		}
	}
	if !sawStateCookie {
		t.Errorf("expected %s cookie on response, got %v", auth.StateCookieName, w.Result().Cookies())
	}
}

// TestOIDCLoginPKCEIncluded asserts that --oidc-use-pkce flips the
// authorize URL to include code_challenge + code_challenge_method.
// Without PKCE these params are absent; the IdP would happily accept
// the flow but the public-client posture is weaker.
func TestOIDCLoginPKCEIncluded(t *testing.T) {
	idp := newFakeIdP(t)
	initOIDCWithFake(t, idp, true)
	h := newTestHandlers()

	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil)
	w := httptest.NewRecorder()
	h.OIDCLoginHandler(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status: got %d want 302", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "code_challenge=") {
		t.Errorf("PKCE on: Location should include code_challenge, got %s", loc)
	}
	if !strings.Contains(loc, "code_challenge_method=S256") {
		t.Errorf("PKCE on: Location should include code_challenge_method=S256, got %s", loc)
	}
}

// TestOIDCLoginNoProvider asserts that if InitOIDC was never run,
// the handler short-circuits with 503 — fail closed. A 200 here
// would be catastrophic (would mean the route is reachable without
// any IdP).
func TestOIDCLoginNoProvider(t *testing.T) {
	// Explicitly reset the global; do NOT call InitOIDCWithFake.
	prev := oidcProvider
	oidcProvider = nil
	t.Cleanup(func() { oidcProvider = prev })

	h := newTestHandlers()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil)
	w := httptest.NewRecorder()
	h.OIDCLoginHandler(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d want 503", w.Code)
	}
}

// TestOIDCLoginNoJWTSecret asserts that an empty JWTSecret on the
// handlers struct yields 500. The state cookie cannot be signed
// without it, so we refuse to start a flow we couldn't validate
// later.
func TestOIDCLoginNoJWTSecret(t *testing.T) {
	idp := newFakeIdP(t)
	initOIDCWithFake(t, idp, false)
	h := newTestHandlers()
	h.JWTSecret = nil

	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil)
	w := httptest.NewRecorder()
	h.OIDCLoginHandler(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d want 500", w.Code)
	}
}

// === OIDCCallbackHandler tests ===
//
// The happy path requires a real users.UserManager + audit log,
// which in turn need a *gorm.DB. That setup is out of scope for
// this file; pkg/auth/oidc/provider_test.go covers the 10-step
// protocol verification end-to-end. The tests below cover the
// handler-level guards that don't depend on DB state: configuration
// errors and state-cookie failures. These are the cases where a
// production misconfig is most likely to surface.

// TestOIDCCallbackNoProvider — same fail-closed posture as
// TestOIDCLoginNoProvider, but for the callback path.
func TestOIDCCallbackNoProvider(t *testing.T) {
	prev := oidcProvider
	oidcProvider = nil
	t.Cleanup(func() { oidcProvider = prev })

	h := newTestHandlers()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback?code=x&state=y", nil)
	w := httptest.NewRecorder()
	h.OIDCCallbackHandler(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d want 503", w.Code)
	}
}

// TestOIDCCallbackNoJWTSecret asserts the empty-secret guard on the
// callback. Same defense as the login path; covered separately
// because the callback can also reach this branch on a partial
// startup race.
func TestOIDCCallbackNoJWTSecret(t *testing.T) {
	idp := newFakeIdP(t)
	initOIDCWithFake(t, idp, false)
	h := newTestHandlers()
	h.JWTSecret = nil

	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback?code=x&state=y", nil)
	w := httptest.NewRecorder()
	h.OIDCCallbackHandler(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d want 500", w.Code)
	}
}

// TestOIDCCallbackMissingStateCookie covers the most common
// production failure: the user opens the callback URL directly
// (or after the 10-minute state cookie expired). The handler MUST
// 302 to "/" — never 500 — so the SPA shows the login page again.
//
// Threat T9 (state cookie replay) lives adjacent: if the callback
// silently failed open here, an attacker could craft a URL with
// any state value. The 302 + clearing of the cookie keeps the
// flow strictly single-use.
func TestOIDCCallbackMissingStateCookie(t *testing.T) {
	idp := newFakeIdP(t)
	initOIDCWithFake(t, idp, false)
	h := newTestHandlers()

	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback?code=x&state=y", nil)
	w := httptest.NewRecorder()
	h.OIDCCallbackHandler(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status: got %d want 302 (body=%s)", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Location"); got != "/" {
		t.Errorf("Location: got %q want /", got)
	}
}

// TestOIDCCallbackTamperedStateCookie covers the case where a
// cookie is present but its HMAC doesn't verify (attacker forging
// or operator rotating the JWT secret without invalidating
// in-flight sessions). Must 302 to "/" without leaking the reason.
func TestOIDCCallbackTamperedStateCookie(t *testing.T) {
	idp := newFakeIdP(t)
	initOIDCWithFake(t, idp, false)
	h := newTestHandlers()

	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback?code=x&state=y", nil)
	r.AddCookie(&http.Cookie{
		Name:  auth.StateCookieName,
		Value: "not.a.valid.jwt",
	})
	w := httptest.NewRecorder()
	h.OIDCCallbackHandler(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status: got %d want 302", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/" {
		t.Errorf("Location: got %q want /", got)
	}
}

// TestOIDCCallbackForeignAudience covers a subtle attack: an
// attacker who can mint a state JWT signed with our JWTSecret but
// with the wrong audience (e.g. they got hold of a user-auth JWT
// and want to replay it as a state cookie). pkg/auth.ParseStateCookie
// must reject mismatched audiences. We assert handler-level behavior
// matches.
func TestOIDCCallbackForeignAudience(t *testing.T) {
	idp := newFakeIdP(t)
	initOIDCWithFake(t, idp, false)
	h := newTestHandlers()

	// Construct a JWT signed with our secret but for a wrong
	// audience. We do this by directly calling the auth.State
	// helpers... but those don't expose audience tweaking. Easier:
	// hand-construct an HS256 JWT.
	// header { alg: HS256, typ: JWT }
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(
		`{"iss":"osctrl-auth","aud":"wrong-audience","exp":%d,"env":"x","nonce":"y"}`,
		time.Now().Add(5*time.Minute).Unix())))
	signingInput := header + "." + payload
	mac := hmacSHA256(h.JWTSecret, []byte(signingInput))
	jwt := signingInput + "." + base64.RawURLEncoding.EncodeToString(mac)

	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback?code=x&state=y", nil)
	r.AddCookie(&http.Cookie{Name: auth.StateCookieName, Value: jwt})
	w := httptest.NewRecorder()
	h.OIDCCallbackHandler(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status: got %d want 302 (body=%s)", w.Code, w.Body.String())
	}
}

// hmacSHA256 mints a test JWT signature so we can construct a state
// cookie with whatever payload we want (e.g. a wrong-audience claim).
// pkg/auth doesn't export a hmac helper because production code never
// hand-builds JWTs — only this test fixture does.
func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// === ResponseShape sanity ===

// TestAuthMethodResponseJSONShape locks the field names on the wire.
// The SPA consumes these by name; a Go-side rename without a JSON tag
// would silently break the frontend.
func TestAuthMethodResponseJSONShape(t *testing.T) {
	body, err := json.Marshal(AuthMethodsResponse{
		Methods: []AuthMethod{{Type: "password", LoginURL: "/api/v1/login"}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, w := range []string{`"methods"`, `"type"`, `"loginUrl"`} {
		if !strings.Contains(string(body), w) {
			t.Errorf("expected %s in JSON: %s", w, body)
		}
	}
}
