package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// secret used by every test. 32 bytes matches the
// pkg/users.MinJWTSecretBytes contract; longer would also work, this
// is just a representative test value.
var testSecret = []byte("test-secret-must-be-at-least-32-bytes-long")

// freshState returns a State with valid fields for round-trip tests.
func freshState(t *testing.T) State {
	t.Helper()
	nonce, err := NewNonce()
	if err != nil {
		t.Fatalf("NewNonce: %v", err)
	}
	oauthState, err := NewNonce()
	if err != nil {
		t.Fatalf("NewNonce: %v", err)
	}
	verifier, err := NewNonce()
	if err != nil {
		t.Fatalf("NewNonce: %v", err)
	}
	return State{
		EnvUUID:    "dev-uuid-1234",
		Nonce:      nonce,
		OAuthState: oauthState,
		Verifier:   verifier,
	}
}

// issueOnRecorder issues a state cookie on a fresh ResponseRecorder
// and returns the corresponding *http.Request that carries the cookie
// for the next call.
func issueOnRecorder(t *testing.T, s State) *http.Request {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := IssueStateCookie(rec, testSecret, s); err != nil {
		t.Fatalf("IssueStateCookie: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	return req
}

// TestNonceUnique sanity-checks that we get distinct nonces across
// calls. With 256-bit entropy a collision in this many calls is
// astronomically improbable; this is purely smoke for the function
// not the math.
func TestNonceUnique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		n, err := NewNonce()
		if err != nil {
			t.Fatalf("NewNonce: %v", err)
		}
		if n == "" {
			t.Fatalf("NewNonce returned empty")
		}
		if seen[n] {
			t.Fatalf("nonce collision in 100 calls: %s", n)
		}
		seen[n] = true
	}
}

// TestStateRoundTripHappy is the canonical "good" path: issue cookie,
// parse the resulting request, get the same State back.
func TestStateRoundTripHappy(t *testing.T) {
	s := freshState(t)
	req := issueOnRecorder(t, s)
	got, err := ParseStateCookie(req, testSecret)
	if err != nil {
		t.Fatalf("ParseStateCookie: %v", err)
	}
	if got.EnvUUID != s.EnvUUID {
		t.Errorf("EnvUUID: got %q want %q", got.EnvUUID, s.EnvUUID)
	}
	if got.Nonce != s.Nonce {
		t.Errorf("Nonce: got %q want %q", got.Nonce, s.Nonce)
	}
	if got.Verifier != s.Verifier {
		t.Errorf("Verifier: got %q want %q", got.Verifier, s.Verifier)
	}
}

// Threat T6 (CSRF): callback without prior login → state cookie
// missing. Must return ErrStateMissing, not ErrStateInvalid (callers
// may want to log differently or rate-limit differently).
func TestStateMissing(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback", nil)
	_, err := ParseStateCookie(req, testSecret)
	if !errors.Is(err, ErrStateMissing) {
		t.Fatalf("expected ErrStateMissing, got %v", err)
	}
}

// Empty-value cookie behaves the same as missing. Some buggy proxies
// strip values but keep cookie names; defensive.
func TestStateEmptyValue(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback", nil)
	req.AddCookie(&http.Cookie{Name: StateCookieName, Value: ""})
	_, err := ParseStateCookie(req, testSecret)
	if !errors.Is(err, ErrStateMissing) {
		t.Fatalf("expected ErrStateMissing, got %v", err)
	}
}

// Threat T31 (timing oracle) + general tampering: any structural
// change to the JWT must fail closed with ErrStateInvalid. We flip a
// byte in the signature segment.
func TestStateSignatureTampered(t *testing.T) {
	s := freshState(t)
	req := issueOnRecorder(t, s)
	c, _ := req.Cookie(StateCookieName)
	parts := strings.Split(c.Value, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed JWT in issued cookie: %s", c.Value)
	}
	// Flip the first character of the signature. Toggle between
	// digits to keep base64-validity but invalidate the signature.
	tampered := parts[2]
	if tampered[0] == 'A' {
		tampered = "B" + tampered[1:]
	} else {
		tampered = "A" + tampered[1:]
	}
	c.Value = parts[0] + "." + parts[1] + "." + tampered
	// Replace the cookie.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback", nil)
	req.AddCookie(c)
	_, err := ParseStateCookie(req, testSecret)
	if !errors.Is(err, ErrStateInvalid) {
		t.Fatalf("expected ErrStateInvalid on tampered sig, got %v", err)
	}
}

// Threat T9 (replay) + general expiry handling: a state cookie issued
// with exp in the past must be rejected. We craft one directly with
// the same key.
func TestStateExpired(t *testing.T) {
	past := time.Now().Add(-1 * time.Hour)
	claims := stateClaims{
		EnvUUID: "dev-uuid-1234",
		Nonce:   "n-1234",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    stateJWTIssuer,
			Audience:  jwt.ClaimStrings{stateJWTAudience},
			IssuedAt:  jwt.NewNumericDate(past.Add(-StateCookieTTL)),
			NotBefore: jwt.NewNumericDate(past.Add(-StateCookieTTL)),
			ExpiresAt: jwt.NewNumericDate(past),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := tok.SignedString(testSecret)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback", nil)
	req.AddCookie(&http.Cookie{Name: StateCookieName, Value: signed})
	_, err := ParseStateCookie(req, testSecret)
	if !errors.Is(err, ErrStateInvalid) {
		t.Fatalf("expected ErrStateInvalid on expired token, got %v", err)
	}
}

// Threat T19 (token confusion): a JWT signed with the same secret but
// for a different audience (e.g., a user-auth JWT mistakenly sent in
// the state cookie position) must be rejected.
func TestStateWrongAudience(t *testing.T) {
	now := time.Now()
	claims := stateClaims{
		EnvUUID: "dev-uuid-1234",
		Nonce:   "n-1234",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    stateJWTIssuer,
			Audience:  jwt.ClaimStrings{"osctrl-api"}, // user-auth aud, not state aud
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(StateCookieTTL)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := tok.SignedString(testSecret)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback", nil)
	req.AddCookie(&http.Cookie{Name: StateCookieName, Value: signed})
	_, err := ParseStateCookie(req, testSecret)
	if !errors.Is(err, ErrStateInvalid) {
		t.Fatalf("expected ErrStateInvalid on wrong aud, got %v", err)
	}
}

// A JWT with the right audience but the wrong issuer must also be
// rejected. Belt-and-braces: aud is the primary defense but iss adds
// a redundant identity claim.
func TestStateWrongIssuer(t *testing.T) {
	now := time.Now()
	claims := stateClaims{
		EnvUUID: "dev-uuid-1234",
		Nonce:   "n-1234",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "some-other-issuer",
			Audience:  jwt.ClaimStrings{stateJWTAudience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(StateCookieTTL)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := tok.SignedString(testSecret)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback", nil)
	req.AddCookie(&http.Cookie{Name: StateCookieName, Value: signed})
	_, err := ParseStateCookie(req, testSecret)
	if !errors.Is(err, ErrStateInvalid) {
		t.Fatalf("expected ErrStateInvalid on wrong iss, got %v", err)
	}
}

// JWT signed with a different key, same structure as ours, must be
// rejected. Equivalent to "attacker minted their own token".
func TestStateWrongSecret(t *testing.T) {
	wrongSecret := []byte("attacker-secret-also-32-bytes-long-aaaa")
	s := freshState(t)
	now := time.Now()
	claims := stateClaims{
		EnvUUID:  s.EnvUUID,
		Nonce:    s.Nonce,
		Verifier: s.Verifier,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    stateJWTIssuer,
			Audience:  jwt.ClaimStrings{stateJWTAudience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(StateCookieTTL)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := tok.SignedString(wrongSecret)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback", nil)
	req.AddCookie(&http.Cookie{Name: StateCookieName, Value: signed})
	_, err := ParseStateCookie(req, testSecret)
	if !errors.Is(err, ErrStateInvalid) {
		t.Fatalf("expected ErrStateInvalid on wrong secret, got %v", err)
	}
}

// Alg-confusion defense: a token with alg=none should be rejected by
// the WithValidMethods option even if a verifier ignores the
// signature. Defense in depth against threats from broken
// dependencies.
func TestStateAlgNoneRejected(t *testing.T) {
	// jwt.SigningMethodNone signs with the value "none" but
	// requires the special key jwt.UnsafeAllowNoneSignatureType.
	// We replicate the on-wire shape manually rather than fight
	// the library.
	header := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0" // {"alg":"none","typ":"JWT"}
	body := "eyJlbnYiOiJkZXYtdXVpZC0xMjM0Iiwibm9uY2UiOiJuLTEyMzQiLCJpc3MiOiJvc2N0cmwtYXBpIiwiYXVkIjpbIm9zY3RybC1hdXRoLXN0YXRlIl0sImV4cCI6OTk5OTk5OTk5OX0"
	tok := header + "." + body + "."
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback", nil)
	req.AddCookie(&http.Cookie{Name: StateCookieName, Value: tok})
	_, err := ParseStateCookie(req, testSecret)
	if !errors.Is(err, ErrStateInvalid) {
		t.Fatalf("expected ErrStateInvalid on alg=none token, got %v", err)
	}
}

// IssueStateCookie must refuse to issue with an empty EnvUUID — that
// would defeat the cross-env mismatch defense (threat T18).
func TestIssueRejectsEmptyEnv(t *testing.T) {
	rec := httptest.NewRecorder()
	err := IssueStateCookie(rec, testSecret, State{Nonce: "n-1234", OAuthState: "s-1234"})
	if err == nil {
		t.Fatal("expected error on empty EnvUUID")
	}
}

// ...and similarly empty Nonce. A missing nonce means the OIDC layer
// can't validate the id_token's nonce claim, which collapses replay
// defense in the protocol.
func TestIssueRejectsEmptyNonce(t *testing.T) {
	rec := httptest.NewRecorder()
	err := IssueStateCookie(rec, testSecret, State{EnvUUID: "dev-uuid-1234", OAuthState: "s-1234"})
	if err == nil {
		t.Fatal("expected error on empty Nonce")
	}
}

// Missing OAuthState — the OAuth2 / SAML RelayState slot — would
// collapse the CSRF defense, the pre-May-2026 implementation's whole
// problem. IssueStateCookie must refuse.
func TestIssueRejectsEmptyOAuthState(t *testing.T) {
	rec := httptest.NewRecorder()
	err := IssueStateCookie(rec, testSecret, State{EnvUUID: "dev-uuid-1234", Nonce: "n-1234"})
	if err == nil {
		t.Fatal("expected error on empty OAuthState")
	}
}

// Defense-in-depth: refuse to issue a cookie that has OAuthState ==
// Nonce. The whole point of splitting them is that they're
// independent random values; allowing a caller to alias them would
// mask a regression that re-introduces the pre-May-2026 problem.
func TestIssueRejectsAliasedNonceAndOAuthState(t *testing.T) {
	rec := httptest.NewRecorder()
	same := "this-is-the-same-value-on-both-slots"
	err := IssueStateCookie(rec, testSecret, State{
		EnvUUID:    "dev-uuid-1234",
		Nonce:      same,
		OAuthState: same,
	})
	if err == nil {
		t.Fatal("expected error when OAuthState == Nonce (must be independent values)")
	}
}

// Backward-compat round trip: a legacy stateClaims emitted by
// pre-split servers (no `os` claim) must parse cleanly and the
// returned State.OAuthState must fall back to the Nonce value. This
// keeps in-flight logins from breaking at upgrade time.
func TestParseLegacyCookieWithoutOAuthState(t *testing.T) {
	// Hand-roll a state cookie like the pre-split code would have
	// emitted — populate the typed claims but with OAuthState
	// blank (the `os` field omits with omitempty).
	now := time.Now().UTC()
	claims := stateClaims{
		EnvUUID: "dev-uuid-1234",
		Nonce:   "legacy-nonce-value",
		// OAuthState deliberately empty
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    stateJWTIssuer,
			Audience:  jwt.ClaimStrings{stateJWTAudience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(StateCookieTTL)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(testSecret)
	if err != nil {
		t.Fatalf("sign legacy cookie: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback", nil)
	req.AddCookie(&http.Cookie{Name: StateCookieName, Value: signed})
	got, err := ParseStateCookie(req, testSecret)
	if err != nil {
		t.Fatalf("legacy cookie should parse, got %v", err)
	}
	if got.Nonce != "legacy-nonce-value" {
		t.Errorf("Nonce: got %q want legacy-nonce-value", got.Nonce)
	}
	if got.OAuthState != "legacy-nonce-value" {
		t.Errorf("OAuthState fallback: got %q want legacy-nonce-value", got.OAuthState)
	}
}

// Cookie attributes (HttpOnly + Secure + SameSite=Lax + path scope)
// are part of the security contract — verify them on every issue.
func TestCookieAttributes(t *testing.T) {
	s := freshState(t)
	rec := httptest.NewRecorder()
	if err := IssueStateCookie(rec, testSecret, s); err != nil {
		t.Fatalf("IssueStateCookie: %v", err)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	c := cookies[0]
	if c.Name != StateCookieName {
		t.Errorf("Name: got %q want %q", c.Name, StateCookieName)
	}
	if !c.HttpOnly {
		t.Error("HttpOnly must be true")
	}
	if !c.Secure {
		t.Error("Secure must be true")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite: got %v want Lax", c.SameSite)
	}
	if c.Path != StateCookiePath {
		t.Errorf("Path: got %q want %q", c.Path, StateCookiePath)
	}
	if c.MaxAge != int(StateCookieTTL.Seconds()) {
		t.Errorf("MaxAge: got %d want %d", c.MaxAge, int(StateCookieTTL.Seconds()))
	}
}

// Verify ClearStateCookie removes the cookie cleanly: MaxAge=-1 and
// preserves the same path scope (else the browser leaves the cookie
// in place because path doesn't match the delete).
func TestClearStateCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	ClearStateCookie(rec)
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie on clear, got %d", len(cookies))
	}
	c := cookies[0]
	if c.MaxAge != -1 {
		t.Errorf("MaxAge: got %d want -1", c.MaxAge)
	}
	if c.Path != StateCookiePath {
		t.Errorf("Path: got %q want %q (must match issue path or the delete is a no-op)", c.Path, StateCookiePath)
	}
}

// IsZero sanity.
func TestStateIsZero(t *testing.T) {
	if !(State{}).IsZero() {
		t.Error("State{} should be zero")
	}
	if (State{EnvUUID: "x"}).IsZero() {
		t.Error("non-empty State should not be zero")
	}
}
