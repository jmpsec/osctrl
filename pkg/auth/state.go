package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// StateCookieName is the HttpOnly cookie that transports the per-login
// State from the LoginURL handler to the callback handler. The cookie
// path is scoped under /api/v1/auth/ so it never gets sent on other
// endpoints; the SPA's token cookie lives at /.
const StateCookieName = "osctrl_auth_state"

// StateCookiePath restricts the cookie scope. Callers must mount the
// auth routes at this prefix; if they don't, the cookie will not be
// sent on the callback request and HandleCallback will reject with
// ErrStateMissing.
const StateCookiePath = "/api/v1/auth/"

// StateCookieTTL is how long a login attempt can be in flight before
// the state JWT expires. Ten minutes accommodates an MFA prompt + IdP
// interstitials with margin; longer than this and we're inviting
// replay risk against the IdP's auth_time enforcement.
const StateCookieTTL = 10 * time.Minute

// stateJWTAudience scopes state JWTs to this purpose so they cannot
// be used as user-authentication tokens (the api's regular JWT has a
// different audience). Token confusion is threat T19.
const stateJWTAudience = "osctrl-auth-state"

// stateJWTIssuer identifies the issuer; matches what
// pkg/users.CreateToken emits for user JWTs, but the audience claim
// segregates the two.
const stateJWTIssuer = "osctrl-api"

// stateNonceBytes is the entropy of the random nonce we put in the
// State.Nonce field. 256 bits is well past the practical-collision
// threshold even with unlimited online queries.
const stateNonceBytes = 32

// Errors returned by IssueStateCookie / ParseStateCookie. Callers should
// match on these (via errors.Is) to map to HTTP status codes; the strings
// are stable and may appear in logs but never in user-facing error
// responses (we never reveal which check failed — see threat T31, T22).
var (
	// ErrStateMissing is returned when the state cookie is not on the
	// request at all. Callback handlers map this to 403 with no body
	// (the legitimate flow always has the cookie because LoginURL set
	// it).
	ErrStateMissing = errors.New("auth: state cookie missing")

	// ErrStateInvalid is returned for any structural problem with the
	// state JWT — bad signature, wrong audience, expired, missing
	// claims, etc. Deliberately one error so external observers
	// cannot distinguish "tampered" from "expired" from "wrong
	// audience" via timing or status code. Threat T31.
	ErrStateInvalid = errors.New("auth: state cookie invalid")
)

// stateClaims is the JWT body for the state cookie. Wrapping
// jwt.RegisteredClaims gives us iss/aud/exp/nbf/iat for free.
type stateClaims struct {
	EnvUUID  string `json:"env"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"v,omitempty"`
	jwt.RegisteredClaims
}

// IssueStateCookie writes the per-login state cookie. The state JWT is
// HMAC-SHA256 signed with the provided secret (typically the same
// secret pkg/users uses for user JWTs; audience claim segregates the
// two purposes — see threat T19).
//
// secret length is not validated here because pkg/users already enforces
// MinJWTSecretBytes >= 32 at startup. If a caller manages to pass a
// shorter secret, HS256 signing will still succeed but is below RFC 7518
// recommendation; the existing startup gate is the right place to
// enforce this, not this hot path.
//
// IssueStateCookie sets the cookie with HttpOnly + Secure + SameSite=Lax
// + Path=/api/v1/auth/. The Secure flag means production deployments
// MUST use HTTPS for the callback URL; this is intentional. Dev mode
// with HTTP is not supported by this helper (use the SetSecure override
// only via the standard library if you really need it for local testing
// — production code paths must keep Secure=true).
func IssueStateCookie(w http.ResponseWriter, secret []byte, state State) error {
	if state.EnvUUID == "" {
		return fmt.Errorf("auth: IssueStateCookie: empty EnvUUID")
	}
	if state.Nonce == "" {
		return fmt.Errorf("auth: IssueStateCookie: empty Nonce")
	}
	now := time.Now().UTC()
	claims := stateClaims{
		EnvUUID:  state.EnvUUID,
		Nonce:    state.Nonce,
		Verifier: state.Verifier,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    stateJWTIssuer,
			Audience:  jwt.ClaimStrings{stateJWTAudience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(StateCookieTTL)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(secret)
	if err != nil {
		// Should be impossible — HS256 signing only fails on
		// malformed claims, and we control the struct.
		return fmt.Errorf("auth: state JWT sign: %w", err)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     StateCookieName,
		Value:    signed,
		Path:     StateCookiePath,
		MaxAge:   int(StateCookieTTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// ParseStateCookie reads the state cookie off the request, verifies
// the JWT, and returns the decoded State.
//
// Verification enforces, in order:
//  1. Cookie present (else ErrStateMissing)
//  2. HS256 algorithm pinned (defeats alg-confusion; defense in depth
//     since jwt.ParseWithClaims's key callback also rejects non-HMAC,
//     but explicit is better than implicit for auth code)
//  3. Signature valid under `secret`
//  4. iss == "osctrl-api"
//  5. aud == "osctrl-auth-state" (defeats token confusion T19)
//  6. exp > now (clock skew tolerance: 0 — state cookies are short-lived)
//  7. nbf <= now (paranoid; should always hold for non-malicious tokens)
//  8. EnvUUID + Nonce non-empty (rejects malformed body)
//
// Any single failure returns ErrStateInvalid. The internal failure
// reason is loggable for ops but never surfaced to the user.
func ParseStateCookie(r *http.Request, secret []byte) (State, error) {
	c, err := r.Cookie(StateCookieName)
	if err != nil {
		return State{}, ErrStateMissing
	}
	if c.Value == "" {
		return State{}, ErrStateMissing
	}
	claims := &stateClaims{}
	tok, err := jwt.ParseWithClaims(c.Value, claims, func(t *jwt.Token) (interface{}, error) {
		// Pin HS256. The library's default already rejects "none"
		// and the public-key algs, but be explicit on auth code
		// paths.
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %s", t.Header["alg"])
		}
		return secret, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || tok == nil || !tok.Valid {
		return State{}, ErrStateInvalid
	}
	// jwt.ParseWithClaims already validated exp / nbf / signature.
	// Now check the application-level claims that the library doesn't
	// know about.
	if claims.Issuer != stateJWTIssuer {
		return State{}, ErrStateInvalid
	}
	hasAudience := false
	for _, a := range claims.Audience {
		if a == stateJWTAudience {
			hasAudience = true
			break
		}
	}
	if !hasAudience {
		return State{}, ErrStateInvalid
	}
	if strings.TrimSpace(claims.EnvUUID) == "" || strings.TrimSpace(claims.Nonce) == "" {
		return State{}, ErrStateInvalid
	}
	return State{
		EnvUUID:  claims.EnvUUID,
		Nonce:    claims.Nonce,
		Verifier: claims.Verifier,
	}, nil
}

// ClearStateCookie removes the state cookie. Callers MUST invoke this
// immediately after a successful ParseStateCookie so that a replay of
// the callback URL fails (threat T8 / T9 — single-use state). The
// cookie is set with MaxAge=-1 which the browser interprets as
// "delete now."
func ClearStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     StateCookieName,
		Value:    "",
		Path:     StateCookiePath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// NewNonce returns a fresh 256-bit cryptorandom nonce, base64url-encoded
// without padding. Suitable for State.Nonce, State.Verifier, or any
// other value that must be unguessable and URL-safe.
//
// Errors only on crypto/rand failure, which on supported platforms
// means the system is too broken to be doing crypto at all. Callers
// should propagate the error (500 Internal Server Error) rather than
// retry.
func NewNonce() (string, error) {
	b := make([]byte, stateNonceBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
