// Package auth defines the provider-agnostic federated-identity surface
// for osctrl-api. Concrete provider implementations live in subpackages
// (pkg/auth/oidc and, eventually, pkg/auth/saml).
//
// The package is intentionally minimal — it defines only what every
// provider must implement and what every caller must receive back. All
// protocol details (token verification, claim parsing, PKCE,
// metadata exchange) live in the subpackage.
//
// Security note: this package never logs raw tokens, claims, or secrets.
// Concrete implementations must follow the same rule; see the spec at
// docs/proposals/osctrl-auth-providers-v0.1-spec.md for the full
// hardening rules.
package auth

import (
	"context"
	"net/http"
)

// Type names for the discriminator on env_auth_providers. New protocol
// implementations must register a string here and provide a Provider
// implementation in a subpackage.
const (
	// TypeOIDC identifies an OpenID Connect provider (RFC 6749 +
	// OpenID Connect Core 1.0).
	TypeOIDC = "oidc"

	// TypeSAML is reserved for a future SAML 2.0 provider; not yet
	// implemented. Holding the constant prevents accidental
	// shadowing in subpackages and signals intent in the API.
	TypeSAML = "saml"
)

// Provider is the contract every federated-identity backend must
// implement. A single Provider instance corresponds to one configured
// IdP for one osctrl environment.
//
// All methods are context-aware. Implementations MUST honor context
// cancellation on any outbound network calls (token endpoint,
// JWKS fetch, etc.) so a slow IdP cannot wedge an HTTP handler.
type Provider interface {
	// Type returns the discriminator that identifies the protocol.
	// Must match one of the Type* constants above.
	Type() string

	// LoginURL builds the URL the user's browser is redirected to in
	// order to start the authentication flow. The State is opaque to
	// the caller; the caller is responsible for transporting it back
	// to HandleCallback via a state cookie (see pkg/auth/state.go).
	//
	// Implementations MUST embed unguessable nonces / verifiers in the
	// returned URL and the State so the callback can detect CSRF and
	// replay attempts. See threat IDs T6, T7, T9 in the spec.
	LoginURL(ctx context.Context, state State) (string, error)

	// HandleCallback consumes the provider's callback request,
	// validates everything (signature, issuer, audience, expiry,
	// nonce, PKCE verifier as applicable) and returns a
	// ResolvedIdentity describing the authenticated user.
	//
	// The State argument is the State that the caller previously
	// transported via cookie. Implementations MUST treat any
	// mismatch as a fatal authentication failure and MUST NOT
	// continue to user resolution. See threat IDs T6, T18.
	//
	// Implementations MUST NOT return raw tokens, claims, or
	// provider error bodies in the error message; those go to
	// server-side structured logging only. See spec hardening rule
	// "no raw token logging".
	HandleCallback(ctx context.Context, r *http.Request, state State) (ResolvedIdentity, error)
}

// ResolvedIdentity is the protocol-neutral output of a successful
// HandleCallback. Callers translate this into an osctrl AdminUser via
// the JIT resolution path (cmd/api/handlers/auth_callback.go); see
// docs/proposals/osctrl-auth-providers-v0.1-spec.md §JIT.
//
// All string fields except Subject may be empty. Subject MUST be
// stable for the lifetime of the IdP-side user account; callers
// rely on it as the cross-login identifier.
type ResolvedIdentity struct {
	// Subject is the stable, opaque identifier issued by the IdP
	// (typically the `sub` claim in OIDC). Never an email, never a
	// preferred name — those can change. Callers that need to
	// preserve identity across renames MUST use Subject.
	Subject string

	// PreferredUsername is what the user sees and types. Defaults to
	// the OIDC `preferred_username` claim; configurable per-provider
	// to fall back to email or sub. Used as the AdminUser.Username
	// after passing validation.
	PreferredUsername string

	// Email is informational; do NOT use it as a stable identifier
	// (mutable in most IdPs; spoofable in poorly-configured ones —
	// see threat T24).
	Email string

	// Name is the human display name (OIDC `name` claim) or a
	// concatenation of given+family if absent.
	Name string

	// Groups carries the user's IdP group memberships (after the
	// optional protocol-mapper claim shaping). v1 uses this only for
	// the RequiredGroups gate; future versions may map groups to
	// osctrl roles. See spec §"What this design does NOT do".
	Groups []string

	// Raw exposes the underlying provider-specific claim set for
	// debugging and future feature work. Callers MUST NOT read Raw
	// to bypass any of the typed fields above; that would defeat the
	// validation layer. Always nil for SAML when it lands; OIDC sets
	// it after id_token verification.
	Raw map[string]any

	// IDToken is the raw, signed id_token bytes the IdP returned.
	// Already verified at this point (sig + iss + aud + exp + nonce
	// checks all passed). The caller's only legitimate use is
	// id_token_hint on RP-initiated logout — DO NOT use it as an
	// authentication credential anywhere else. Empty for SAML.
	IDToken string
}

// State is the per-login data the caller must round-trip from
// LoginURL through the user's browser to HandleCallback. It is opaque
// to the user (transported in an HttpOnly cookie) but its claim shape
// is part of the contract between the auth handler and the provider.
//
// Implementations may add unexported provider-specific fields by
// embedding State in a protocol-specific extension type kept inside
// the provider subpackage.
type State struct {
	// EnvUUID locks this State to a specific osctrl environment.
	// Callbacks for env A using state issued for env B MUST be
	// rejected — see threat T18 (cross-env auth confusion).
	EnvUUID string

	// Nonce is a 256-bit cryptorandom value. For OIDC, this is
	// embedded in the authorize URL via the `nonce` parameter and
	// must match the `nonce` claim on the returned id_token. Other
	// protocols may or may not use it; the field is always
	// populated regardless.
	Nonce string

	// Verifier is the PKCE code_verifier (RFC 7636) when the
	// provider has PKCE enabled. Empty otherwise. The callback
	// presents this to the token endpoint along with the code; the
	// IdP recomputes the challenge and compares.
	//
	// Empty Verifier with a PKCE-enabled provider MUST cause
	// HandleCallback to reject — see threat T10.
	Verifier string
}

// IsZero reports whether the State is the zero value, useful for
// callers that need to distinguish "missing state" from "valid state
// with zero fields".
func (s State) IsZero() bool {
	return s == State{}
}
