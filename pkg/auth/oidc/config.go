// Package oidc is the OpenID Connect (RFC 6749 + OIDC Core 1.0)
// implementation of the auth.Provider interface defined in pkg/auth.
//
// The package is intentionally decoupled from osctrl's config and DB
// layers: callers pass a Config struct rather than a viper-bound
// YAML struct. This makes the package reusable from:
//   - cmd/admin (legacy, configured via YAML)
//   - cmd/api (v1, configured via DB row in env_auth_providers)
//   - tests (configured inline)
//
// Security: every operation is bounded by a context deadline (caller
// responsibility), uses the verified go-oidc.Verifier for id_token
// checks, and never logs raw tokens or secrets. See
// docs/proposals/osctrl-auth-providers-v0.1-spec.md §Security.
package oidc

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Default values used when a Config field is left at the zero value.
const (
	// DefaultUsernameClaim is the OIDC claim consulted for the
	// AdminUser.Username field. preferred_username is the most
	// stable choice for human-readable login names that IdPs emit
	// consistently. Configurable via Config.UsernameClaim.
	DefaultUsernameClaim = "preferred_username"

	// DefaultGroupsClaim is the OIDC claim consulted for the
	// RequiredGroups gate (and for the future role-mapping
	// extension point). Both Keycloak and Auth0 emit "groups"
	// by convention when a group-membership mapper is attached.
	DefaultGroupsClaim = "groups"
)

// Config holds everything NewOIDCProvider needs to construct a working
// OIDC client. Callers populate this struct from whatever config source
// they prefer (YAML, DB row, env var) — the package doesn't care.
//
// Field validity is checked once at NewOIDCProvider time. Failed
// validation returns an error rather than panicking so callers can
// surface a clean operator message.
type Config struct {
	// IssuerURL is the OIDC issuer (typically the realm root for
	// Keycloak, the tenant URL for Auth0/Entra, etc.). Must be a
	// well-formed http(s) URL.
	//
	// http:// is permitted but production callers should reject it
	// unless an explicit opt-in flag is set; the package itself
	// allows http to support dev IdPs (Keycloak on localhost) but
	// emits no production guarantees over plaintext.
	IssuerURL string

	// ClientID is the OIDC client identifier registered with the IdP.
	ClientID string

	// ClientSecret is the OIDC client secret. Required for the
	// "confidential client" pattern; may be empty when UsePKCE is
	// true and the client is registered as public.
	ClientSecret string

	// RedirectURL is the absolute callback URL osctrl-api advertises
	// to the IdP. Must match exactly what's registered IdP-side; any
	// drift causes the IdP to reject the authorize request.
	//
	// Must be https in production. The package permits http for the
	// same reason as IssuerURL (dev IdPs) but callers are expected
	// to enforce https for non-dev configs.
	RedirectURL string

	// Scopes are passed verbatim to the authorize endpoint. If empty,
	// the provider injects ["openid", "profile", "email"]. If non-empty
	// without "openid", "openid" is prepended.
	Scopes []string

	// UsernameClaim is the OIDC claim used as the AdminUser.Username.
	// Values: "preferred_username" (default), "email", "sub". An
	// invalid value falls back to "sub" (always available, always
	// stable, but unfriendly to humans).
	UsernameClaim string

	// GroupsClaim is the OIDC claim consulted for group membership.
	// Default: "groups". Used only when RequiredGroups is non-empty.
	GroupsClaim string

	// RequiredGroups, if non-empty, gates HandleCallback so only users
	// whose group claim contains at least one of these strings can
	// authenticate. Empty list disables the gate entirely.
	RequiredGroups []string

	// JITProvision controls whether HandleCallback's downstream
	// caller (cmd/api/handlers/auth_callback.go) should auto-create a
	// new AdminUser on first login. The package itself never creates
	// users; this field is plumbed through ResolvedIdentity-adjacent
	// caller logic.
	//
	// We expose this on Config rather than on the resolved-identity
	// path so per-env policy can vary: some envs JIT, others don't.
	JITProvision bool

	// UsePKCE enables PKCE (RFC 7636) on the authorize + token
	// requests. Recommended for any deployment; mandatory for public
	// clients (those without a client secret).
	UsePKCE bool

	// LegacyPermissiveUsername disables the strict character-class
	// validation on the resolved username, passing the IdP-supplied
	// value (after TrimSpace) directly into ResolvedIdentity.
	// PreferredUsername.
	//
	// New callers MUST leave this false — strict validation is the
	// safe default and prevents audit-log poisoning (T26) and
	// injection-shaped usernames (T23) from reaching downstream
	// code.
	//
	// This flag exists ONLY to preserve backwards compatibility with
	// legacy osctrl-admin deployments where operators may have
	// pre-existing AdminUser rows whose usernames contain `.`, `@`,
	// or spaces (typical when an IdP emits `preferred_username` as
	// an email). Setting this true bypasses the regex but leaves
	// every other verification step intact (signature, iss, aud,
	// exp, nonce, groups).
	//
	// cmd/admin/oidc.go sets this true. cmd/api/handlers/oidc.go
	// MUST leave it false.
	LegacyPermissiveUsername bool
}

// Validate is called by NewOIDCProvider; callers may invoke it
// independently when persisting a Config to verify shape before write.
// Returns the first error encountered; full validation requires fixing
// each error and re-running.
func (c Config) Validate() error {
	if strings.TrimSpace(c.IssuerURL) == "" {
		return errors.New("oidc.Config: IssuerURL is required")
	}
	u, err := url.Parse(c.IssuerURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("oidc.Config: IssuerURL must be a valid http(s) URL: %q", c.IssuerURL)
	}
	if u.Host == "" {
		return fmt.Errorf("oidc.Config: IssuerURL has no host: %q", c.IssuerURL)
	}
	if strings.TrimSpace(c.ClientID) == "" {
		return errors.New("oidc.Config: ClientID is required")
	}
	if strings.TrimSpace(c.ClientSecret) == "" && !c.UsePKCE {
		return errors.New("oidc.Config: ClientSecret is required when UsePKCE is false")
	}
	if strings.TrimSpace(c.RedirectURL) == "" {
		return errors.New("oidc.Config: RedirectURL is required")
	}
	ru, err := url.Parse(c.RedirectURL)
	if err != nil || (ru.Scheme != "http" && ru.Scheme != "https") {
		return fmt.Errorf("oidc.Config: RedirectURL must be a valid http(s) URL: %q", c.RedirectURL)
	}
	if ru.Host == "" {
		return fmt.Errorf("oidc.Config: RedirectURL has no host: %q", c.RedirectURL)
	}
	return nil
}

// effectiveScopes returns the Scopes slice with "openid" guaranteed
// present at the front. Returns the default OIDC scope set when the
// caller supplied none.
func (c Config) effectiveScopes() []string {
	if len(c.Scopes) == 0 {
		return []string{"openid", "profile", "email"}
	}
	for _, s := range c.Scopes {
		if s == "openid" {
			return c.Scopes
		}
	}
	out := make([]string, 0, len(c.Scopes)+1)
	out = append(out, "openid")
	out = append(out, c.Scopes...)
	return out
}

// effectiveUsernameClaim returns UsernameClaim if set and recognized,
// else DefaultUsernameClaim. The provider's pickUsername function
// handles unknown values gracefully (falls back to sub), but having
// the default-normalization in one place keeps tests honest.
func (c Config) effectiveUsernameClaim() string {
	claim := strings.ToLower(strings.TrimSpace(c.UsernameClaim))
	if claim == "" {
		return DefaultUsernameClaim
	}
	return claim
}

// effectiveGroupsClaim returns GroupsClaim if set, else
// DefaultGroupsClaim.
func (c Config) effectiveGroupsClaim() string {
	claim := strings.TrimSpace(c.GroupsClaim)
	if claim == "" {
		return DefaultGroupsClaim
	}
	return claim
}
