package oidc

import (
	"regexp"
	"strings"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/rs/zerolog/log"
)

// idTokenClaims captures the OIDC claims we care about. Defined as a
// distinct struct from auth.ResolvedIdentity because the JSON tags
// here must match the OIDC spec verbatim — we read raw id_token
// claims into this shape, then translate into the protocol-neutral
// auth.ResolvedIdentity for callers.
type idTokenClaims struct {
	Subject           string `json:"sub"`
	PreferredUsername string `json:"preferred_username"`
	Email             string `json:"email"`
	Name              string `json:"name"`
	GivenName         string `json:"given_name"`
	FamilyName        string `json:"family_name"`
}

// usernameAllowed mirrors the character class enforced by
// pkg/environments.EnvNameFilter — lowercase ASCII letters, digits,
// dash, underscore. Rejects newlines, semicolons, quotes, slashes,
// spaces, NULs, and any other shell/SQL/HTML metacharacter. Threat T23.
//
// We deliberately do NOT lowercase the IdP-supplied username before
// matching: if the IdP returns "Alice" and the regex demands [a-z]
// only, the validation rejects mixed-case rather than silently
// canonicalizing. The CALLER (cmd/api/handlers/auth_callback.go)
// decides whether to lowercase before reaching this check; the
// package's job is to refuse anything that doesn't already fit the
// safe shape.
//
// The 64-byte cap defeats audit-log poisoning via comically long
// usernames (threat T26 adjacent).
var usernameAllowed = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// pickUsername selects the OIDC claim to use as the AdminUser.Username
// based on the provider's configured UsernameClaim. Always falls back
// to subject when the configured claim is missing or empty — subject
// is the only OIDC claim that's both guaranteed-present and stable
// across user renames in the IdP.
//
// Sanitization happens at the boundary in HandleCallback after this
// returns; pickUsername itself doesn't validate, only selects.
func pickUsername(c idTokenClaims, claim string) string {
	switch claim {
	case DefaultUsernameClaim:
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
	// Unknown or empty claim, or the configured claim was absent on
	// the id_token. Subject is always present on a verified id_token
	// (the OIDC spec mandates it; verification would have failed
	// otherwise).
	return c.Subject
}

// sanitizeUsername enforces the safe character class. Returns the
// username unchanged on success, empty string on rejection. Callers
// must treat the empty return as a hard rejection — never use an
// IdP-supplied value that fails this check, even for logging
// (audit-log poisoning, threat T26).
func sanitizeUsername(u string) string {
	u = strings.TrimSpace(u)
	if !usernameAllowed.MatchString(u) {
		return ""
	}
	return u
}

// hasRequiredGroup returns true if the user's group memberships
// intersect the provider's RequiredGroups list. When RequiredGroups
// is empty the gate is disabled and this function is not invoked by
// the caller.
//
// The IdP-supplied groups claim is consulted as a raw map[string]any
// rather than via a typed Claims() decode because some IdPs (Entra,
// older Auth0) emit groups as objects {id,name} or as a single string
// rather than an array of strings; this function only accepts
// []string-shaped claims for safety. Anything else is logged at WARN
// (server-side, no client-visible disclosure — threat T17) and the
// gate denies access.
func hasRequiredGroup(idToken *gooidc.IDToken, groupsClaim string, requiredGroups []string) bool {
	if len(requiredGroups) == 0 {
		// Sanity guard — callers should not invoke this when the
		// gate is disabled, but if they do, treat absence of a
		// requirement as "no membership required."
		return true
	}
	var all map[string]any
	if err := idToken.Claims(&all); err != nil {
		log.Warn().Err(err).Msg("oidc: failed to decode claims for group check")
		return false
	}
	raw, ok := all[groupsClaim]
	if !ok {
		// Claim wasn't on the token at all. Log at WARN — this
		// is a configuration issue (mapper not attached) more
		// often than a malicious one.
		log.Warn().Msgf("oidc: groups claim %q not present in id_token", groupsClaim)
		return false
	}
	groups, ok := raw.([]any)
	if !ok {
		log.Warn().Msgf("oidc: groups claim %q is not an array", groupsClaim)
		return false
	}
	required := make(map[string]struct{}, len(requiredGroups))
	for _, r := range requiredGroups {
		required[r] = struct{}{}
	}
	for _, g := range groups {
		name, ok := g.(string)
		if !ok {
			continue
		}
		if _, present := required[name]; present {
			return true
		}
	}
	return false
}
