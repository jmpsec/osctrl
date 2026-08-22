package utils

import (
	"regexp"
	"strings"
)

// ---------------------------------------------------------------------------
// Username validation.
//
// AdminUser.Username is the join key for user_permissions, user_mfa_*, audit
// records and JWT claims, and it is interpolated into API paths and log lines.
// Everything that accepts an externally-supplied username — federated login
// (OIDC/SAML) today, SCIM provisioning later — funnels through
// SanitizeUsername so the accepted shape is defined in exactly one place.
//
// Two shapes are accepted:
//
//   - Plain: the historical [a-zA-Z0-9_-]{1,64} class, unchanged.
//   - Email: local@domain, for deployments whose IdP identifies users by
//     email address (the common case for Entra ID, Okta and Google
//     Workspace, where NameID and preferred_username are mailboxes).
//
// Both reject newlines, NULs, quotes, semicolons, slashes, spaces, angle
// brackets and every other shell/SQL/HTML metacharacter (threats T23, T26).
// ---------------------------------------------------------------------------

const (
	// MaxPlainUsernameLen caps the historical username shape. The limit
	// defeats audit-log poisoning via comically long usernames.
	MaxPlainUsernameLen = 64
	// MaxEmailUsernameLen is the RFC 5321 maximum length of a forward path,
	// which is the practical ceiling on a real mailbox.
	MaxEmailUsernameLen = 254
)

// plainUsernameAllowed is the original character class, kept verbatim so
// existing accounts and IdP configurations keep validating exactly as before.
var plainUsernameAllowed = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// emailUsernameAllowed is deliberately NARROWER than RFC 5322. The RFC permits
// quotes, slashes, backticks and other characters that are precisely what the
// threat model above exists to keep out; no real-world IdP emits them. The
// structure also encodes the dot rules directly rather than checking them
// separately:
//
//   - the local part is dot-separated runs of safe characters, so a leading
//     dot, a trailing dot and a ".." sequence are all unmatchable — ".." in a
//     username would otherwise be a path-traversal primitive once the value is
//     interpolated into an API path;
//   - each domain label starts and ends alphanumeric (no leading/trailing
//     hyphen), at least one label precedes the TLD, and the TLD is alphabetic.
var emailUsernameAllowed = regexp.MustCompile(
	`^[a-zA-Z0-9_%+-]+(?:\.[a-zA-Z0-9_%+-]+)*` + // local part
		`@` +
		`(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+` + // domain labels
		`[a-zA-Z]{2,}$`, // TLD
)

// IsEmailUsername reports whether a username is email-shaped. Callers that
// need to branch on the two shapes (help text, SCIM attribute mapping) should
// use this rather than searching for "@" themselves.
func IsEmailUsername(u string) bool {
	return strings.Contains(u, "@")
}

// SanitizeUsername enforces the accepted username shape. It returns the
// username to store on success and an empty string on rejection — callers MUST
// treat the empty return as a hard rejection and never reuse the offending
// value, not even for logging (audit-log poisoning, threat T26).
//
// Email-shaped usernames are canonicalized to lowercase. IdPs are not
// consistent about the casing they emit for the same mailbox, and without
// canonicalization "Jane@corp.com" and "jane@corp.com" would be two accounts
// on PostgreSQL (case-sensitive comparison) but collide on MySQL's default
// case-insensitive collation — a difference in identity semantics between
// backends. Plain usernames are deliberately NOT case-folded: they predate
// this function, and folding them would stop existing mixed-case accounts from
// matching their stored row on the next login.
func SanitizeUsername(u string) string {
	u = strings.TrimSpace(u)
	if u == "" {
		return ""
	}
	if IsEmailUsername(u) {
		if len(u) > MaxEmailUsernameLen || !emailUsernameAllowed.MatchString(u) {
			return ""
		}
		return strings.ToLower(u)
	}
	if !plainUsernameAllowed.MatchString(u) {
		return ""
	}
	return u
}
