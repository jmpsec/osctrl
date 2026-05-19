package saml

import (
	"regexp"
	"strings"

	crewjam "github.com/crewjam/saml"
)

// Common SAML attribute names. SAML doesn't have a "standard" claim set
// the way OIDC does — instead there are several long-form URI naming
// conventions in wide use. We cover the OASIS-recommended
// urn:oid:* names (LDAP-derived) and the X.500 short names.
const (
	samlAttrEmailAddress = "urn:oid:0.9.2342.19200300.100.1.3"   // RFC822 mailbox
	samlAttrGivenName    = "urn:oid:2.5.4.42"                    // givenName
	samlAttrSurname      = "urn:oid:2.5.4.4"                     // sn
	samlAttrCommonName   = "urn:oid:2.5.4.3"                     // cn
	samlAttrUID          = "urn:oid:0.9.2342.19200300.100.1.1"   // LDAP uid
	samlAttrEduPerson    = "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"    // eduPersonPrincipalName
)

// usernameAllowed mirrors pkg/auth/oidc's regex verbatim. Same threat
// model: reject newlines, NULs, shell/SQL metacharacters, anything that
// could survive a sanitization boundary and reach audit logs, file
// paths, or templated SQL.
var usernameAllowed = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// pickSAMLUsername chooses the username for the AdminUser row from the
// assertion's available identity fields. Lookup order:
//
//  1. If Config.UsernameAttribute is non-empty AND that attribute is
//     present on the assertion, use it. Single-valued only — if the
//     IdP emits multiple values, we take the first.
//  2. Otherwise (or if the configured attribute is absent), fall back
//     to NameID, which SAML guarantees is present on a valid assertion.
//
// Sanitization happens at the boundary in HandleCallback after this
// returns; pickSAMLUsername itself doesn't validate, only selects.
func pickSAMLUsername(nameID string, attrs map[string][]string, configuredAttr string) string {
	if configuredAttr != "" && attrs != nil {
		if vals, ok := attrs[configuredAttr]; ok && len(vals) > 0 && vals[0] != "" {
			return vals[0]
		}
		// FriendlyName fallback: operators often configure
		// "username" or "uid" as the FriendlyName even though the
		// canonical Name is a long urn:oid:* URI. The attribute
		// collector indexes under both.
	}
	return nameID
}

// sanitizeUsername — same as OIDC's version. Reuse the regex; reject
// anything that doesn't fit the safe shape. See pkg/auth/oidc/claims.go
// for the threat-model rationale.
func sanitizeUsername(u string) string {
	u = strings.TrimSpace(u)
	if !usernameAllowed.MatchString(u) {
		return ""
	}
	return u
}

// collectAttributes flattens an Assertion's AttributeStatements into a
// map keyed by both Name and FriendlyName, with values as []string so
// multi-valued attributes (memberships, group lists) survive.
//
// SAML allows multiple AttributeStatements per assertion (rare in
// practice, but the spec permits it). We merge across all of them.
//
// Indexing by both Name and FriendlyName lets operators configure
// either form in --saml-groups-attribute / --saml-username-attribute.
// Collisions are unlikely (Name and FriendlyName of different
// attributes overlapping is a misconfigured IdP), but if one occurs
// the later attribute wins — same as Go's map semantics.
func collectAttributes(assertion *crewjam.Assertion) map[string][]string {
	out := make(map[string][]string)
	if assertion == nil {
		return out
	}
	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			values := make([]string, 0, len(attr.Values))
			for _, v := range attr.Values {
				if v.Value != "" {
					values = append(values, v.Value)
				}
			}
			if len(values) == 0 {
				continue
			}
			if attr.Name != "" {
				out[attr.Name] = append(out[attr.Name], values...)
			}
			if attr.FriendlyName != "" && attr.FriendlyName != attr.Name {
				out[attr.FriendlyName] = append(out[attr.FriendlyName], values...)
			}
		}
	}
	return out
}

// firstAttribute returns the first non-empty value across the given
// attribute name candidates. Used for the "the IdP might call this
// attribute any of three things" lookups (email, displayName).
func firstAttribute(attrs map[string][]string, names ...string) string {
	for _, n := range names {
		if vs, ok := attrs[n]; ok {
			for _, v := range vs {
				if v != "" {
					return v
				}
			}
		}
	}
	return ""
}

// hasSAMLRequiredGroup returns true if any of the user's groups appears
// in the RequiredGroups list. Disabled when groupsAttr is empty or
// required is empty — callers should not invoke in either case, but
// be defensive.
func hasSAMLRequiredGroup(attrs map[string][]string, groupsAttr string, required []string) bool {
	if groupsAttr == "" || len(required) == 0 {
		return true
	}
	got, ok := attrs[groupsAttr]
	if !ok || len(got) == 0 {
		return false
	}
	want := make(map[string]struct{}, len(required))
	for _, r := range required {
		want[r] = struct{}{}
	}
	for _, g := range got {
		if _, present := want[g]; present {
			return true
		}
	}
	return false
}

// decodeSAMLGroups extracts the user's group memberships for surfacing
// on ResolvedIdentity. Returns nil when groupsAttr is unset or absent
// — same nil-vs-empty contract as OIDC's decodeGroups.
func decodeSAMLGroups(attrs map[string][]string, groupsAttr string) []string {
	if groupsAttr == "" {
		return nil
	}
	got, ok := attrs[groupsAttr]
	if !ok || len(got) == 0 {
		return nil
	}
	out := make([]string, 0, len(got))
	for _, g := range got {
		if g != "" {
			out = append(out, g)
		}
	}
	return out
}
