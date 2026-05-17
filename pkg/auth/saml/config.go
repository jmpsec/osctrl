// Package saml is the SAML 2.0 Web Browser SSO Profile implementation
// of the auth.Provider interface defined in pkg/auth.
//
// The package wraps crewjam/saml's low-level ServiceProvider directly
// (NOT the high-level samlsp middleware) because cmd/api issues its
// own JWT cookies after the SAML round-trip — see
// cmd/api/handlers/auth_jwt.go. Matches the shape of the OIDC
// provider in pkg/auth/oidc.
//
// Security: every operation rejects malformed XML, unsigned
// assertions, audience mismatches, NotBefore/NotOnOrAfter window
// violations, and replays. See
// docs/proposals/osctrl-auth-providers-v0.1-spec.md §"SAML 2.0
// provider design" — threat catalogue S1–S11.
package saml

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Default values applied when a Config field is left at the zero value.
const (
	// DefaultUsernameAttribute is the value of Config.UsernameAttribute
	// when the operator hasn't configured one. Empty means "use the
	// assertion's NameID element verbatim." A non-empty value means
	// "look for a <saml:Attribute Name=...> in the AttributeStatement
	// and use its value."
	//
	// NameID is the SAML spec's primary identity field; most IdPs
	// emit a clean string there (email, employeeID, etc). Operators
	// who need a different identity field (e.g. "uid" from LDAP-
	// backed IdPs) override via --saml-username-attribute.
	DefaultUsernameAttribute = ""

	// DefaultGroupsAttribute is consulted by hasRequiredGroup when
	// the operator hasn't set --saml-groups-attribute. Empty means
	// "no groups gate" — when paired with empty RequiredGroups, the
	// gate is disabled. When RequiredGroups is non-empty but
	// GroupsAttribute is empty, Validate() rejects the config (the
	// operator clearly forgot one of the two).
	DefaultGroupsAttribute = ""

	// DefaultReplayWindow is the maximum clock skew tolerated on
	// assertion NotBefore / NotOnOrAfter validation. 5 minutes
	// matches the SAML spec recommendation. Configurable via
	// Config.ReplayWindow.
	DefaultReplayWindow = 5
)

// Config bundles the parameters cmd/api passes to NewSAMLProvider.
// Decoupled from viper / YAML so the package can be exercised from
// tests without dragging in the config tree.
type Config struct {
	// IDPMetadataURL points at the IdP's published SAML metadata
	// document (XML). The Provider fetches this once at startup,
	// caches the certs and endpoints from it, and refreshes
	// periodically (crewjam handles the cache lifecycle). One of
	// IDPMetadataURL OR IDPMetadataXML must be set.
	IDPMetadataURL string

	// IDPMetadataXML is an alternative to IDPMetadataURL when the
	// operator has the metadata file on disk (e.g. air-gapped
	// deployments). Mutually exclusive with IDPMetadataURL.
	IDPMetadataXML string

	// EntityID is the SP's entity identifier — what the IdP knows
	// us by. Conventionally the metadata URL, e.g.
	// "http://192.168.31.239:8088/api/v1/auth/saml/metadata".
	// Required.
	EntityID string

	// ACSURL is the Assertion Consumer Service URL — where the
	// IdP POSTs the signed SAMLResponse. Must match the value the
	// IdP has registered. Required.
	ACSURL string

	// SignOnURL is the IdP's SSO endpoint we redirect users to.
	// When IDPMetadataURL is provided, this is auto-discovered
	// and the operator-provided value (if any) is ignored. Kept
	// as a config field for operators who hand-paste metadata
	// (IDPMetadataXML) and don't want to embed a full bindings
	// section in the XML.
	SignOnURL string

	// UsernameAttribute names the <saml:Attribute> whose value
	// becomes AdminUser.Username. Empty means "use NameID."
	UsernameAttribute string

	// GroupsAttribute names the <saml:Attribute> whose
	// AttributeValue children carry the user's group memberships.
	// Empty disables the groups gate.
	GroupsAttribute string

	// RequiredGroups is the list of groups at least one of which
	// must be present in the user's assertion for login to succeed.
	// Empty disables the gate.
	RequiredGroups []string

	// JITProvision enables Just-In-Time AdminUser row creation on
	// first successful login. Matches the OIDC field semantics.
	JITProvision bool

	// RequireAssertionSigned MUST be true for production deployments.
	// crewjam's default is true; we expose the field to make the
	// invariant visible in config files. Setting false disables S2
	// defense and is rejected by Validate().
	RequireAssertionSigned bool

	// ReplayWindow is the maximum clock skew tolerated on NotBefore /
	// NotOnOrAfter checks, in minutes. Defaults to DefaultReplayWindow.
	ReplayWindow int

	// LegacyPermissiveUsername bypasses the strict username regex
	// the same way the OIDC config field does. Set true ONLY by
	// the legacy cmd/admin code path which has pre-existing
	// AdminUser rows with email-format usernames. cmd/api leaves
	// it false.
	LegacyPermissiveUsername bool
}

// Validate enforces the structural invariants on Config. Called once
// at startup by NewSAMLProvider before any IdP interaction.
func (c Config) Validate() error {
	if c.IDPMetadataURL == "" && c.IDPMetadataXML == "" {
		return errors.New("saml: IDPMetadataURL or IDPMetadataXML is required")
	}
	if c.IDPMetadataURL != "" && c.IDPMetadataXML != "" {
		return errors.New("saml: IDPMetadataURL and IDPMetadataXML are mutually exclusive")
	}
	if c.IDPMetadataURL != "" {
		if _, err := url.Parse(c.IDPMetadataURL); err != nil {
			return fmt.Errorf("saml: malformed IDPMetadataURL: %w", err)
		}
	}
	if c.EntityID == "" {
		return errors.New("saml: EntityID is required")
	}
	if c.ACSURL == "" {
		return errors.New("saml: ACSURL is required")
	}
	if _, err := url.Parse(c.ACSURL); err != nil {
		return fmt.Errorf("saml: malformed ACSURL: %w", err)
	}
	if !c.RequireAssertionSigned {
		return errors.New("saml: RequireAssertionSigned MUST be true (threat S2 defense)")
	}
	if len(c.RequiredGroups) > 0 && c.GroupsAttribute == "" {
		return errors.New("saml: RequiredGroups set without GroupsAttribute — operator likely forgot to configure the attribute name")
	}
	if c.UsernameAttribute != "" {
		// Attribute names are URIs or shortnames; reject obvious
		// garbage that hints at a config typo.
		if strings.ContainsAny(c.UsernameAttribute, " \t\n\r") {
			return errors.New("saml: UsernameAttribute contains whitespace")
		}
	}
	if c.ReplayWindow < 0 {
		return errors.New("saml: ReplayWindow must be non-negative (minutes)")
	}
	return nil
}

// effectiveReplayWindow returns Config.ReplayWindow or
// DefaultReplayWindow when unset.
func (c Config) effectiveReplayWindow() int {
	if c.ReplayWindow <= 0 {
		return DefaultReplayWindow
	}
	return c.ReplayWindow
}
