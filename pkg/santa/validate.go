package santa

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrInvalidRule wraps every ValidateRule failure.
var ErrInvalidRule = errors.New("invalid santa rule")

var (
	hex64    = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	hex40    = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	teamIDRe = regexp.MustCompile(`^[0-9A-Za-z]{10}$`)
	uuidRe   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// ValidClientMode reports whether m is a supported Santa client mode.
func ValidClientMode(m string) bool { return m == "MONITOR" || m == "LOCKDOWN" }

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidRule, fmt.Sprintf(format, a...))
}

// ValidateRule checks r and normalizes it in place: hashes lowercase, TEAMID,
// the SIGNINGID team prefix and node UUIDs uppercase.
func ValidateRule(r *Rule) error {
	if len(r.Identifier) > 255 {
		return invalid("identifier too long")
	}
	if len(r.CustomMsg) > 255 {
		return invalid("custom message too long")
	}
	if len(r.CustomURL) > 1024 {
		return invalid("custom URL too long")
	}
	if len(r.ScopeValue) > 255 {
		return invalid("scope value too long")
	}
	switch r.RuleType {
	case "BINARY", "CERTIFICATE":
		if !hex64.MatchString(r.Identifier) {
			return invalid("%s identifier must be 64 hex characters", r.RuleType)
		}
		r.Identifier = strings.ToLower(r.Identifier)
	case "CDHASH":
		if !hex40.MatchString(r.Identifier) {
			return invalid("CDHASH identifier must be 40 hex characters")
		}
		r.Identifier = strings.ToLower(r.Identifier)
	case "TEAMID":
		if !teamIDRe.MatchString(r.Identifier) {
			return invalid("TEAMID identifier must be 10 alphanumeric characters")
		}
		r.Identifier = strings.ToUpper(r.Identifier)
	case "SIGNINGID":
		prefix, rest, ok := strings.Cut(r.Identifier, ":")
		if !ok || prefix == "" || rest == "" {
			return invalid("SIGNINGID identifier must be <teamid|platform>:<signing id>")
		}
		if prefix != "platform" {
			prefix = strings.ToUpper(prefix)
			if !teamIDRe.MatchString(prefix) {
				return invalid("SIGNINGID prefix must be a 10-character team ID or platform")
			}
		}
		r.Identifier = prefix + ":" + rest
	default:
		return invalid("unknown rule type %q", r.RuleType)
	}
	switch r.Policy {
	case "ALLOWLIST", "ALLOWLIST_COMPILER", "BLOCKLIST", "SILENT_BLOCKLIST":
		r.CELExpr = ""
	case "CEL":
		if strings.TrimSpace(r.CELExpr) == "" {
			return invalid("CEL policy requires an expression")
		}
	default:
		return invalid("unknown policy %q", r.Policy)
	}
	switch r.Scope {
	case "env":
		r.ScopeValue = ""
	case "tag":
		if r.ScopeValue == "" {
			return invalid("tag scope requires a tag name")
		}
	case "node":
		if !uuidRe.MatchString(r.ScopeValue) {
			return invalid("node scope requires a UUID")
		}
		r.ScopeValue = strings.ToUpper(r.ScopeValue)
	default:
		return invalid("unknown scope %q", r.Scope)
	}
	if r.CustomURL != "" && !strings.HasPrefix(r.CustomURL, "https://") {
		return invalid("custom URL must start with https://")
	}
	return nil
}
