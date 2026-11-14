package santa

import (
	"errors"
	"fmt"
	"net/url"
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

// Removable media actions.
const (
	MediaAllow   = "ALLOW"
	MediaBlock   = "BLOCK"
	MediaRemount = "REMOUNT"
)

// remountFlags are the mount options Santa accepts for a remount
// (mountArgsToMask in SNTEndpointSecurityDeviceManager.mm).
var remountFlags = map[string]bool{
	"rdonly": true, "noexec": true, "nosuid": true, "nobrowse": true,
	"noowners": true, "nodev": true, "async": true, "-j": true,
}

// normalizeMedia validates one removable media action and its remount flags,
// returning the flags lowercased and deduplicated. inherit allows "" (use the
// baseline policy).
func normalizeMedia(action string, flags []string, inherit bool) ([]string, error) {
	switch action {
	case MediaAllow, MediaBlock:
		if len(flags) > 0 {
			return nil, fmt.Errorf("remount flags are only valid with %s", MediaRemount)
		}
		return nil, nil
	case MediaRemount:
	case "":
		if inherit && len(flags) == 0 {
			return nil, nil
		}
		fallthrough
	default:
		return nil, fmt.Errorf("invalid removable media action %q", action)
	}
	var out []string
	seen := map[string]bool{}
	for _, f := range flags {
		f = strings.ToLower(strings.TrimSpace(f))
		if !remountFlags[f] {
			return nil, fmt.Errorf("invalid remount flag %q", f)
		}
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s needs at least one remount flag", MediaRemount)
	}
	return out, nil
}

// ValidateConfig checks the settable config fields, normalizes remount flags
// and derives the deprecated BlockUSBMount. An empty RemovableMedia means ALLOW.
func ValidateConfig(c *EnvConfig) error {
	if !ValidClientMode(c.ClientMode) {
		return fmt.Errorf("invalid client mode %q", c.ClientMode)
	}
	if c.RemovableMedia == "" {
		c.RemovableMedia = MediaAllow
	}
	var err error
	if c.RemovableMediaFlags, err = normalizeMedia(c.RemovableMedia, c.RemovableMediaFlags, false); err != nil {
		return err
	}
	if c.EncryptedRemovableMediaFlags, err = normalizeMedia(c.EncryptedRemovableMedia, c.EncryptedRemovableMediaFlags, true); err != nil {
		return fmt.Errorf("encrypted: %w", err)
	}
	c.BlockUSBMount = c.RemovableMedia != MediaAllow // BLOCK or REMOUNT, validated above
	c.ApprovalURL = strings.TrimRight(strings.TrimSpace(c.ApprovalURL), "/")
	if c.ApprovalURL != "" {
		// Santa expands %placeholders% in the URL it is sent, so none may come from here.
		u, err := url.Parse(c.ApprovalURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
			strings.Contains(c.ApprovalURL, "%") || len(c.ApprovalURL) > 255 {
			return errors.New("approval URL must be an https URL without query, fragment or % characters")
		}
	}
	return nil
}

// ApprovalRequestPath is the UI route of the approval request page, under the
// environment config's ApprovalURL.
const ApprovalRequestPath = "/santa/request/"

// ErrInvalidOverride wraps every ValidateModeOverride failure.
var ErrInvalidOverride = errors.New("invalid santa mode override")

// ValidateModeOverride checks o and uppercases a node UUID, like ValidateRule.
func ValidateModeOverride(o *ModeOverride) error {
	bad := func(msg string) error { return fmt.Errorf("%w: %s", ErrInvalidOverride, msg) }
	if !ValidClientMode(o.ClientMode) {
		return bad("mode must be MONITOR or LOCKDOWN")
	}
	switch o.Scope {
	case "tag":
		if o.ScopeValue == "" || len(o.ScopeValue) > 255 {
			return bad("tag scope requires a tag name of at most 255 characters")
		}
	case "node":
		if !uuidRe.MatchString(o.ScopeValue) {
			return bad("node scope requires a UUID")
		}
		o.ScopeValue = strings.ToUpper(o.ScopeValue)
	default:
		return bad("scope must be tag or node")
	}
	return nil
}

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
