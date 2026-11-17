package santa

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
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
	slices.Sort(c.NotifyChannels)
	c.NotifyChannels = slices.Compact(c.NotifyChannels)
	switch {
	case len(c.NotifyChannels) > MaxNotifyChannels:
		return fmt.Errorf("at most %d notification channels", MaxNotifyChannels)
	case len(c.NotifyChannels) > 0 && c.ApprovalURL == "":
		return errors.New("notification channels need the approval URL")
	}
	local, global := c.VoteLocalThreshold, c.VoteGlobalThreshold
	switch {
	case local > MaxVoteThreshold || global > MaxVoteThreshold:
		return fmt.Errorf("vote thresholds are at most %d", MaxVoteThreshold)
	case local > 0 && global > 0 && global < local:
		return errors.New("the global vote threshold cannot be below the local one")
	case (local > 0 || global > 0) && c.ApprovalURL == "":
		return errors.New("voting needs the approval URL")
	}
	if s := c.FullSyncIntervalSeconds; s != 0 && (s < MinSyncInterval || s > MaxSyncInterval) {
		return fmt.Errorf("sync interval is 0 (Santa default) or %d to %d seconds", MinSyncInterval, MaxSyncInterval)
	}
	if len(c.GroupTags) > MaxGroupTags {
		return fmt.Errorf("at most %d group tags", MaxGroupTags)
	}
	seen := map[GroupTag]bool{}
	gts := c.GroupTags[:0]
	for _, gt := range c.GroupTags {
		gt.Group, gt.Tag = strings.TrimSpace(gt.Group), strings.TrimSpace(gt.Tag)
		if gt.Group == "" || gt.Tag == "" || len(gt.Group) > 255 || len(gt.Tag) > 255 || strings.ContainsAny(gt.Group+gt.Tag, "\r\n") {
			return errors.New("group tags need a group and a tag of at most 255 characters")
		}
		if !seen[gt] {
			seen[gt] = true
			gts = append(gts, gt)
		}
	}
	c.GroupTags = gts
	if a := c.OverrideFileAccessAction; a != "" && a != "NONE" && a != "AUDIT_ONLY" && a != "DISABLE" {
		return fmt.Errorf("invalid file access override %q", a)
	}
	for name, re := range map[string]string{"allowed": c.AllowedPathRegex, "blocked": c.BlockedPathRegex} {
		// Santa uses ICU regexes; RE2 parses their common subset, which catches typos.
		if _, err := regexp.Compile(re); err != nil || len(re) > 1024 || strings.ContainsAny(re, "\r\n") {
			return fmt.Errorf("invalid %s path regex", name)
		}
	}
	c.EventDetailURL = strings.TrimSpace(c.EventDetailURL)
	if c.EventDetailURL != "" {
		// Santa placeholders like %file_sha% are allowed here; they make the URL unparseable as-is.
		u, err := url.Parse(strings.ReplaceAll(c.EventDetailURL, "%", ""))
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || len(c.EventDetailURL) > 1024 {
			return errors.New("event detail URL must be an https URL")
		}
	}
	c.EventDetailText = strings.TrimSpace(c.EventDetailText)
	if utf8.RuneCountInString(c.EventDetailText) > 32 || strings.ContainsAny(c.EventDetailText, "\r\n") {
		return errors.New("event detail text is at most 32 characters on one line")
	}
	return nil
}

// Bounds for a custom full sync interval: every client hits the server this often.
const (
	MinSyncInterval = 60
	MaxSyncInterval = 86400
)

// MaxGroupTags caps the group-to-tag mappings of an environment.
const MaxGroupTags = 100

// MaxVoteThreshold caps both vote thresholds.
const MaxVoteThreshold = 10000

// MaxNotifyChannels caps the alert channels notified of a new request.
const MaxNotifyChannels = 10

// ApprovalDecidePath is the UI route the approve and deny links open, under
// the environment config's ApprovalURL.
const ApprovalDecidePath = "/santa/decide/"

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
