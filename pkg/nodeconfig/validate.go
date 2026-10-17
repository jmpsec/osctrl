// Package nodeconfig validates and applies per-node osquery configuration
// overrides on top of an environment's configuration.
package nodeconfig

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Options that control how osquery talks to osctrl. An override that changes
// them could cut a host off with no way to undo it from osctrl, so they are
// refused. Matching is case-sensitive, as osquery's flags are.
var (
	protectedPrefixes = []string{
		"config_",
		"logger_tls_",
		"distributed_",
		"enroll_",
		"tls_",
	}
	protectedNames = []string{
		"carver_start_endpoint",
		"carver_continue_endpoint",
		"config_plugin",
		"logger_plugin",
		"distributed_plugin",
		"disable_distributed",
		"disable_enrollment",
		"disable_reenrollment",
		"host_identifier",
		"specified_identifier",
		"proxy_hostname",
		"read_max",
	}
)

// Sections of the osquery configuration that osctrl models; when present in an
// override they must be JSON objects.
var objectSections = []string{"options", "schedule", "packs", "decorators", "auto_table_construction"}

// ProtectedOption reports whether an osquery option controls the connection to
// osctrl and so cannot be set by a node override.
func ProtectedOption(name string) bool {
	for _, n := range protectedNames {
		if name == n {
			return true
		}
	}
	for _, p := range protectedPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// Validate checks that an override is a JSON object that is safe to merge: known
// sections are objects, no value is null and no protected option is set.
func Validate(override string) error {
	var v any
	if err := json.Unmarshal([]byte(override), &v); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	top, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("override must be a JSON object")
	}
	for _, s := range objectSections {
		if val, present := top[s]; present {
			if _, isObj := val.(map[string]any); !isObj && val != nil {
				return fmt.Errorf("%q must be a JSON object", s)
			}
		}
	}
	if opts, ok := top["options"].(map[string]any); ok {
		for _, k := range sortedKeys(opts) {
			if ProtectedOption(k) {
				return fmt.Errorf("option %q controls the connection to osctrl and cannot be overridden", k)
			}
		}
	}
	return findNull(top, "")
}

// findNull returns an error naming the dotted path of the first null found.
func findNull(v any, path string) error {
	switch t := v.(type) {
	case nil:
		return fmt.Errorf("null is not allowed at %q", path)
	case map[string]any:
		for _, k := range sortedKeys(t) {
			child := k
			if path != "" {
				child = path + "." + k
			}
			if err := findNull(t[k], child); err != nil {
				return err
			}
		}
	case []any:
		for i, e := range t {
			if err := findNull(e, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
