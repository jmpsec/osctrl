package nodeconfig

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Flags that control how osquery talks to osctrl, as for options: an override
// that changes them could cut a host off, so they are refused. A "no" prefix
// (gflags negation) of a protected flag is protected too.
var (
	protectedFlagPrefixes = []string{"tls_", "config_", "logger_tls_", "distributed_tls_", "enroll_"}
	protectedFlagNames    = []string{
		"config_plugin", "logger_plugin", "distributed_plugin", "disable_distributed",
		"disable_enrollment", "disable_reenrollment", "host_identifier", "specified_identifier",
		"flagfile", "database_path", "db_path", "carver_start_endpoint", "carver_continue_endpoint",
		"proxy_hostname", "read_max", "force",
	}
)

// flagLine matches "--name", "--name=value" and the single-dash forms.
var flagLine = regexp.MustCompile(`^(-{1,2})([A-Za-z0-9_]+)(=.*)?$`)

// ProtectedFlag reports whether an osquery flag controls the connection to
// osctrl and so cannot be set by a node flags override.
func ProtectedFlag(name string) bool {
	if protectedFlagExact(name) {
		return true
	}
	rest, ok := strings.CutPrefix(name, "no")
	return ok && protectedFlagExact(rest)
}

func protectedFlagExact(name string) bool {
	for _, n := range protectedFlagNames {
		if name == n {
			return true
		}
	}
	for _, p := range protectedFlagPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// flagOf parses a flagfile line into its dash prefix, name and "=value" suffix.
// ok is false for blank lines, comments and anything that is not a flag.
func flagOf(line string) (dashes, name, value string, ok bool) {
	m := flagLine.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return "", "", "", false
	}
	return m[1], m[2], m[3], true
}

func skippable(line string) bool {
	line = strings.TrimSpace(line)
	return line == "" || strings.HasPrefix(line, "#")
}

// ValidateFlagsOverride checks that an override is a list of osquery flags, one
// per line, with no protected flag, no flag repeated and at least one flag.
// Blank lines and # comments are ignored.
func ValidateFlagsOverride(override string) error {
	seen := map[string]int{}
	for i, line := range strings.Split(override, "\n") {
		if skippable(line) {
			continue
		}
		_, name, _, ok := flagOf(line)
		if !ok {
			return fmt.Errorf("line %d is not a flag (expected --name or --name=value): %q", i+1, strings.TrimSpace(line))
		}
		if ProtectedFlag(name) {
			return fmt.Errorf("line %d: flag %q controls the connection to osctrl and cannot be overridden", i+1, name)
		}
		if first, dup := seen[name]; dup {
			return fmt.Errorf("line %d: flag %q is already set on line %d", i+1, name, first)
		}
		seen[name] = i + 1
	}
	if len(seen) == 0 {
		return fmt.Errorf("override must contain at least one flag")
	}
	return nil
}

// MergeFlags applies a flags override to an environment flagfile. Each override
// flag replaces every environment line with the same name in place, keeping that
// line's dash prefix; flags the environment lacks are appended in override
// order. The output is deterministic for the same inputs.
func MergeFlags(envFlags, override string) (string, error) {
	if err := ValidateFlagsOverride(override); err != nil {
		return "", err
	}
	values := map[string]string{}
	var order []string
	for _, line := range strings.Split(override, "\n") {
		if skippable(line) {
			continue
		}
		dashes, name, value, _ := flagOf(line)
		values[name] = value
		order = append(order, dashes+name+value)
	}
	used := map[string]bool{}
	lines := strings.Split(envFlags, "\n")
	for i, line := range lines {
		dashes, name, _, ok := flagOf(line)
		if !ok {
			continue
		}
		if v, set := values[name]; set {
			lines[i] = dashes + name + v
			used[name] = true
		}
	}
	out := strings.Join(lines, "\n")
	var extra []string
	for _, l := range order {
		_, name, _, _ := flagOf(l)
		if !used[name] {
			extra = append(extra, l)
		}
	}
	if len(extra) > 0 {
		out += "\n" + strings.Join(extra, "\n")
	}
	return out, nil
}

// FlagOptionConflicts returns, sorted, the flag names of a flags override that
// are also keys of "options" in any of the given JSON configurations. Flags and
// options both set osquery options, so the same one in both is ambiguous.
// Configurations that are not valid JSON are ignored.
func FlagOptionConflicts(override string, configs ...string) []string {
	options := map[string]bool{}
	for _, c := range configs {
		var cfg struct {
			Options map[string]json.RawMessage `json:"options"`
		}
		if json.Unmarshal([]byte(c), &cfg) != nil {
			continue
		}
		for k := range cfg.Options {
			options[k] = true
		}
	}
	set := map[string]bool{}
	for _, line := range strings.Split(override, "\n") {
		if _, name, _, ok := flagOf(line); ok && options[name] {
			set[name] = true
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
