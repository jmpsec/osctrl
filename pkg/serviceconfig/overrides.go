package serviceconfig

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// overrides.go — saying out loud what a database row changed.
//
// Resolve applies every source=db row on top of flags, environment variables
// and YAML. That precedence is deliberate (it is what makes "Apply & Restart"
// work), but it used to be silent: an operator passing --port 9002 saw the
// service bind 9000 with no log line, no error, and nothing in the docs to
// explain why. Saving one field in the Service Config page stores the WHOLE
// section, so a single edit pins every other field in it too (port, listener,
// host…) and quietly shadows their flags from then on.
//
// The functions here only describe what changed; they never decide anything.

// maxRenderedValue bounds a value in a log line. Sections like
// configEndpoints are long arrays, and a log line is not the place for them.
const maxRenderedValue = 80

// fieldChange is one field a database row changed relative to what the process
// would otherwise have used.
type fieldChange struct {
	Key  string
	From string
	To   string
}

// diffSections compares two JSON renderings of the same section, taken before
// and after a database row was applied.
//
// It returns the fields that differ, sorted by key so the log line is stable.
// whole is true when the section is not a JSON object (an array such as
// configEndpoints) and therefore cannot be compared field by field; in that
// case changes is empty and the caller reports the section as replaced.
func diffSections(before, after string) (changes []fieldChange, whole bool) {
	if before == after {
		return nil, false
	}
	var b, a map[string]json.RawMessage
	if json.Unmarshal([]byte(before), &b) != nil || json.Unmarshal([]byte(after), &a) != nil {
		return nil, true
	}
	for key, newRaw := range a {
		oldRaw, existed := b[key]
		if existed && string(oldRaw) == string(newRaw) {
			continue
		}
		from := "unset"
		if existed {
			from = string(oldRaw)
		}
		changes = append(changes, fieldChange{Key: key, From: from, To: string(newRaw)})
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Key < changes[j].Key })
	return changes, false
}

// describeChanges renders field changes for a log line.
//
// Values are shown only when showValues is true. The caller passes the
// registry's Editable flag: sections that can be edited through the API are
// the non-secret ones by construction (db, redis, jwt, tls, saml, oidc and
// other connection or credential sections are never editable). A row written
// into a non-editable section by hand still gets its field names reported —
// enough to explain a surprise — without its values ever reaching a log.
func describeChanges(changes []fieldChange, showValues bool) string {
	parts := make([]string, 0, len(changes))
	for _, c := range changes {
		if !showValues {
			parts = append(parts, c.Key)
			continue
		}
		parts = append(parts, fmt.Sprintf("%s (%s -> %s)", c.Key, truncate(c.From), truncate(c.To)))
	}
	return strings.Join(parts, ", ")
}

func truncate(s string) string {
	if len(s) <= maxRenderedValue {
		return s
	}
	return s[:maxRenderedValue-3] + "..."
}
