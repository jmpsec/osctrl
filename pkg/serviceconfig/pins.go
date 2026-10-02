package serviceconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// pins.go — field-level overrides.
//
// A section used to be all-or-nothing: saving one field stored the whole
// section as source=db, and Resolve then applied every field in it over flags,
// environment variables and YAML. Changing a log level silently froze the port.
//
// A row now carries the list of fields the operator actually pinned
// (ServiceConfig.Overrides). Resolve applies only those, and Seed keeps every
// other field in step with the configuration the process started with, so the
// stored value stays an honest picture of what is running.
//
// Granularity is the section's TOP-LEVEL fields. Editing a nested value such as
// rateLimits.Enroll.Burst pins the whole Enroll object, which is also how the
// Service Config page already edits it.

// field is one top-level member of a section's JSON object, in document order.
// Order is kept so a refreshed value reads the same in the UI as the struct it
// was marshalled from, instead of being alphabetised by a map round trip.
type field struct {
	Key string
	Raw json.RawMessage
}

// ErrSectionNotPatchable is returned when a field-level change targets a
// section whose value is not a JSON object (an array such as configEndpoints
// has no fields to pin).
var ErrSectionNotPatchable = fmt.Errorf("section is not a JSON object, replace it as a whole")

// ErrUnknownField is returned when a patch names a field the section does not
// have. Pinning a field that does not exist would be a silent no-op, which is
// the worst way to fail a configuration change.
var ErrUnknownField = fmt.Errorf("unknown field")

// ErrEmptyPatch is returned when a patch neither sets nor releases anything.
var ErrEmptyPatch = fmt.Errorf("patch changes nothing")

// norm is the identity of a field name. encoding/json matches object keys to
// struct fields case-insensitively, so two spellings that unmarshal into the
// same field must be the same field here too, or a key sent in YAML style
// ("logLevel") and the stored Go-style one ("LogLevel") would diverge.
func norm(key string) string { return strings.ToLower(key) }

// orderedFields splits a JSON object into its top-level members, preserving
// order. It returns an error for anything that is not an object.
func orderedFields(raw string) ([]field, error) {
	dec := json.NewDecoder(strings.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("not a JSON object")
	}
	var out []field
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, fmt.Errorf("unexpected object key %v", keyTok)
		}
		var val json.RawMessage
		if err := dec.Decode(&val); err != nil {
			return nil, err
		}
		out = append(out, field{Key: key, Raw: compact(val)})
	}
	// Consume the closing brace, then require the input to end there. Reading
	// the closing brace alone would accept `{"a":1} garbage`.
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("unexpected data after the JSON object")
	}
	return out, nil
}

// compact strips insignificant whitespace so values compare by content.
func compact(raw json.RawMessage) json.RawMessage {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return raw
	}
	return buf.Bytes()
}

// renderFields writes fields back out as a JSON object.
func renderFields(fields []field) (string, error) {
	var b strings.Builder
	b.WriteByte('{')
	for i, f := range fields {
		if i > 0 {
			b.WriteByte(',')
		}
		k, err := json.Marshal(f.Key)
		if err != nil {
			return "", err
		}
		b.Write(k)
		b.WriteByte(':')
		b.Write(f.Raw)
	}
	b.WriteByte('}')
	return b.String(), nil
}

// sameFields reports whether two field lists hold the same keys and values in
// the same order.
func sameFields(a, b []field) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Key != b[i].Key || !bytes.Equal(a[i].Raw, b[i].Raw) {
			return false
		}
	}
	return true
}

// pinSet is the set of fields a row pins, keyed by norm().
type pinSet struct {
	// all means every field is pinned: a row written before pins existed, or
	// replaced as a whole. See ServiceConfig.Overrides.
	all  bool
	keys map[string]bool
}

func (p pinSet) has(key string) bool { return p.all || p.keys[norm(key)] }

// pinSet decodes the pins of a row. A source=yaml row pins nothing whatever
// its Overrides column holds, so a stale column can never resurrect a pin.
func (sc ServiceConfig) pinSet() pinSet {
	if sc.Source != SourceDB {
		return pinSet{keys: map[string]bool{}}
	}
	if strings.TrimSpace(sc.Overrides) == "" {
		return pinSet{all: true}
	}
	var list []string
	if err := json.Unmarshal([]byte(sc.Overrides), &list); err != nil {
		// An unreadable pin list must not quietly turn into "pin nothing",
		// which would drop the operator's edits on the next boot. Pin all.
		return pinSet{all: true}
	}
	keys := make(map[string]bool, len(list))
	for _, k := range list {
		keys[norm(k)] = true
	}
	return pinSet{keys: keys}
}

// encodePins renders canonical field names as the Overrides column value,
// sorted so equal pin sets compare equal.
func encodePins(keys []string) string {
	sorted := append([]string(nil), keys...)
	sort.Strings(sorted)
	raw, err := json.Marshal(sorted)
	if err != nil {
		return ""
	}
	return string(raw)
}

// filterToPins reduces a stored section to only its pinned fields, ready to be
// unmarshalled over the live configuration. A value that is not an object (an
// array section) cannot be filtered and is returned whole.
func filterToPins(value string, pins pinSet) string {
	if pins.all {
		return value
	}
	fields, err := orderedFields(value)
	if err != nil {
		return value
	}
	var kept []field
	for _, f := range fields {
		if pins.has(f.Key) {
			kept = append(kept, f)
		}
	}
	out, err := renderFields(kept)
	if err != nil {
		return value
	}
	return out
}

// mergeUnpinned rebuilds a stored section so that pinned fields keep the
// operator's value and every other field takes the value the process started
// with. Fields appear in the order of fresh, so a refreshed row reads the same
// as a newly seeded one. changed is false when the result equals the stored
// value, so an unchanged boot writes nothing.
//
// A stored value that is not a JSON object is returned untouched.
func mergeUnpinned(stored, fresh string, pins pinSet) (merged string, changed bool) {
	storedFields, err := orderedFields(stored)
	if err != nil {
		return stored, false
	}
	freshFields, err := orderedFields(fresh)
	if err != nil {
		return stored, false
	}
	storedBy := make(map[string]json.RawMessage, len(storedFields))
	for _, f := range storedFields {
		storedBy[norm(f.Key)] = f.Raw
	}
	out := make([]field, 0, len(freshFields))
	for _, f := range freshFields {
		if raw, ok := storedBy[norm(f.Key)]; ok && pins.has(f.Key) {
			out = append(out, field{Key: f.Key, Raw: raw})
			continue
		}
		out = append(out, f)
	}
	if sameFields(storedFields, out) {
		return stored, false
	}
	rendered, err := renderFields(out)
	if err != nil {
		return stored, false
	}
	return rendered, true
}

// canonicalKeys maps each normalised field name of a section to the spelling
// the section already uses.
func canonicalKeys(fields []field) map[string]string {
	out := make(map[string]string, len(fields))
	for _, f := range fields {
		out[norm(f.Key)] = f.Key
	}
	return out
}
