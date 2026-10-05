package alerts

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"

	"github.com/jmpsec/osctrl/pkg/types"
)

// matcher.go — pure evaluation of decoded logs against a rule snapshot.
//
// Every function here is read-only over the RuleSet and the decoded
// batch: no DB, no Redis, no clock. That keeps the ingest path free of
// I/O and makes the matcher trivially unit-testable. Hits are returned
// (not dispatched) — the caller (Stage 2 ingest hook) decides how to
// queue them.

// Hit is one rule × one entity match, ready for the dispatch worker.
type Hit struct {
	RuleID        uint
	RuleName      string
	EnvironmentID uint
	// Environment is the env name captured at match time, used for the
	// history row and rendered payloads.
	Environment     string
	NodeUUID        string
	Entity          string
	Detail          string
	CooldownMinutes int
	Channels        []uint
}

// detailMax bounds the context stored per hit so a pathological match
// cannot balloon alert history rows or channel payloads.
const detailMax = 1024

// ruleApplies reports whether a compiled rule matches the given env:
// global rules (EnvironmentID 0) apply everywhere, scoped rules only to
// their own env.
func (r *compiledRule) ruleApplies(envID uint) bool {
	return r.env == NoEnvironmentID || r.env == envID
}

// MatchResultLogs evaluates result-log entries against rules scoped to
// envID. The columns of each entry (or its snapshot rows) are matched
// field-scoped or across all fields depending on the rule.
//
// nodeUUID is the node osctrl-tls authenticated the batch as, by node_key.
// Hits are attributed to it, and node-scoped rules are checked against it,
// never against the entries' hostIdentifier: the sender writes that field, so
// trusting it would let a node frame another one, or evade a rule scoped to
// itself by claiming to be someone else.
func (rs *RuleSet) MatchResultLogs(envID uint, environment, nodeUUID string, logs []types.LogResultData) []Hit {
	if len(rs.result) == 0 || len(logs) == 0 {
		return nil
	}
	var hits []Hit
	for i := range logs {
		entry := &logs[i]
		uuid := nodeUUID
		fields := resultFields(entry)
		keys := sortedKeys(fields)
		lowered := make(map[string]string, len(fields))
		for j := range rs.result {
			r := &rs.result[j]
			if !r.ruleApplies(envID) {
				continue
			}
			// Node-scoped rules only see entries from their node.
			if r.nodeScope != "" && r.nodeScope != uuid {
				continue
			}
			if matched, detail := matchFields(r, fields, keys, lowered); matched {
				hits = append(hits, Hit{
					RuleID:          r.id,
					RuleName:        r.name,
					EnvironmentID:   envID,
					Environment:     environment,
					NodeUUID:        uuid,
					Entity:          entityOf(uuid, entry.Name),
					Detail:          truncateDetail(detail),
					CooldownMinutes: r.cooldownMinutes,
					Channels:        r.channels,
				})
			}
		}
	}
	return hits
}

// MatchStatusLogs evaluates status-log entries against rules scoped to
// envID. Entries below the rule's severity floor are skipped before any
// pattern work happens. nodeUUID is the authenticated sender, as for
// MatchResultLogs.
func (rs *RuleSet) MatchStatusLogs(envID uint, environment, nodeUUID string, logs []types.LogStatusData) []Hit {
	if len(rs.status) == 0 || len(logs) == 0 {
		return nil
	}
	var hits []Hit
	for i := range logs {
		entry := &logs[i]
		uuid := nodeUUID
		lowered := make(map[string]string, 3)
		for j := range rs.status {
			r := &rs.status[j]
			if !r.ruleApplies(envID) {
				continue
			}
			// Node-scoped rules only see entries from their node.
			if r.nodeScope != "" && r.nodeScope != uuid {
				continue
			}
			if int(entry.Severity) < r.minSeverity {
				continue
			}
			// Status logs have a fixed, small schema; the only
			// meaningful fields are message / filename / version.
			matched, detail := matchStatus(r, entry, lowered)
			if matched {
				hits = append(hits, Hit{
					RuleID:          r.id,
					RuleName:        r.name,
					EnvironmentID:   envID,
					Environment:     environment,
					NodeUUID:        uuid,
					Entity:          entityOf(uuid, "status"),
					Detail:          truncateDetail(detail),
					CooldownMinutes: r.cooldownMinutes,
					Channels:        r.channels,
				})
			}
		}
	}
	return hits
}

// MatchQueryResult evaluates one on-demand query result (the
// ProcessLogQueryResult tap) against rules scoped to envID. queryName
// scopes the hit to the query; rows is the decoded result payload.
func (rs *RuleSet) MatchQueryResult(envID uint, environment, queryName string, result json.RawMessage, status int, message string) []Hit {
	if len(rs.query) == 0 {
		return nil
	}
	fields, ok := queryResultFields(result, status, message)
	if !ok {
		return nil
	}
	keys := sortedKeys(fields)
	lowered := make(map[string]string, len(fields))
	var hits []Hit
	for j := range rs.query {
		r := &rs.query[j]
		if !r.ruleApplies(envID) {
			continue
		}
		if matched, detail := matchFields(r, fields, keys, lowered); matched {
			hits = append(hits, Hit{
				RuleID:          r.id,
				RuleName:        r.name,
				EnvironmentID:   envID,
				Environment:     environment,
				NodeUUID:        "",
				Entity:          queryName,
				Detail:          truncateDetail(detail),
				CooldownMinutes: r.cooldownMinutes,
				Channels:        r.channels,
			})
		}
	}
	return hits
}

// ─────────────────────────────── field extraction ───────────────────────────────

// resultFields flattens a result entry into lowercase field names mapped
// to string values, parsed once per entry. Snapshot entries (name/action
// columns per row) are expanded into per-row synthetic fields
// row_0_columns_*, …
func resultFields(entry *types.LogResultData) map[string]string {
	fields := map[string]string{
		"name":   entry.Name,
		"action": entry.Action,
	}
	// Columns arrive as either a flat object (name/action columns) or a
	// snapshot array of objects.
	if len(entry.Columns) > 0 && entry.Columns[0] == '{' {
		var cols map[string]string
		if err := json.Unmarshal(entry.Columns, &cols); err == nil {
			for k, v := range cols {
				fields[strings.ToLower(k)] = v
			}
		}
	}
	if len(entry.Snapshot) > 0 && entry.Snapshot[0] == '[' {
		var rows []map[string]string
		if err := json.Unmarshal(entry.Snapshot, &rows); err == nil {
			for idx, row := range rows {
				for k, v := range row {
					fields[queryFieldKey(idx, k)] = v
				}
			}
		}
	}
	return fields
}

// queryFieldKey builds the synthetic key for snapshot row columns.
func queryFieldKey(idx int, k string) string {
	var b strings.Builder
	b.Grow(len("row__columns_") + 4 + len(k))
	b.WriteString("row_")
	b.WriteString(intToString(idx))
	b.WriteString("_columns_")
	b.WriteString(strings.ToLower(k))
	return b.String()
}

func intToString(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return string(rune('0'+i/10)) + intToString(i%10)
}

// queryResultFields flattens a distributed-query result payload. Results
// may be a bare object, an array of objects, or absent (query failed —
// status/message still match).
func queryResultFields(result json.RawMessage, status int, message string) (map[string]string, bool) {
	fields := map[string]string{
		"status":  intToString(status),
		"message": message,
	}
	trimmed := strings.TrimSpace(string(result))
	if trimmed == "" || trimmed == "null" {
		return fields, true
	}
	switch trimmed[0] {
	case '{':
		var cols map[string]string
		if err := json.Unmarshal(result, &cols); err == nil {
			for k, v := range cols {
				fields[strings.ToLower(k)] = v
			}
		}
	case '[':
		var rows []map[string]string
		if err := json.Unmarshal(result, &rows); err == nil {
			for idx, row := range rows {
				for k, v := range row {
					fields[queryFieldKey(idx, k)] = v
				}
			}
		}
	}
	return fields, true
}

// matchStatus evaluates a status-log entry. Only the well-known fields
// participate: message (the default), filename, version. lowered caches
// lowercased values across rules for the same entry.
func matchStatus(r *compiledRule, entry *types.LogStatusData, lowered map[string]string) (bool, string) {
	if !r.matchAny {
		switch r.matchFieldLower {
		case "message":
			return matchSingle(r, entry.Message, "message", lowered)
		case "filename":
			return matchSingle(r, entry.Filename, "filename", lowered)
		case "version":
			return matchSingle(r, entry.Version, "version", lowered)
		default:
			// Unknown scoped field on a status log: no match, never
			// fall back to all-fields (explicit scope is a contract).
			return false, ""
		}
	}
	// Fields in a fixed order rather than through matchFields' map, whose
	// iteration order is random: when several fields match — always the case
	// for the empty pattern of the node page's "any error" preset — the
	// reported detail must be the message, not whichever field came first.
	for _, f := range [...]struct{ key, value string }{
		{"message", entry.Message},
		{"filename", entry.Filename},
		{"version", entry.Version},
	} {
		if matched, detail := matchSingle(r, f.value, f.key, lowered); matched {
			return true, detail
		}
	}
	return false, ""
}

// substringDetail is the context a substring match reports. An empty
// pattern matches everything (the "any error from this node" preset), and
// echoing the empty pattern back would leave the notification with no
// context at all — so fall back to the value that matched.
func substringDetail(pattern, value string) string {
	if pattern == "" {
		return value
	}
	return pattern
}

// matchSingle evaluates one value against the rule, lowering through
// the shared cache.
func matchSingle(r *compiledRule, value, key string, lowered map[string]string) (bool, string) {
	if r.matchRegex != nil {
		if m := r.matchRegex.FindString(value); m != "" {
			return true, m
		}
		return false, ""
	}
	if lv, ok := lowered[key]; ok {
		if strings.Contains(lv, r.matchSubstring) {
			return true, substringDetail(r.matchSubstring, value)
		}
		return false, ""
	}
	lv := strings.ToLower(value)
	lowered[key] = lv
	if strings.Contains(lv, r.matchSubstring) {
		return true, substringDetail(r.matchSubstring, value)
	}
	return false, ""
}

// matchFields evaluates all fields (scoped or not) against the rule.
// For scoped rules the field must exist; for match-any rules every value
// is tried. Values are lowercased at most once per call regardless of
// how many rules share the entry — the caller reuses the lowered map
// across the whole rule slice.
// sortedKeys returns the keys of fields in a fixed order, for matchFields to
// walk instead of the map: Go randomizes map iteration, and when several fields
// match a rule the one visited first supplies the hit's detail. Computed once
// per entry, not per rule.
func sortedKeys(fields map[string]string) []string {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// keys must be the keys of fields in sorted order (see sortedKeys), so that
// match-any rules report the same detail for the same entry every time.
func matchFields(r *compiledRule, fields map[string]string, keys []string, lowered map[string]string) (bool, string) {
	lowerOnce := func(k, v string) string {
		if lv, ok := lowered[k]; ok {
			return lv
		}
		lv := strings.ToLower(v)
		lowered[k] = lv
		return lv
	}
	if !r.matchAny {
		v, ok := fields[r.matchFieldLower]
		if !ok {
			return false, ""
		}
		if r.matchRegex != nil {
			if m := r.matchRegex.FindString(v); m != "" {
				return true, m
			}
			return false, ""
		}
		if strings.Contains(lowerOnce(r.matchFieldLower, v), r.matchSubstring) {
			return true, substringDetail(r.matchSubstring, v)
		}
		return false, ""
	}
	if r.matchRegex != nil {
		for _, k := range keys {
			if m := r.matchRegex.FindString(fields[k]); m != "" {
				return true, m
			}
		}
		return false, ""
	}
	// The empty pattern matches every entry; report the first non-empty
	// value, since a blank field (action often is) would say nothing.
	if r.matchSubstring == "" {
		for _, k := range keys {
			if v := fields[k]; v != "" {
				return true, v
			}
		}
		return true, ""
	}
	for _, k := range keys {
		v := fields[k]
		if strings.Contains(lowerOnce(k, v), r.matchSubstring) {
			return true, substringDetail(r.matchSubstring, v)
		}
	}
	return false, ""
}

// entityOf composes the dedupe entity: node + secondary key (query
// name, or "status" for status logs) so the same rule can alert per
// node per query independently.
func entityOf(uuid, secondary string) string {
	if secondary == "" {
		return uuid
	}
	return uuid + ":" + secondary
}

// truncateDetail bounds a match detail.
func truncateDetail(s string) string {
	if len(s) > detailMax {
		return s[:detailMax-3] + "..."
	}
	return s
}

// CompileRule validates and compiles one rule into its matcher form.
// Returns an error when the regex is invalid or the pattern is too
// long — callers (manager Create/Update) must reject such rules before
// they reach the store.
func CompileRule(rule AlertRule) (compiledRule, error) {
	cr := compiledRule{
		id:              rule.ID,
		name:            rule.Name,
		env:             rule.EnvironmentID,
		nodeScope:       strings.TrimSpace(rule.NodeUUID),
		matchAny:        strings.TrimSpace(rule.MatchField) == "",
		matchFieldLower: strings.ToLower(strings.TrimSpace(rule.MatchField)),
		cooldownMinutes: rule.CooldownMinutes,
	}
	if len(rule.MatchValue) > MaxPatternLen {
		return cr, errPatternTooLong
	}
	switch rule.MatchType {
	case MatchTypeRegex:
		re, err := regexp.Compile(rule.MatchValue)
		if err != nil {
			return cr, err
		}
		cr.matchRegex = re
	case MatchTypeSubstring, "":
		cr.matchSubstring = strings.ToLower(rule.MatchValue)
	default:
		return cr, errInvalidMatchType
	}
	switch strings.ToLower(rule.StatusSeverity) {
	case "error":
		cr.minSeverity = osquerySeverityError
	case "warning", "warn":
		cr.minSeverity = osquerySeverityWarning
	default:
		cr.minSeverity = osquerySeverityInfo
	}
	if err := validateChannels(rule.ChannelIDs, &cr); err != nil {
		return cr, err
	}
	return cr, nil
}
