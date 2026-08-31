package alerts

import (
	"encoding/json"
	"testing"

	"github.com/jmpsec/osctrl/pkg/types"
	"gorm.io/gorm"
)

// ruleWithID returns a rule with the model ID set (used in Hit assertions).
func ruleWithID(id uint) gorm.Model {
	return gorm.Model{ID: id}
}

// compileForTest builds a RuleSet from raw rules, failing the test on
// any compile error.
func compileForTest(t *testing.T, rules ...AlertRule) *RuleSet {
	t.Helper()
	rs := &RuleSet{}
	for _, rule := range rules {
		cr, err := CompileRule(rule)
		if err != nil {
			t.Fatalf("CompileRule(%q): %v", rule.Name, err)
		}
		switch rule.Source {
		case SourceResultLog:
			rs.result = append(rs.result, cr)
		case SourceStatusLog:
			rs.status = append(rs.status, cr)
		case SourceQueryLog:
			rs.query = append(rs.query, cr)
		}
	}
	return rs
}

func resultEntry(uuid, name string, columns map[string]string) types.LogResultData {
	raw, _ := json.Marshal(columns)
	return types.LogResultData{
		HostIdentifier: uuid,
		Name:           name,
		Columns:        raw,
	}
}

func statusEntry(uuid string, severity int, message string) types.LogStatusData {
	return types.LogStatusData{
		HostIdentifier: uuid,
		Severity:       types.StringInt(severity),
		Message:        message,
	}
}

func TestMatchResultLogs(t *testing.T) {
	rs := compileForTest(t,
		AlertRule{Model: ruleWithID(1), Name: "any-substring", Source: SourceResultLog, MatchType: MatchTypeSubstring, MatchValue: "MALICIOUS.EXE", ChannelIDs: "[2]"},
		AlertRule{Model: ruleWithID(2), Name: "scoped-regex", Source: SourceResultLog, MatchType: MatchTypeRegex, MatchField: "path", MatchValue: `^/etc/(shadow|sudoers)$`, ChannelIDs: "[2]"},
	)
	logs := []types.LogResultData{
		resultEntry("UUID1", "file_events", map[string]string{"path": "C:\\Users\\malicious.exe", "action": "modified"}),
		resultEntry("UUID2", "file_events", map[string]string{"path": "/etc/shadow"}),
		resultEntry("UUID3", "file_events", map[string]string{"path": "/etc/hostname"}),
	}
	hits := rs.MatchResultLogs(NoEnvironmentID, "dev", logs)
	if len(hits) != 2 {
		t.Fatalf("expected 2 hits, got %d: %+v", len(hits), hits)
	}
	// Hit 1: case-insensitive any-field substring on UUID1.
	if hits[0].RuleName != "any-substring" || hits[0].NodeUUID != "UUID1" {
		t.Fatalf("unexpected hit 0: %+v", hits[0])
	}
	// Hit 2: scoped regex path match on UUID2.
	if hits[1].RuleName != "scoped-regex" || hits[1].NodeUUID != "UUID2" {
		t.Fatalf("unexpected hit 1: %+v", hits[1])
	}
	if hits[1].Entity != "UUID2:file_events" {
		t.Fatalf("entity should include query name: %q", hits[1].Entity)
	}
}

func TestMatchResultLogsScopedFieldMissing(t *testing.T) {
	rs := compileForTest(t,
		AlertRule{Model: ruleWithID(1), Name: "scope", Source: SourceResultLog, MatchType: MatchTypeSubstring, MatchField: "path", MatchValue: "etc"},
	)
	// Entry has no "path" column — scoped rule must not fall back to
	// other fields.
	logs := []types.LogResultData{resultEntry("U", "processes", map[string]string{"name": "/etc value in wrong field"})}
	if hits := rs.MatchResultLogs(NoEnvironmentID, "dev", logs); len(hits) != 0 {
		t.Fatalf("scoped rule matched absent field: %+v", hits)
	}
}

func TestMatchResultLogsSnapshot(t *testing.T) {
	rs := compileForTest(t,
		AlertRule{Model: ruleWithID(1), Name: "snap", Source: SourceResultLog, MatchType: MatchTypeSubstring, MatchValue: "root", MatchField: "row_0_columns_username"},
	)
	snap := []map[string]string{{"username": "root", "host": "box"}}
	raw, _ := json.Marshal(snap)
	logs := []types.LogResultData{{HostIdentifier: "U", Name: "logged_in_users", Snapshot: raw}}
	hits := rs.MatchResultLogs(NoEnvironmentID, "dev", logs)
	if len(hits) != 1 {
		t.Fatalf("expected snapshot match, got %+v", hits)
	}
}

func TestMatchStatusLogs(t *testing.T) {
	rs := compileForTest(t,
		AlertRule{Model: ruleWithID(1), Name: "any-error", Source: SourceStatusLog, MatchType: MatchTypeSubstring, MatchValue: "error", StatusSeverity: "error"},
		AlertRule{Model: ruleWithID(2), Name: "warn-or-worse-any", Source: SourceStatusLog, MatchType: MatchTypeSubstring, MatchValue: "scheduler", StatusSeverity: "warning"},
		AlertRule{Model: ruleWithID(3), Name: "info-ok", Source: SourceStatusLog, MatchType: MatchTypeSubstring, MatchValue: "line"},
	)
	logs := []types.LogStatusData{
		statusEntry("U1", 0, "informational line"),                // matches info-ok only
		statusEntry("U2", 2, "error: scheduler failed"),           // matches all three rules
		statusEntry("U3", 1, "warning: scheduler backoff"),        // matches warn-or-worse + info-ok
		statusEntry("U4", 2, "error: different message entirely"), // matches any-error + info? no line... any-error yes
	}
	hits := rs.MatchStatusLogs(NoEnvironmentID, "dev", logs)
	// U1: info-ok (1). U2: any-error + warn-or-worse + info-ok? "line" not
	// in message... info-ok pattern is "line" and message has no "line":
	// so U2 matches any-error + warn-or-worse (2). U3: warn-or-worse (1).
	// U4: any-error (1). Total 5.
	if len(hits) != 5 {
		t.Fatalf("expected 5 hits, got %d: %+v", len(hits), hits)
	}
}

func TestMatchResultLogsEnvScoping(t *testing.T) {
	// One global rule (env 0) + one rule scoped to env 7.
	rs := compileForTest(t,
		AlertRule{Model: ruleWithID(1), Name: "global", Source: SourceResultLog, MatchType: MatchTypeSubstring, MatchValue: "match"},
		AlertRule{Model: ruleWithID(2), Name: "scoped", EnvironmentID: 7, Source: SourceResultLog, MatchType: MatchTypeSubstring, MatchValue: "match"},
	)
	logs := []types.LogResultData{resultEntry("U", "t", map[string]string{"f": "match-me"})}

	// env 7: both rules apply.
	hits := rs.MatchResultLogs(7, "prod", logs)
	if len(hits) != 2 {
		t.Fatalf("env 7 expected 2 hits, got %d", len(hits))
	}
	// other envs: only the global rule.
	hits = rs.MatchResultLogs(9, "other", logs)
	if len(hits) != 1 || hits[0].RuleName != "global" {
		t.Fatalf("env 9 expected global-only hit, got %+v", hits)
	}
	if hits[0].Environment != "other" || hits[0].EnvironmentID != 9 {
		t.Fatalf("hit env not captured: %+v", hits[0])
	}
}

func TestMatchStatusLogsSeverityFloor(t *testing.T) {
	rs := compileForTest(t,
		AlertRule{Model: ruleWithID(1), Name: "err-only", Source: SourceStatusLog, MatchType: MatchTypeSubstring, MatchValue: "match", StatusSeverity: "error"},
	)
	logs := []types.LogStatusData{
		statusEntry("U1", 0, "match at info"), // below floor — skipped
		statusEntry("U2", 1, "match at warn"), // below floor — skipped
		statusEntry("U3", 2, "match at error"),
	}
	hits := rs.MatchStatusLogs(NoEnvironmentID, "dev", logs)
	if len(hits) != 1 || hits[0].NodeUUID != "U3" {
		t.Fatalf("severity floor not enforced: %+v", hits)
	}
}

func TestMatchQueryResult(t *testing.T) {
	rs := compileForTest(t,
		AlertRule{Model: ruleWithID(1), Name: "q", Source: SourceQueryLog, MatchType: MatchTypeSubstring, MatchValue: "root", MatchField: "username"},
		AlertRule{Model: ruleWithID(2), Name: "q-status", Source: SourceQueryLog, MatchType: MatchTypeSubstring, MatchValue: "nonzero", MatchField: "status"},
	)
	result, _ := json.Marshal(map[string]string{"username": "root", "host": "box"})
	hits := rs.MatchQueryResult(NoEnvironmentID, "dev", "query-42", result, 0, "")
	if len(hits) != 1 || hits[0].RuleName != "q" {
		t.Fatalf("expected username hit only, got %+v", hits)
	}
	// status=0 means success; the q-status rule wants "nonzero"
}

func TestMatchQueryResultFailedQuery(t *testing.T) {
	rs := compileForTest(t,
		AlertRule{Model: ruleWithID(1), Name: "failed", Source: SourceQueryLog, MatchType: MatchTypeSubstring, MatchValue: "1", MatchField: "status"},
	)
	hits := rs.MatchQueryResult(NoEnvironmentID, "dev", "q-fail", nil, 1, "query failed")
	if len(hits) != 1 {
		t.Fatalf("failed-query hit expected: %+v", hits)
	}
	if hits[0].Entity != "q-fail" {
		t.Fatalf("query entity wrong: %+v", hits[0])
	}
}

func TestMatchNoRulesNoWork(t *testing.T) {
	rs := NewStore().Snapshot()
	if hits := rs.MatchResultLogs(NoEnvironmentID, "dev", []types.LogResultData{resultEntry("U", "t", map[string]string{"a": "b"})}); hits != nil {
		t.Fatalf("empty snapshot must not hit: %+v", hits)
	}
	if hits := rs.MatchStatusLogs(NoEnvironmentID, "dev", nil); hits != nil {
		t.Fatalf("empty snapshot must not hit: %+v", hits)
	}
	if hits := rs.MatchQueryResult(NoEnvironmentID, "dev", "q", nil, 0, ""); hits != nil {
		t.Fatalf("empty snapshot must not hit: %+v", hits)
	}
}

func TestCompileRuleRejects(t *testing.T) {
	cases := []struct {
		name string
		rule AlertRule
	}{
		{"bad-regex", AlertRule{Name: "r", Source: SourceResultLog, MatchType: MatchTypeRegex, MatchValue: `([unclosed`}},
		{"too-long", AlertRule{Name: "r", Source: SourceResultLog, MatchType: MatchTypeSubstring, MatchValue: makeString(MaxPatternLen + 1)}},
		{"bad-match-type", AlertRule{Name: "r", Source: SourceResultLog, MatchType: "glob", MatchValue: "x"}},
		{"bad-source", AlertRule{Name: "r", Source: "carrier_pigeon", MatchType: MatchTypeSubstring, MatchValue: "x"}},
		{"bad-channels", AlertRule{Name: "r", Source: SourceResultLog, MatchType: MatchTypeSubstring, MatchValue: "x", ChannelIDs: "{not json"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := ValidateRule(c.rule); err == nil {
				t.Fatalf("expected rejection for %s", c.name)
			}
		})
	}
}

func TestCompileRuleNodeStateSkipsPattern(t *testing.T) {
	// node_inactive rules have no pattern; validation must not require one.
	rule := AlertRule{Name: "offline", Source: SourceNodeInactive, MatchType: MatchTypeSubstring, MatchValue: ""}
	if err := ValidateRule(rule); err != nil {
		t.Fatalf("node_inactive rule rejected: %v", err)
	}
}

func TestStorePublishSwap(t *testing.T) {
	store := NewStore()
	if !store.Snapshot().empty() {
		t.Fatal("new store must be empty")
	}
	rs := compileForTest(t, AlertRule{Model: ruleWithID(1), Name: "r", Source: SourceResultLog, MatchType: MatchTypeSubstring, MatchValue: "x"})
	store.Publish(rs)
	if r, s, q := store.Snapshot().counts(); r != 1 || s != 0 || q != 0 {
		t.Fatalf("unexpected counts: %d %d %d", r, s, q)
	}
	// republish empty
	store.Publish(&RuleSet{})
	if !store.Snapshot().empty() {
		t.Fatal("republish must replace snapshot")
	}
	// nil publish is a no-op safe guard
	store.Publish(nil)
	if !store.Snapshot().empty() {
		t.Fatal("nil publish must yield empty set")
	}
}

func makeString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}
