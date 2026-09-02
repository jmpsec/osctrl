package alerts

import (
	"context"
	"testing"

	"github.com/jmpsec/osctrl/pkg/types"
)

// TestMatchNodeScopedResultRule pins the node-scoping contract: a rule
// with NodeUUID set only matches that node's entries.
func TestMatchNodeScopedResultRule(t *testing.T) {
	rs := compileForTest(t,
		AlertRule{Model: ruleWithID(1), Name: "scoped", Source: SourceResultLog, MatchType: MatchTypeSubstring, MatchValue: "needle", NodeUUID: "UUID-SCOPED"},
		AlertRule{Model: ruleWithID(2), Name: "global", Source: SourceResultLog, MatchType: MatchTypeSubstring, MatchValue: "needle"},
	)
	logs := []types.LogResultData{
		resultEntry("UUID-SCOPED", "file_events", map[string]string{"path": "needle-here"}),
		resultEntry("UUID-OTHER", "file_events", map[string]string{"path": "needle-here"}),
	}
	hits := rs.MatchResultLogs(7, "prod", logs)
	if len(hits) != 3 {
		// scoped fires on UUID-SCOPED only (1), global fires on both (2)
		t.Fatalf("expected 3 hits (1 scoped + 2 global), got %d: %+v", len(hits), hits)
	}
	scopedCount := 0
	for _, h := range hits {
		if h.RuleName == "scoped" {
			scopedCount++
			if h.NodeUUID != "UUID-SCOPED" {
				t.Fatalf("scoped hit on wrong node: %+v", h)
			}
		}
	}
	if scopedCount != 1 {
		t.Fatalf("scoped rule must fire exactly once, got %d", scopedCount)
	}
}

// TestMatchNodeScopedStatusRule pins node scoping on the status path.
func TestMatchNodeScopedStatusRule(t *testing.T) {
	rs := compileForTest(t,
		AlertRule{Model: ruleWithID(1), Name: "scoped-status", Source: SourceStatusLog, MatchType: MatchTypeSubstring, MatchValue: "error", NodeUUID: "UUID-SCOPED"},
	)
	logs := []types.LogStatusData{
		statusEntry("UUID-SCOPED", 2, "error: mine"),
		statusEntry("UUID-OTHER", 2, "error: not mine"),
	}
	hits := rs.MatchStatusLogs(7, "prod", logs)
	if len(hits) != 1 || hits[0].NodeUUID != "UUID-SCOPED" {
		t.Fatalf("scoped status rule must only fire for its node: %+v", hits)
	}
}

// TestInactiveWatcherNodeScopedRule: a node_inactive rule scoped to one
// UUID fires only for that node's transition.
func TestInactiveWatcherNodeScopedRule(t *testing.T) {
	rs := &RuleSet{}
	cr, err := CompileRule(AlertRule{Model: ruleWithID(1), Name: "watch-one", Source: SourceNodeInactive, NodeUUID: "WATCH-U9"})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	rs.nodeInactive = append(rs.nodeInactive, cr)
	store := NewStore()
	store.Publish(rs)
	sink := &recordingSinkRef{}
	worker := NewSyncWorker(store, nil, nil, sink)
	source := &fakeNodeSource{}
	w := newInactiveWatcherWithState(source, store, worker, &memInactiveState{})

	source.setInactive(
		NodeSnapshot{UUID: "WATCH-U9", EnvironmentID: 0, Environment: "prod", Hostname: "target"},
		NodeSnapshot{UUID: "WATCH-U1", EnvironmentID: 0, Environment: "prod", Hostname: "other"},
	)
	w.Sweep(context.Background())
	hits := sink.snapshot()
	if len(hits) != 1 || hits[0].NodeUUID != "WATCH-U9" {
		t.Fatalf("node-scoped inactive rule must only fire for its node: %+v", hits)
	}
}

// TestValidateRuleNodeUUID rejects malformed node scopes before rows
// are stored — a typo would silently create a rule matching nothing.
func TestValidateRuleNodeUUID(t *testing.T) {
	bad := AlertRule{Name: "r", Source: SourceResultLog, MatchType: MatchTypeSubstring, MatchValue: "x", NodeUUID: "not-a-uuid"}
	if err := ValidateRule(bad); err == nil {
		t.Fatal("malformed node_uuid must be rejected")
	}
	good := AlertRule{Name: "r", Source: SourceResultLog, MatchType: MatchTypeSubstring, MatchValue: "x", NodeUUID: "123e4567-e89b-42d3-a456-426614174000"}
	if err := ValidateRule(good); err != nil {
		t.Fatalf("valid node_uuid rejected: %v", err)
	}
	none := AlertRule{Name: "r", Source: SourceResultLog, MatchType: MatchTypeSubstring, MatchValue: "x"}
	if err := ValidateRule(none); err != nil {
		t.Fatalf("empty node_uuid must stay valid: %v", err)
	}
}

// TestRuleCRUDNodeScope verifies the scope round-trips through the
// manager (create, read, update) and the snapshot load.
func TestRuleCRUDNodeScope(t *testing.T) {
	m := newTestManager(t)
	nodeUUID := "123e4567-e89b-42d3-a456-426614174000"
	created, err := m.CreateRule(AlertRule{
		Name: "scoped", Source: SourceResultLog, MatchType: MatchTypeSubstring,
		MatchValue: "x", NodeUUID: nodeUUID, Enabled: true,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.NodeUUID != nodeUUID {
		t.Fatalf("scope not persisted: %q", created.NodeUUID)
	}
	got, err := m.GetRule(created.ID)
	if err != nil || got.NodeUUID != nodeUUID {
		t.Fatalf("read: %v %+v", err, got)
	}
	// Update clears the scope
	updated, err := m.UpdateRule(created.ID, AlertRule{
		Name: "scoped", Source: SourceResultLog, MatchType: MatchTypeSubstring,
		MatchValue: "x", Enabled: true,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.NodeUUID != "" {
		t.Fatalf("update must be able to clear the scope, got %q", updated.NodeUUID)
	}
	// Snapshot load compiles scoped rules into the right bucket with scope intact
	store := NewStore()
	if err := m.LoadSnapshot(store); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	r, _, _ := store.Snapshot().counts()
	if r != 1 {
		t.Fatalf("snapshot expected 1 result rule, got %d", r)
	}
}
