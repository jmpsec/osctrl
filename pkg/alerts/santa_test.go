package alerts

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func santaEvent(decision, path, sha string) map[string]string {
	return map[string]string{
		"decision": decision, "file_path": path, "file_sha256": sha,
		"executing_user": "alice", "team_id": "EQHXZ8M8AV",
	}
}

func TestMatchSantaEvents(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	rules := []AlertRule{
		{Model: ruleWithID(1), Name: "blocks", Source: SourceSantaEvent, MatchType: MatchTypeSubstring, MatchField: "decision", MatchValue: "block", ChannelIDs: "[2]"},
		{Model: ruleWithID(2), Name: "team", Source: SourceSantaEvent, MatchType: MatchTypeRegex, MatchField: "team_id", MatchValue: "^EQHXZ8M8AV$"},
		{Model: ruleWithID(3), Name: "other-node", Source: SourceSantaEvent, NodeUUID: "NODE-B", MatchType: MatchTypeSubstring, MatchValue: ""},
		{Model: ruleWithID(4), Name: "other-env", Source: SourceSantaEvent, EnvironmentID: 9, MatchType: MatchTypeSubstring, MatchValue: ""},
		{Model: ruleWithID(5), Name: "result-rule", Source: SourceResultLog, MatchType: MatchTypeSubstring, MatchValue: "block"},
	}
	rs := compileForTest(t, rules...)

	tests := []struct {
		name   string
		event  map[string]string
		wantID []uint
	}{
		{"blocked execution matches decision and team rules", santaEvent("BLOCK_BINARY", "/tmp/evil", sha), []uint{1, 2}},
		{"allowed execution matches only the team rule", santaEvent("ALLOW_TEAMID", "/Applications/x", sha), []uint{2}},
		{"scoped field does not fall back to other fields", map[string]string{"decision": "ALLOW_BINARY", "file_path": "/tmp/block"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []uint
			for _, h := range rs.MatchSantaEvents(1, "dev", testNode, []map[string]string{tt.event}) {
				got = append(got, h.RuleID)
				require.Equal(t, testNode, h.NodeUUID)
				require.Equal(t, testNode+":"+tt.event["file_sha256"], h.Entity)
			}
			require.Equal(t, tt.wantID, got)
		})
	}

	hits := rs.MatchSantaEvents(1, "dev", testNode, []map[string]string{santaEvent("BLOCK_BINARY", "/tmp/evil", sha)})
	require.Equal(t, "BLOCK_BINARY /tmp/evil sha256="+sha+" user=alice", hits[0].Detail)
	require.Equal(t, []uint{2}, hits[0].Channels)
}

// Event fields are written by the Santa client: they must not break a
// notification into forged lines or overflow the entity column.
func TestMatchSantaEventsUntrustedFields(t *testing.T) {
	rs := compileForTest(t, AlertRule{Model: ruleWithID(1), Name: "all", Source: SourceSantaEvent, MatchType: MatchTypeSubstring, MatchValue: ""})
	ev := santaEvent("BLOCK_BINARY", "/tmp/x\r\nRule: forged\x00", strings.Repeat("é", 200)+"\n")
	hits := rs.MatchSantaEvents(1, "dev", testNode, []map[string]string{ev})
	require.Len(t, hits, 1)
	require.NotContains(t, hits[0].Detail, "\n")
	require.NotContains(t, hits[0].Detail, "\r")
	require.NotContains(t, hits[0].Detail, "\x00")
	require.NotContains(t, hits[0].Entity, "\n")
	require.LessOrEqual(t, len(hits[0].Entity), len(testNode)+1+64)
	require.LessOrEqual(t, len(hits[0].Detail), detailMax)
}

// A stored Santa rule is loaded into the snapshot and reaches the dispatcher
// through the ingest adapter.
func TestSantaRuleLoadsAndDispatches(t *testing.T) {
	m := newTestManager(t)
	_, err := m.CreateRule(AlertRule{Name: "blocks", Source: SourceSantaEvent, MatchType: MatchTypeSubstring, MatchField: "decision", MatchValue: "BLOCK", Enabled: true})
	require.NoError(t, err)
	store := NewStore()
	require.NoError(t, m.LoadSnapshot(store))
	require.False(t, store.Snapshot().empty())

	sink := &recordingSink{}
	matcher := NewIngestMatcher(store, NewSyncWorker(store, nil, nil, sink))
	matcher.MatchSantaEvents(1, "dev", testNode, []map[string]string{
		santaEvent("BLOCK_BINARY", "/tmp/evil", "aa"),
		santaEvent("ALLOW_BINARY", "/bin/ls", "bb"),
	})
	require.Equal(t, 1, sink.count())
	require.Equal(t, "blocks", sink.hits[0].RuleName)

	var nilMatcher *IngestMatcher
	nilMatcher.MatchSantaEvents(1, "dev", testNode, nil)
}
