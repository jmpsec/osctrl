package logging

import (
	"encoding/json"
	"testing"

	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/types"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// recordingMatcher captures hook invocations for the ingest tests.
type recordingMatcher struct {
	resultBatches  []int
	statusBatches  []int
	queryResults   []string
	lastEnvID      uint
	lastEnvName    string
	lastResultLogs []types.LogResultData
	lastStatusLogs []types.LogStatusData
}

func (m *recordingMatcher) MatchResultLogs(envID uint, environment string, logs []types.LogResultData) {
	m.resultBatches = append(m.resultBatches, len(logs))
	m.lastEnvID = envID
	m.lastEnvName = environment
	m.lastResultLogs = logs
}

func (m *recordingMatcher) MatchStatusLogs(envID uint, environment string, logs []types.LogStatusData) {
	m.statusBatches = append(m.statusBatches, len(logs))
	m.lastEnvID = envID
	m.lastEnvName = environment
	m.lastStatusLogs = logs
}

func (m *recordingMatcher) MatchQueryResult(envID uint, environment, queryName string, result json.RawMessage, status int, message string) {
	m.queryResults = append(m.queryResults, queryName)
	m.lastEnvID = envID
	m.lastEnvName = environment
}

// TestProcessLogsAlertHookResult verifies the result-log alert tap: the
// matcher sees the decoded batch with env context, before dispatch.
func TestProcessLogsAlertHookResult(t *testing.T) {
	logger := testLoggerWithMatcher(t, &recordingMatcher{})
	data := json.RawMessage(`[{"name":"file_events","columns":{"path":"/etc/shadow"},"hostIdentifier":"NODE-A"}]`)

	returned := logger.ProcessLogs(data, types.ResultLog, 3, "prod", "10.0.0.1", len(data), false)

	if len(returned) != 1 {
		t.Fatalf("ProcessLogs must still return decoded results: %d", len(returned))
	}
	m := logger.Alerts.(*recordingMatcher)
	if len(m.resultBatches) != 1 || m.resultBatches[0] != 1 {
		t.Fatalf("matcher not invoked with the batch: %+v", m.resultBatches)
	}
	if m.lastEnvID != 3 || m.lastEnvName != "prod" {
		t.Fatalf("env context missing: %d %q", m.lastEnvID, m.lastEnvName)
	}
	if m.lastResultLogs[0].HostIdentifier != "NODE-A" {
		t.Fatalf("unexpected entry passed to matcher: %+v", m.lastResultLogs[0])
	}
}

// TestProcessLogsAlertHookStatus verifies the status-log tap decodes the
// full schema for the matcher (metadata-only decode is not enough).
func TestProcessLogsAlertHookStatus(t *testing.T) {
	logger := testLoggerWithMatcher(t, &recordingMatcher{})
	data := json.RawMessage(`[{"severity":"2","message":"error: bad thing happened","hostIdentifier":"NODE-A"}]`)

	logger.ProcessLogs(data, types.StatusLog, 3, "prod", "10.0.0.1", len(data), false)

	m := logger.Alerts.(*recordingMatcher)
	if len(m.statusBatches) != 1 {
		t.Fatalf("status matcher not invoked: %+v", m.statusBatches)
	}
	if len(m.lastStatusLogs) != 1 || m.lastStatusLogs[0].Message != "error: bad thing happened" {
		t.Fatalf("full status decode missing: %+v", m.lastStatusLogs)
	}
	if int(m.lastStatusLogs[0].Severity) != 2 {
		t.Fatalf("severity not decoded: %+v", m.lastStatusLogs[0])
	}
}

// TestProcessLogsNoMatcherIsNoop pins the feature-off contract: with a
// nil matcher ProcessLogs behaves exactly as before.
func TestProcessLogsNoMatcherIsNoop(t *testing.T) {
	logger := testLoggerWithMatcher(t, nil)
	data := json.RawMessage(`[{"name":"x","columns":{"a":"b"},"hostIdentifier":"U"}]`)

	returned := logger.ProcessLogs(data, types.ResultLog, 1, "dev", "10.0.0.1", len(data), false)
	if len(returned) != 1 {
		t.Fatalf("no-matcher path must not change behavior: %d", len(returned))
	}
}

// TestProcessLogQueryResultAlertHook verifies the distributed-query
// tap: one matcher call per answered query, with node env context.
func TestProcessLogQueryResultAlertHook(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	nodeMgr := nodes.CreateNodes(db)
	queryMgr := queries.CreateQueries(db)
	matcher := &recordingMatcher{}
	logger := &LoggerTLS{
		Logging: "none",
		Nodes:   nodeMgr,
		Queries: queryMgr,
		Alerts:  matcher,
	}
	node := nodes.OsqueryNode{NodeKey: "hook-key", UUID: "NODE-H", EnvironmentID: 5, Environment: "prod"}
	if err := db.Create(&node).Error; err != nil {
		t.Fatalf("create node: %v", err)
	}
	query := queries.DistributedQuery{Name: "hook-query", Query: "select 1", Active: true, EnvironmentID: 5}
	if err := queryMgr.Create(&query); err != nil {
		t.Fatalf("create query: %v", err)
	}
	if err := queryMgr.CreateNodeQueries([]uint{node.ID}, query.ID); err != nil {
		t.Fatalf("link node-query: %v", err)
	}

	write := types.QueryWriteRequest{
		Queries:  types.QueryWriteQueries{"hook-query": json.RawMessage(`{"answer":"42"}`)},
		Statuses: types.QueryWriteStatuses{"hook-query": 0},
		NodeKey:  "hook-key",
	}
	logger.ProcessLogQueryResult(write, 5, false)

	if len(matcher.queryResults) != 1 || matcher.queryResults[0] != "hook-query" {
		t.Fatalf("matcher not called per query: %+v", matcher.queryResults)
	}
	if matcher.lastEnvID != 5 || matcher.lastEnvName != "prod" {
		t.Fatalf("env context wrong: %d %q", matcher.lastEnvID, matcher.lastEnvName)
	}
}

// testLoggerWithMatcher builds a LoggerTLS with real node/queries
// managers (DispatchLogs touches them) and the given matcher attached.
func testLoggerWithMatcher(t *testing.T, matcher AlertMatcher) *LoggerTLS {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	nodeMgr := nodes.CreateNodes(db)
	queryMgr := queries.CreateQueries(db)
	return &LoggerTLS{
		Logging: "none",
		Nodes:   nodeMgr,
		Queries: queryMgr,
		Alerts:  matcher,
	}
}
