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

// openBenchDB opens a fresh in-memory SQLite database for a benchmark.
func openBenchDB(b *testing.B) (*gorm.DB, error) {
	b.Helper()
	return gorm.Open(sqlite.Open("file::memory:"), &gorm.Config{})
}

// benchNodeManager builds a nodes manager over the bench database.
func benchNodeManager(b *testing.B, db *gorm.DB) *nodes.NodeManager {
	b.Helper()
	return nodes.CreateNodes(db)
}

// benchQueryManager builds a queries manager over the bench database.
func benchQueryManager(b *testing.B, db *gorm.DB) *queries.Queries {
	b.Helper()
	return queries.CreateQueries(db)
}

// bench_alerts_test.go — Stage-7 load validation for the ingest path.
//
// The alert contract from Stage 0: attaching the matcher must not
// regress ProcessLogs latency beyond ~5% when no rules match, and must
// stay well under budget when rules do match. These benchmarks pin both
// sides of that contract and are CI-runnable via:
//
//	go test ./pkg/logging/ -bench 'BenchmarkProcessLogsAlert' -benchmem -run XXX
//
// A realistic result batch (10 entries × 8 columns) is the common shape
// of an osquery scheduled-query batch, so per-batch costs read directly
// as per-request costs at the /log endpoint.

// benchResultBatch builds a realistic 10-entry result-log batch.
func benchResultBatch(n int) []byte {
	entries := make([]map[string]any, 0, n)
	for i := 0; i < n; i++ {
		entries = append(entries, map[string]any{
			"name":           "file_events",
			"hostIdentifier": "UUID-BENCH-0001",
			"columns": map[string]string{
				"path":     "/usr/local/bin/somebinary",
				"action":   "modified",
				"md5":      "d41d8cd98f00b204e9800998ecf8427e",
				"sha256":   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				"hostname": "node-07.example.com",
				"username": "operator",
				"pid":      "4321",
				"target":   "/usr/local/bin/somebinary",
			},
		})
	}
	raw, err := json.Marshal(entries)
	if err != nil {
		panic(err)
	}
	return raw
}

// benchStatusBatch builds a realistic n-entry status-log batch.
func benchStatusBatch(n int) []byte {
	entries := make([]map[string]any, 0, n)
	for i := 0; i < n; i++ {
		entries = append(entries, map[string]any{
			"line":           "54",
			"message":        "scheduler executing query: file_events",
			"severity":       "0",
			"filename":       "scheduler.cpp",
			"version":        "5.23.1",
			"hostIdentifier": "UUID-BENCH-0001",
		})
	}
	raw, err := json.Marshal(entries)
	if err != nil {
		panic(err)
	}
	return raw
}

// noopMatcher stands in for the real alerts.IngestMatcher at the
// logging layer: the hook shape is what is being measured, the matcher's
// own cost is benchmarked in pkg/alerts.
type noopMatcher struct {
	calls int
}

func (m *noopMatcher) MatchResultLogs(envID uint, environment string, logs []types.LogResultData) {
	m.calls += len(logs)
}

func (m *noopMatcher) MatchStatusLogs(envID uint, environment string, logs []types.LogStatusData) {
	m.calls += len(logs)
}

func (m *noopMatcher) MatchQueryResult(envID uint, environment, queryName string, result json.RawMessage, status int, message string) {
	m.calls++
}

// benchmarkProcessLogs runs one ProcessLogs pass over the batch.
func benchmarkProcessLogs(b *testing.B, matcher AlertMatcher) {
	db, err := openBenchDB(b)
	if err != nil {
		b.Fatalf("open db: %v", err)
	}
	logger := &LoggerTLS{
		Logging: "none",
		Nodes:   benchNodeManager(b, db),
		Queries: benchQueryManager(b, db),
		Alerts:  matcher,
	}
	data := json.RawMessage(benchResultBatch(10))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = logger.ProcessLogs(data, "result", 1, "prod", "10.0.0.1", len(data), false)
	}
}

// BenchmarkProcessLogsBaseline is the feature-off path: no matcher
// attached. This is the regression reference.
func BenchmarkProcessLogsBaseline(b *testing.B) {
	benchmarkProcessLogs(b, nil)
}

// BenchmarkProcessLogsMatcherNoop attaches a matcher that does zero
// work — the upper bound of the pure hook overhead (real IngestMatcher
// returns immediately on an empty snapshot before calling this).
func BenchmarkProcessLogsMatcherNoop(b *testing.B) {
	benchmarkProcessLogs(b, &noopMatcher{})
}

// BenchmarkProcessLogsStatusBaseline covers the status-log path, where
// the hook decodes the full schema before matching.
func BenchmarkProcessLogsStatusBaseline(b *testing.B) {
	db, err := openBenchDB(b)
	if err != nil {
		b.Fatalf("open db: %v", err)
	}
	logger := &LoggerTLS{
		Logging: "none",
		Nodes:   benchNodeManager(b, db),
		Queries: benchQueryManager(b, db),
	}
	data := json.RawMessage(benchStatusBatch(10))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = logger.ProcessLogs(data, "status", 1, "prod", "10.0.0.1", len(data), false)
	}
}

// BenchmarkProcessLogsStatusMatcher attaches the noop matcher to the
// status path — measures the extra full-schema decode the hook adds.
func BenchmarkProcessLogsStatusMatcher(b *testing.B) {
	db, err := openBenchDB(b)
	if err != nil {
		b.Fatalf("open db: %v", err)
	}
	logger := &LoggerTLS{
		Logging: "none",
		Nodes:   benchNodeManager(b, db),
		Queries: benchQueryManager(b, db),
		Alerts:  &noopMatcher{},
	}
	data := json.RawMessage(benchStatusBatch(10))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = logger.ProcessLogs(data, "status", 1, "prod", "10.0.0.1", len(data), false)
	}
}
