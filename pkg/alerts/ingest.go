package alerts

import (
	"encoding/json"

	"github.com/jmpsec/osctrl/pkg/types"
)

// ingest.go — the adapter that turns LoggerTLS hook calls into match
// evaluations and queued hits. Implements the logging.AlertMatcher
// interface (defined in pkg/logging to keep the dependency direction
// logging → interface ← alerts).
//
// Hot-path contract: Evaluate* does the snapshot match (pure, lock-free)
// and hands hits to the worker's non-blocking Enqueue. No I/O here.

// IngestMatcher adapts a rule snapshot + worker to the ingest hook.
// A nil *IngestMatcher is a valid disabled matcher (all methods no-op),
// so cmd/tls can store the nil pointer without nil-interface traps.
type IngestMatcher struct {
	store  *Store
	worker *Worker
}

// NewIngestMatcher wires a matcher over the given snapshot store and
// dispatch worker. Both must be non-nil.
func NewIngestMatcher(store *Store, worker *Worker) *IngestMatcher {
	return &IngestMatcher{store: store, worker: worker}
}

// MatchResultLogs implements logging.AlertMatcher.
func (m *IngestMatcher) MatchResultLogs(envID uint, environment string, logs []types.LogResultData) {
	if m == nil {
		return
	}
	m.worker.Enqueue(m.store.Snapshot().MatchResultLogs(envID, environment, logs))
}

// MatchStatusLogs implements logging.AlertMatcher.
func (m *IngestMatcher) MatchStatusLogs(envID uint, environment string, logs []types.LogStatusData) {
	if m == nil {
		return
	}
	m.worker.Enqueue(m.store.Snapshot().MatchStatusLogs(envID, environment, logs))
}

// MatchQueryResult implements logging.AlertMatcher.
func (m *IngestMatcher) MatchQueryResult(envID uint, environment, queryName string, result json.RawMessage, status int, message string) {
	if m == nil {
		return
	}
	m.worker.Enqueue(m.store.Snapshot().MatchQueryResult(envID, environment, queryName, result, status, message))
}
