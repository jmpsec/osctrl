package alerts

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/types"
)

// recordingSink captures dispatched hits in order.
type recordingSink struct {
	mu   sync.Mutex
	hits []Hit
	err  error
}

func (s *recordingSink) Dispatch(_ context.Context, h Hit) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.hits = append(s.hits, h)
	return nil
}

func (s *recordingSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.hits)
}

// TestWorkerEnqueueDispatch verifies the full pipeline: enqueue → claim
// → sink → history, with the sync worker (no sleeps).
func TestWorkerEnqueueDispatch(t *testing.T) {
	m := newTestManager(t)
	sink := &recordingSink{}
	w := NewSyncWorker(NewStore(), nil, m, sink)

	w.Enqueue([]Hit{{
		RuleID: 1, RuleName: "r", Environment: "dev",
		NodeUUID: "U", Entity: "U:q", Detail: "d", Channels: []uint{1},
	}})

	if sink.count() != 1 {
		t.Fatalf("expected 1 dispatch, got %d", sink.count())
	}
	if got := w.metrics.Dispatched.Load(); got != 1 {
		t.Fatalf("dispatched counter: %d", got)
	}
	rows, err := m.RecentHistory(10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("history not recorded: %v %d", err, len(rows))
	}
	if rows[0].RuleName != "r" || rows[0].Environment != "dev" {
		t.Fatalf("unexpected history row: %+v", rows[0])
	}
}

// TestWorkerCooldownCollapse: identical hits inside the window collapse;
// different details dispatch independently.
func TestWorkerCooldownCollapse(t *testing.T) {
	m := newTestManager(t)
	sink := &recordingSink{}
	// Nil state means claims pass through — use a counting gate instead.
	gate := &countingGate{allowed: map[string]bool{}}
	w := NewSyncWorker(NewStore(), gate, m, sink)

	h := Hit{RuleID: 1, RuleName: "r", Environment: "dev", Entity: "e", Detail: "same"}
	w.Enqueue([]Hit{h})
	w.Enqueue([]Hit{h}) // same claim key → gate denies → collapse
	if sink.count() != 1 {
		t.Fatalf("expected collapse to 1 dispatch, got %d", sink.count())
	}
	if got := w.metrics.Collapsed.Load(); got != 1 {
		t.Fatalf("collapsed counter: %d", got)
	}
	h2 := h
	h2.Detail = "different"
	w.Enqueue([]Hit{h2})
	if sink.count() != 2 {
		t.Fatalf("different detail must dispatch: %d", sink.count())
	}
}

// countingGate is a test State substitute without Redis: it denies a
// claim key after the first grant.
type countingGate struct {
	mu      sync.Mutex
	allowed map[string]bool
}

func (g *countingGate) Claim(_ context.Context, h Hit) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.allowed == nil {
		g.allowed = map[string]bool{}
	}
	key := h.RuleName + h.Entity + h.Detail
	if g.allowed[key] {
		return false, nil
	}
	g.allowed[key] = true
	return true, nil
}

func (g *countingGate) Release(_ context.Context, h Hit) {}

// TestWorkerSinkFailureReleasesClaim: a failing sink must not write
// history and must bump the failed counter.
func TestWorkerSinkFailure(t *testing.T) {
	m := newTestManager(t)
	sink := &recordingSink{err: errors.New("boom")}
	w := NewSyncWorker(NewStore(), nil, m, sink)

	w.Enqueue([]Hit{{RuleID: 1, RuleName: "r", Entity: "e", Detail: "d"}})

	if got := w.metrics.Failed.Load(); got != 1 {
		t.Fatalf("failed counter: %d", got)
	}
	if got := w.metrics.Dispatched.Load(); got != 0 {
		t.Fatalf("failed dispatch must not count as dispatched: %d", got)
	}
	rows, err := m.RecentHistory(10)
	if err != nil || len(rows) != 0 {
		t.Fatalf("failed dispatch must not record history: %v %d", err, len(rows))
	}
}

// TestWorkerDropWhenFull: a full queue drops, never blocks.
func TestWorkerDropWhenFull(t *testing.T) {
	// Async worker with a blocked sink and a 1-slot queue.
	block := make(chan struct{})
	sink := &blockingSink{release: block}
	w := NewWorker(NewStore(), nil, nil, sink, 1, 1)
	defer func() {
		close(block)
		w.Close()
	}()

	// First hit occupies the worker; second fills the queue; third must drop.
	w.Enqueue([]Hit{{RuleID: 1, Entity: "a"}})
	// give the worker time to pick up the first hit
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && w.QueueDepth() != 0 {
		time.Sleep(time.Millisecond)
	}
	w.Enqueue([]Hit{{RuleID: 1, Entity: "b"}})
	w.Enqueue([]Hit{{RuleID: 1, Entity: "c"}}) // dropped
	if got := w.metrics.Dropped.Load(); got != 1 {
		t.Fatalf("drop counter: %d", got)
	}
	if got := w.metrics.Matched.Load(); got != 3 {
		t.Fatalf("matched counter: %d", got)
	}
}

type blockingSink struct {
	release <-chan struct{}
}

func (s *blockingSink) Dispatch(_ context.Context, _ Hit) error {
	<-s.release
	return nil
}

// TestWorkerCloseDrains: Close flushes queued hits before returning.
func TestWorkerCloseDrains(t *testing.T) {
	sink := &recordingSink{}
	// A worker whose queue is full but workers not consuming yet: we
	// stop consumption by using a single worker and closing right after
	// enqueue. The drain path must deliver everything.
	w := NewWorker(NewStore(), nil, nil, sink, 64, 1)
	hits := make([]Hit, 0, 10)
	for i := 0; i < 10; i++ {
		hits = append(hits, Hit{RuleID: uint(i), Entity: "e"})
	}
	w.Enqueue(hits)
	w.Close()
	if sink.count() != 10 {
		t.Fatalf("close must drain all hits, got %d of 10", sink.count())
	}
}

// TestNilWorkerNoOp: enqueue on a nil worker is allocation- and
// error-free — the feature-off contract.
func TestNilWorkerNoOp(t *testing.T) {
	var w *Worker
	w.Enqueue([]Hit{{RuleID: 1}})
	w.Close()
	if w.QueueDepth() != 0 {
		t.Fatalf("nil worker depth must be 0")
	}
}

// TestIngestMatcherAdapts: the ingest adapter evaluates snapshots and
// forwards hits. Also verifies the nil *IngestMatcher safe no-op.
func TestIngestMatcherAdapts(t *testing.T) {
	store := NewStore()
	sink := &recordingSink{}
	worker := NewSyncWorker(store, nil, nil, sink)

	rs := compileForTest(t,
		AlertRule{Model: ruleWithID(1), Name: "result-rule", Source: SourceResultLog, MatchType: MatchTypeSubstring, MatchValue: "needle"},
		AlertRule{Model: ruleWithID(2), Name: "status-rule", Source: SourceStatusLog, MatchType: MatchTypeSubstring, MatchValue: "error"},
	)
	store.Publish(rs)

	matcher := NewIngestMatcher(store, worker)
	matcher.MatchResultLogs(1, "dev", []types.LogResultData{resultEntry("node-1", "file_events", map[string]string{"path": "needle here"})})
	matcher.MatchStatusLogs(1, "dev", []types.LogStatusData{statusEntry("node-1", 2, "an error occurred")})
	if sink.count() != 2 {
		t.Fatalf("expected 2 dispatches through adapter, got %d", sink.count())
	}

	// nil matcher must be safe
	var nilMatcher *IngestMatcher
	nilMatcher.MatchResultLogs(1, "dev", nil)
	nilMatcher.MatchStatusLogs(1, "dev", nil)
	nilMatcher.MatchQueryResult(1, "dev", "q", nil, 0, "")
}
