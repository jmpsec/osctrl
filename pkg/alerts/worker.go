package alerts

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/rs/zerolog/log"
)

// worker.go — async dispatch of matched hits.
//
// The ingest path enqueues hits on a buffered channel and returns; it
// never blocks on dispatch (activityWriter pattern: select-default drop
// with a counter when the buffer is full). Worker goroutines drain the
// channel and run the full fan-out: cooldown claim (Redis) → render →
// channels (Stage 3) → history write. Until Stage 3 lands, the worker
// performs the claim + history write so the pipeline is observable
// end-to-end through alert_history rows.

// DispatchSink processes one claimed hit. Implemented by the channel
// fan-out in Stage 3; tests substitute their own.
type DispatchSink interface {
	Dispatch(ctx context.Context, h Hit) error
}

// WorkerMetrics collects the counters exposed to Prometheus. Kept as
// plain atomics so the hot path never touches the registry; cmd/tls
// polls them from its metrics endpoint.
type WorkerMetrics struct {
	// Matched counts hits accepted into the queue.
	Matched atomic.Uint64
	// Dropped counts hits rejected because the queue was full.
	Dropped atomic.Uint64
	// Dispatched counts hits processed by the sink.
	Dispatched atomic.Uint64
	// Collapsed counts hits suppressed by the cooldown gate.
	Collapsed atomic.Uint64
	// Failed counts sink errors.
	Failed atomic.Uint64
}

// QueueDepth returns the current queue length.
func (w *Worker) QueueDepth() int {
	if w == nil {
		return 0
	}
	return len(w.queue)
}

// claimGate is the cooldown surface the worker needs. *State
// implements it; tests substitute their own.
type claimGate interface {
	Claim(ctx context.Context, h Hit) (bool, error)
	Release(ctx context.Context, h Hit)
}

// Worker is the dispatch pipeline behind the matcher.
type Worker struct {
	store   *Store
	state   claimGate
	manager *Manager
	sink    DispatchSink
	queue   chan Hit
	metrics WorkerMetrics
	workers int
	wg      sync.WaitGroup
	stop    chan struct{}
	// syncFlush, when true, dispatches synchronously in Enqueue (test
	// mode) so integration tests can assert outcomes without sleeps.
	syncFlush bool
}

// Worker defaults tuned for the ingest goroutine's non-blocking
// contract: queue holds a burst of large batches; workers are few
// because dispatch is I/O-bound but low-rate (post-cooldown).
const (
	defaultQueueSize = 8192
	defaultWorkers   = 2
)

// NewWorker builds and starts the dispatch worker pool. store is the
// rule snapshot (for future per-rule lookups); state may be nil (claims
// pass through); sink may be nil (hits are only claimed + recorded).
func NewWorker(store *Store, state claimGate, manager *Manager, sink DispatchSink, queueSize, workers int) *Worker {
	if queueSize <= 0 {
		queueSize = defaultQueueSize
	}
	if workers <= 0 {
		workers = defaultWorkers
	}
	w := &Worker{
		store:   store,
		state:   state,
		manager: manager,
		sink:    sink,
		queue:   make(chan Hit, queueSize),
		workers: workers,
		stop:    make(chan struct{}),
	}
	for i := 0; i < workers; i++ {
		w.wg.Add(1)
		go w.run()
	}
	return w
}

// NewSyncWorker builds a worker that dispatches inline (tests only).
func NewSyncWorker(store *Store, state claimGate, manager *Manager, sink DispatchSink) *Worker {
	w := &Worker{
		store:     store,
		state:     state,
		manager:   manager,
		sink:      sink,
		queue:     make(chan Hit, 16),
		workers:   0,
		syncFlush: true,
	}
	return w
}

// Enqueue offers hits to the dispatch pipeline. Never blocks: a full
// queue drops the hit and bumps the counter. Nil worker is a no-op
// (alerts disabled), which keeps the ingest hook allocation-free when
// the feature is off.
func (w *Worker) Enqueue(hits []Hit) {
	if w == nil || len(hits) == 0 {
		return
	}
	for _, h := range hits {
		w.metrics.Matched.Add(1)
		if w.syncFlush {
			w.dispatch(context.Background(), h)
			continue
		}
		select {
		case w.queue <- h:
		default:
			w.metrics.Dropped.Add(1)
			log.Warn().
				Uint("rule_id", h.RuleID).
				Str("entity", h.Entity).
				Msg("dropping alert hit because dispatch queue is full")
		}
	}
}

// Close drains the queue and stops the workers.
func (w *Worker) Close() {
	if w == nil || w.syncFlush {
		return
	}
	close(w.stop)
	w.wg.Wait()
}

func (w *Worker) run() {
	defer w.wg.Done()
	for {
		select {
		case <-w.stop:
			w.drain()
			return
		case h := <-w.queue:
			w.dispatch(context.Background(), h)
		}
	}
}

// drain flushes anything still queued after stop was signaled.
func (w *Worker) drain() {
	for {
		select {
		case h := <-w.queue:
			w.dispatch(context.Background(), h)
		default:
			return
		}
	}
}

// dispatch runs the claim → sink → history pipeline for one hit.
func (w *Worker) dispatch(ctx context.Context, h Hit) {
	// Cooldown gate. A nil state (no Redis configured) fails open.
	if w.state != nil {
		ok, err := w.state.Claim(ctx, h)
		if err != nil {
			log.Warn().Err(err).Msg("alert cooldown claim failed — dispatching anyway")
		}
		if !ok {
			w.metrics.Collapsed.Add(1)
			return
		}
	}
	if w.sink != nil {
		if err := w.sink.Dispatch(ctx, h); err != nil {
			w.metrics.Failed.Add(1)
			log.Err(err).
				Uint("rule_id", h.RuleID).
				Str("entity", h.Entity).
				Msg("alert dispatch failed")
			// Release the claim so the next hit retries within the
			// window instead of being swallowed by the cooldown.
			if w.state != nil {
				w.state.Release(ctx, h)
			}
			return
		}
	}
	w.metrics.Dispatched.Add(1)
	// History is written only for successfully dispatched alerts.
	if w.manager != nil {
		if err := w.manager.RecordHistory(AlertHistory{
			RuleID:      h.RuleID,
			RuleName:    h.RuleName,
			Environment: h.Environment,
			NodeUUID:    h.NodeUUID,
			Entity:      h.Entity,
			Detail:      h.Detail,
		}); err != nil {
			log.Err(err).Msg("recording alert history failed")
		}
	}
}
