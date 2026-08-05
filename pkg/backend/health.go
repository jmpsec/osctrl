package backend

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// DegradedReader is the read-only interface for DB health state.
// Caches and handlers use it to decide whether to serve stale data
// or extend TTLs during a DB outage.
type DegradedReader interface {
	// IsDegraded returns true when the DB has been unreachable for
	// at least FailureThreshold consecutive checks. Returns to false
	// on the first successful ping after a degradation window.
	IsDegraded() bool
}

// DBHealth monitors database availability by pinging the DB on a
// fixed interval. It is safe for concurrent use.
//
// A background goroutine calls the check function every Interval. If
// the check fails FailureThreshold times in a row, IsDegraded()
// flips to true. The first success after degradation flips it back
// to false.
//
// The monitor is opt-in: callers must call Start to launch the
// goroutine and Stop to shut it down. A nil *DBHealth is always
// non-degraded — EnvCache treats nil as "no monitoring, behave as
// before" so existing callers that don't wire a monitor are
// unaffected.
type DBHealth struct {
	checkFn             func() error
	interval            time.Duration
	failureThreshold    uint32
	consecutiveFailures atomic.Uint32
	degraded            atomic.Bool
	onChange            func(degraded bool)
	cancel              context.CancelFunc
	wg                  sync.WaitGroup
}

// NewDBHealth creates a DBHealth monitor for the given DBManager.
// Call Start to begin monitoring and Stop to shut down.
func NewDBHealth(db *DBManager, interval time.Duration, failureThreshold uint32) *DBHealth {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if failureThreshold == 0 {
		failureThreshold = 3
	}
	return &DBHealth{
		checkFn:          db.Check,
		interval:         interval,
		failureThreshold: failureThreshold,
	}
}

// newDBHealthWithChecker is a test constructor that injects a
// custom check function instead of relying on a live DBManager.
func newDBHealthWithChecker(checkFn func() error, interval time.Duration, failureThreshold uint32) *DBHealth {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if failureThreshold == 0 {
		failureThreshold = 3
	}
	return &DBHealth{
		checkFn:          checkFn,
		interval:         interval,
		failureThreshold: failureThreshold,
	}
}

// SetOnChange wires a callback invoked whenever the degraded state
// transitions. Receives the new state (true = degraded). Used by
// callers to flip a Prometheus gauge without pkg/backend importing
// prometheus. Called from the monitor goroutine; callers must ensure
// their callback is safe to invoke from that goroutine.
func (h *DBHealth) SetOnChange(fn func(degraded bool)) {
	h.onChange = fn
}

// Start launches the background ping goroutine. Calling Start twice
// without an intervening Stop is a no-op.
func (h *DBHealth) Start() {
	if h == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	h.wg.Add(1)
	go h.run(ctx)
}

// Stop shuts down the monitor and waits for the goroutine to exit.
func (h *DBHealth) Stop() {
	if h == nil || h.cancel == nil {
		return
	}
	h.cancel()
	h.wg.Wait()
	h.cancel = nil
}

// IsDegraded returns true when the DB has been unreachable for at
// least FailureThreshold consecutive checks.
func (h *DBHealth) IsDegraded() bool {
	if h == nil {
		return false
	}
	return h.degraded.Load()
}

func (h *DBHealth) run(ctx context.Context) {
	defer h.wg.Done()
	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.check()
		}
	}
}

func (h *DBHealth) check() {
	if err := h.checkFn(); err != nil {
		failures := h.consecutiveFailures.Add(1)
		if failures == h.failureThreshold {
			log.Warn().Err(err).Uint32("consecutive_failures", failures).Msg("DB health: entering degraded state")
			h.degraded.Store(true)
			if h.onChange != nil {
				h.onChange(true)
			}
		} else if failures > h.failureThreshold {
			log.Debug().Err(err).Uint32("consecutive_failures", failures).Msg("DB health: still degraded")
		}
		return
	}
	if h.degraded.Load() {
		log.Info().Msg("DB health: recovered from degraded state")
		h.degraded.Store(false)
		if h.onChange != nil {
			h.onChange(false)
		}
	}
	h.consecutiveFailures.Store(0)
	h.degraded.Store(false)
}
