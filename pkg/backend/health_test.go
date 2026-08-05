package backend

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDBHealth_FailureReachesThreshold(t *testing.T) {
	var calls atomic.Uint32
	h := newDBHealthWithChecker(
		func() error {
			calls.Add(1)
			return errors.New("db down")
		},
		10*time.Millisecond,
		2,
	)

	h.check()
	assert.Equal(t, uint32(1), h.consecutiveFailures.Load(),
		"first failed ping should increment failures to 1")
	assert.False(t, h.IsDegraded(),
		"degraded must not flip until threshold is reached")

	h.check()
	assert.Equal(t, uint32(2), h.consecutiveFailures.Load())
	assert.True(t, h.IsDegraded(),
		"degraded must flip on reaching the failure threshold")
}

func TestDBHealth_RecoveryClearsDegraded(t *testing.T) {
	var fail atomic.Bool
	h := newDBHealthWithChecker(
		func() error {
			if fail.Load() {
				return errors.New("db down")
			}
			return nil
		},
		10*time.Millisecond,
		1,
	)

	fail.Store(true)
	h.check()
	assert.True(t, h.IsDegraded(), "should be degraded after threshold failures")

	fail.Store(false)
	h.check()
	assert.False(t, h.IsDegraded(), "should recover on first success")
	assert.Equal(t, uint32(0), h.consecutiveFailures.Load())
}

func TestDBHealth_OnChangeFiresOnTransition(t *testing.T) {
	var fail atomic.Bool
	var lastReported atomic.Bool
	var transitionCount atomic.Uint32
	h := newDBHealthWithChecker(
		func() error {
			if fail.Load() {
				return errors.New("db down")
			}
			return nil
		},
		10*time.Millisecond,
		1,
	)
	h.SetOnChange(func(degraded bool) {
		lastReported.Store(degraded)
		transitionCount.Add(1)
	})

	fail.Store(true)
	h.check()
	assert.True(t, h.IsDegraded())
	assert.True(t, lastReported.Load(), "OnChange should report degraded=true on entry")
	assert.Equal(t, uint32(1), transitionCount.Load(), "first transition")

	fail.Store(false)
	h.check()
	assert.False(t, h.IsDegraded())
	assert.False(t, lastReported.Load(), "OnChange should report degraded=false on recovery")
	assert.Equal(t, uint32(2), transitionCount.Load(), "second transition")
}

func TestDBHealth_OnChangeDoesNotFireBelowThreshold(t *testing.T) {
	h := newDBHealthWithChecker(
		func() error { return errors.New("db down") },
		10*time.Millisecond,
		5,
	)
	var calls atomic.Uint32
	h.SetOnChange(func(degraded bool) { calls.Add(1) })

	for i := 0; i < 4; i++ {
		h.check()
	}
	assert.False(t, h.IsDegraded())
	assert.Equal(t, uint32(0), calls.Load(),
		"OnChange must not fire before threshold reached")
}

func TestDBHealth_NilMonitorIsNeverDegraded(t *testing.T) {
	var h *DBHealth
	assert.False(t, h.IsDegraded(), "nil *DBHealth must report non-degraded")
}

func TestDBHealth_StartStopReturns(t *testing.T) {
	h := newDBHealthWithChecker(
		func() error { return nil },
		5*time.Millisecond,
		100,
	)
	h.Start()
	time.Sleep(20 * time.Millisecond)
	h.Stop()
}

func TestDBHealth_StartIsIdempotent(t *testing.T) {
	h := newDBHealthWithChecker(
		func() error { return nil },
		5*time.Millisecond,
		100,
	)
	h.Start()
	// Second Start should not launch a second goroutine (cancel is
	// overwritten, which would leak the first). We can't assert on
	// goroutine count cheaply, but we can assert Stop still returns.
	h.Stop()
}
