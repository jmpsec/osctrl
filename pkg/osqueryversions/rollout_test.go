package osqueryversions

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func uuids(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("UUID-%05d", i)
	}
	return out
}

func rolloutManager(t *testing.T) *Manager {
	t.Helper()
	m := newTestManager(t)
	seed(t, m, "5.13.0", deb(digestA))
	seed(t, m, "5.14.0", deb(digestB))
	return m
}

func startRollout(t *testing.T, m *Manager, version string, at time.Time) *Rollout {
	t.Helper()
	_, r, err := m.SetEnvTargetRollout(1, version, "admin", uuids(10), at)
	require.NoError(t, err)
	require.NotNil(t, r)
	return r
}

func TestBucketStable(t *testing.T) {
	b := Bucket(1, "5.13.0", "ABC-123")
	assert.Equal(t, b, Bucket(1, "5.13.0", "ABC-123"))
	assert.Equal(t, b, Bucket(1, "5.13.0", "abc-123"))
	differs := false
	for _, u := range uuids(50) {
		assert.Less(t, Bucket(1, "5.13.0", u), uint32(10000))
		if Bucket(1, "5.13.0", u) != Bucket(1, "5.14.0", u) {
			differs = true
		}
	}
	assert.True(t, differs, "version must change the bucket for some uuid")
}

func countBelow(us []string, thr uint32) int {
	n := 0
	for _, u := range us {
		if Bucket(1, "5.13.0", u) < thr {
			n++
		}
	}
	return n
}

func TestComputeThresholds(t *testing.T) {
	assert.Equal(t, [4]uint32{100, 1000, 5000, 10001}, ComputeThresholds(1, "5.13.0", nil))
	for _, n := range []int{1, 3} {
		us := uuids(n)
		th := ComputeThresholds(1, "5.13.0", us)
		assert.GreaterOrEqual(t, countBelow(us, th[0]), 1, "n=%d", n)
		for i := 1; i < 4; i++ {
			assert.GreaterOrEqual(t, th[i], th[i-1])
		}
		assert.Equal(t, uint32(10001), th[3])
		for _, v := range th {
			assert.LessOrEqual(t, v, uint32(10001))
		}
	}
	us := uuids(1000)
	th := ComputeThresholds(1, "5.13.0", us)
	for i, want := range []int{10, 100, 500, 1000} {
		got := countBelow(us, th[i])
		assert.InDelta(t, want, got, 1, "stage %d", i)
	}
	assert.Equal(t, uint32(10001), th[3])
}

func TestEffectiveStageRunning(t *testing.T) {
	r := Rollout{State: RolloutRunning, Stage: 0, StageOpenedAt: t0}
	assert.Equal(t, 0, r.EffectiveStage(t0))
	assert.Equal(t, 0, r.EffectiveStage(t0.Add(RolloutStageWait-time.Second)))
	assert.Equal(t, 1, r.EffectiveStage(t0.Add(RolloutStageWait)))
	assert.Equal(t, 2, r.EffectiveStage(t0.Add(2*RolloutStageWait)))
	assert.Equal(t, 3, r.EffectiveStage(t0.Add(3*RolloutStageWait)))
	assert.Equal(t, 3, r.EffectiveStage(t0.Add(100*RolloutStageWait)))
	r.Stage = 2
	assert.Equal(t, 3, r.EffectiveStage(t0.Add(RolloutStageWait)))
	assert.Equal(t, 0, Rollout{State: RolloutRunning, StageOpenedAt: t0}.EffectiveStage(t0.Add(-time.Hour)))
}

func TestEffectiveStatePausedFreezes(t *testing.T) {
	r := Rollout{State: RolloutPaused, Stage: 1, StageOpenedAt: t0}
	later := t0.Add(50 * RolloutStageWait)
	assert.Equal(t, 1, r.EffectiveStage(later))
	assert.Equal(t, RolloutPaused, r.EffectiveState(later))
	assert.Nil(t, r.NextStageAt(later))
}

func TestEffectiveStateCompleted(t *testing.T) {
	r := Rollout{State: RolloutRunning, StageOpenedAt: t0}
	assert.Equal(t, RolloutRunning, r.EffectiveState(t0.Add(2*RolloutStageWait)))
	assert.Equal(t, RolloutCompleted, r.EffectiveState(t0.Add(3*RolloutStageWait)))
	assert.Nil(t, r.NextStageAt(t0.Add(3*RolloutStageWait)))
	next := r.NextStageAt(t0.Add(RolloutStageWait + time.Minute))
	require.NotNil(t, next)
	assert.True(t, next.Equal(t0.Add(2*RolloutStageWait)))
	assert.Equal(t, RolloutAborted, Rollout{State: RolloutAborted}.EffectiveState(t0))
}

func TestEligibleUsesEffectiveStage(t *testing.T) {
	r := Rollout{State: RolloutRunning, StageOpenedAt: t0, Thresholds: "[100,1000,5000,10001]"}
	assert.True(t, r.Eligible(99, t0))
	assert.False(t, r.Eligible(100, t0))
	assert.True(t, r.Eligible(100, t0.Add(RolloutStageWait)))
	assert.False(t, r.Eligible(1000, t0.Add(RolloutStageWait)))
	assert.True(t, r.Eligible(9999, t0.Add(3*RolloutStageWait)))
	assert.False(t, Rollout{State: RolloutRunning, Thresholds: "bad"}.Eligible(0, t0))
	assert.False(t, Rollout{State: RolloutRunning, Thresholds: "[]"}.Eligible(0, t0))
	assert.False(t, Rollout{State: RolloutPaused, Stage: 9, Thresholds: "[1,2,3,4]"}.Eligible(0, t0))
}

func TestSetEnvTargetRolloutCreatesRunning(t *testing.T) {
	m := rolloutManager(t)
	tg, r, err := m.SetEnvTargetRollout(1, "5.13.0", "admin", uuids(10), t0)
	require.NoError(t, err)
	assert.Equal(t, tg.RequestID, r.RequestID)
	assert.Equal(t, RolloutRunning, r.State)
	assert.Equal(t, 0, r.Stage)
	assert.True(t, r.StageOpenedAt.Equal(t0))
	assert.Equal(t, "admin", r.CreatedBy)
	got, err := m.GetRollout(1)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, r.ID, got.ID)
	assert.Equal(t, "5.13.0", got.Version)
	none, err := m.GetRollout(2)
	require.NoError(t, err)
	assert.Nil(t, none)
	_, _, err = m.SetEnvTargetRollout(1, "9.9.9", "admin", nil, t0)
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestSetEnvTargetRolloutReplacesActiveRollout(t *testing.T) {
	m := rolloutManager(t)
	first := startRollout(t, m, "5.13.0", t0)
	second := startRollout(t, m, "5.14.0", t0.Add(time.Hour))
	var rows []Rollout
	require.NoError(t, m.db.Order("id").Find(&rows).Error)
	require.Len(t, rows, 2)
	assert.Equal(t, first.ID, rows[0].ID)
	assert.Equal(t, RolloutAborted, rows[0].State)
	assert.Equal(t, "replaced", rows[0].AbortedBy)
	assert.NotNil(t, rows[0].AbortedAt)
	assert.Equal(t, second.ID, rows[1].ID)
	assert.Equal(t, RolloutRunning, rows[1].State)
}

func TestSetEnvTargetRolloutSameVersionNewRequestIDNewRollout(t *testing.T) {
	m := rolloutManager(t)
	a := startRollout(t, m, "5.13.0", t0)
	b := startRollout(t, m, "5.13.0", t0)
	assert.NotEqual(t, a.RequestID, b.RequestID)
	assert.NotEqual(t, a.ID, b.ID)
	tg, err := m.GetEnvTarget(1)
	require.NoError(t, err)
	assert.Equal(t, b.RequestID, tg.RequestID)
}

func TestSetEnvTargetRolloutPrunesHistory(t *testing.T) {
	m := rolloutManager(t)
	for i := 0; i < 15; i++ {
		startRollout(t, m, "5.13.0", t0)
	}
	env2Target, _, err := m.SetEnvTargetRollout(2, "5.13.0", "admin", nil, t0)
	require.NoError(t, err)
	require.NotNil(t, env2Target)
	var n int64
	require.NoError(t, m.db.Unscoped().Model(&Rollout{}).Where("environment_id = ?", 1).Count(&n).Error)
	assert.EqualValues(t, 10, n)
	require.NoError(t, m.db.Unscoped().Model(&Rollout{}).Where("environment_id = ?", 2).Count(&n).Error)
	assert.EqualValues(t, 1, n)
	got, err := m.GetRollout(1)
	require.NoError(t, err)
	assert.Equal(t, RolloutRunning, got.State)
}

func TestPauseRolloutOnlyForMatchingRequestAndRunning(t *testing.T) {
	m := rolloutManager(t)
	r := startRollout(t, m, "5.13.0", t0)
	paused, err := m.PauseRollout(1, "other", "h", "why", t0, t0)
	require.NoError(t, err)
	assert.False(t, paused)
	paused, err = m.PauseRollout(1, r.RequestID, "web-1", "version_not_reported", t0.Add(time.Minute), t0.Add(time.Minute))
	require.NoError(t, err)
	assert.True(t, paused)
	got, _ := m.GetRollout(1)
	assert.Equal(t, RolloutPaused, got.State)
	assert.Equal(t, "web-1", got.PausedHost)
	assert.Equal(t, "version_not_reported", got.PausedReason)
	require.NotNil(t, got.PausedAt)
	assert.True(t, got.PausedAt.Equal(t0.Add(time.Minute)))
	paused, err = m.PauseRollout(1, r.RequestID, "web-2", "other", t0.Add(time.Hour), t0.Add(time.Hour))
	require.NoError(t, err)
	assert.False(t, paused)
	got, _ = m.GetRollout(1)
	assert.Equal(t, "web-1", got.PausedHost)
	assert.Equal(t, "version_not_reported", got.PausedReason)
}

func TestPauseRolloutWritesEffectiveStageBack(t *testing.T) {
	m := rolloutManager(t)
	r := startRollout(t, m, "5.13.0", t0)
	paused, err := m.PauseRollout(1, r.RequestID, "h", "r", t0.Add(2*RolloutStageWait+time.Minute), t0.Add(2*RolloutStageWait+time.Minute))
	require.NoError(t, err)
	require.True(t, paused)
	got, _ := m.GetRollout(1)
	assert.Equal(t, 2, got.Stage)
}

func TestPauseRolloutConcurrent(t *testing.T) {
	m := rolloutManager(t)
	// One connection avoids SQLite shared-cache table locks; both goroutines
	// still read "running" before either writes, so the CAS decides the winner.
	sqlDB, err := m.db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	r := startRollout(t, m, "5.13.0", t0)
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins, errs := 0, 0
	start := make(chan struct{})
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			ok, err := m.PauseRollout(1, r.RequestID, fmt.Sprintf("h%d", i), "r", t0, t0)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs++
			}
			if ok {
				wins++
			}
		}(i)
	}
	close(start)
	wg.Wait()
	assert.Equal(t, 0, errs)
	assert.Equal(t, 1, wins)
}

func TestResumeRollout(t *testing.T) {
	m := rolloutManager(t)
	_, err := m.ResumeRollout(1, "op", t0)
	assert.ErrorIs(t, err, ErrNotFound)
	r := startRollout(t, m, "5.13.0", t0)
	_, err = m.ResumeRollout(1, "op", t0)
	assert.ErrorIs(t, err, ErrRolloutState)
	_, err = m.PauseRollout(1, r.RequestID, "h", "r", t0.Add(RolloutStageWait+time.Minute), t0.Add(RolloutStageWait+time.Minute))
	require.NoError(t, err)
	later := t0.Add(10 * time.Hour)
	got, err := m.ResumeRollout(1, "op", later)
	require.NoError(t, err)
	assert.Equal(t, RolloutRunning, got.State)
	assert.Equal(t, 1, got.Stage)
	assert.True(t, got.StageOpenedAt.Equal(later))
	assert.Equal(t, "op", got.ResumedBy)
	assert.Equal(t, 1, got.EffectiveStage(later))
	_, err = m.ResumeRollout(1, "op", later)
	assert.ErrorIs(t, err, ErrRolloutState)
	assert.Empty(t, got.PausedHost)
	assert.Nil(t, got.PausedAt)
	again := later.Add(time.Minute)
	paused, err := m.PauseRollout(1, r.RequestID, "web-2", "rollback", again, again)
	require.NoError(t, err)
	require.True(t, paused)
	got, _ = m.GetRollout(1)
	assert.Equal(t, "web-2", got.PausedHost)
	assert.Equal(t, "rollback", got.PausedReason)
	require.NotNil(t, got.PausedAt)
	assert.True(t, got.PausedAt.Equal(again))
	_, err = m.AbortRollout(1, "op", later)
	require.NoError(t, err)
	_, err = m.ResumeRollout(1, "op", later)
	assert.ErrorIs(t, err, ErrRolloutState)
}

func TestAbortRolloutClearsTargetKeepsPins(t *testing.T) {
	m := rolloutManager(t)
	_, err := m.AbortRollout(1, "op", t0)
	assert.ErrorIs(t, err, ErrNotFound)
	startRollout(t, m, "5.13.0", t0)
	_, err = m.SetPin("U1", 1, "5.14.0", nil, "admin")
	require.NoError(t, err)
	got, err := m.AbortRollout(1, "op", t0.Add(time.Minute))
	require.NoError(t, err)
	assert.Equal(t, RolloutAborted, got.State)
	assert.Equal(t, "op", got.AbortedBy)
	require.NotNil(t, got.AbortedAt)
	tg, err := m.GetEnvTarget(1)
	require.NoError(t, err)
	assert.Nil(t, tg)
	p, err := m.GetPin("U1")
	require.NoError(t, err)
	assert.NotNil(t, p)
	_, err = m.AbortRollout(1, "op", t0)
	assert.ErrorIs(t, err, ErrRolloutState)
}

func TestClearEnvTargetAbortsActiveRollout(t *testing.T) {
	m := rolloutManager(t)
	startRollout(t, m, "5.13.0", t0)
	cleared, err := m.ClearEnvTarget(1)
	require.NoError(t, err)
	assert.True(t, cleared)
	got, err := m.GetRollout(1)
	require.NoError(t, err)
	assert.Equal(t, RolloutAborted, got.State)
	assert.Equal(t, "target cleared", got.AbortedBy)
}

func TestAbortAndResumeUseEffectiveState(t *testing.T) {
	m := rolloutManager(t)
	startRollout(t, m, "5.13.0", t0)
	done := t0.Add(7 * time.Hour) // stored running, effective completed
	_, err := m.AbortRollout(1, "op", done)
	assert.ErrorIs(t, err, ErrRolloutState)
	_, err = m.ResumeRollout(1, "op", done)
	assert.ErrorIs(t, err, ErrRolloutState)
	tgt, err := m.GetEnvTarget(1)
	require.NoError(t, err)
	assert.NotNil(t, tgt, "target kept")
	r, err := m.GetRollout(1)
	require.NoError(t, err)
	assert.Equal(t, RolloutRunning, r.State)
}

func TestCountPaused(t *testing.T) {
	m := rolloutManager(t)
	add := func(env uint, req, state string) {
		require.NoError(t, m.db.Create(&Rollout{EnvironmentID: env, RequestID: req, Version: "5.13.0", State: state, Thresholds: "[]"}).Error)
	}
	add(1, "a", RolloutPaused) // replaced by a newer running row
	add(1, "b", RolloutRunning)
	add(2, "c", RolloutRunning) // replaced by a newer paused row
	add(2, "d", RolloutPaused)
	add(3, "e", RolloutPaused) // replaced by aborted
	add(3, "f", RolloutAborted)
	add(4, "g", RolloutPaused) // replaced by running (completed is effective only)
	add(4, "h", RolloutRunning)
	add(5, "i", RolloutPaused)
	got, err := m.CountPaused()
	require.NoError(t, err)
	require.Equal(t, map[uint]int{2: 1, 5: 1}, got)
}

func TestPauseRolloutIgnoresRollbackOlderThanLastResume(t *testing.T) {
	m := rolloutManager(t)
	r := startRollout(t, m, "5.13.0", t0)
	// Never resumed: any event time pauses.
	paused, err := m.PauseRollout(1, r.RequestID, "h", "r", t0.Add(-time.Hour), t0)
	require.NoError(t, err)
	require.True(t, paused)
	resumed := t0.Add(time.Hour)
	_, err = m.ResumeRollout(1, "op", resumed)
	require.NoError(t, err)
	// The same rollback re-reported after the resume, and one at the same instant.
	for _, at := range []time.Time{t0, resumed} {
		paused, err = m.PauseRollout(1, r.RequestID, "h", "r", at, resumed.Add(time.Minute))
		require.NoError(t, err)
		require.False(t, paused)
	}
	got, _ := m.GetRollout(1)
	require.Equal(t, RolloutRunning, got.State)
	// A rollback first seen after the resume pauses again.
	paused, err = m.PauseRollout(1, r.RequestID, "h2", "r2", resumed.Add(time.Second), resumed.Add(time.Minute))
	require.NoError(t, err)
	require.True(t, paused)
}
