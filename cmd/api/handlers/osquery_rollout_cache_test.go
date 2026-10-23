package handlers

import (
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/osqueryversions"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// countNodeScans counts the host scans of Progress (the only query selecting localname).
func countNodeScans(t *testing.T, db *gorm.DB) *atomic.Int32 {
	t.Helper()
	var n atomic.Int32
	count := func(tx *gorm.DB) {
		if strings.Contains(tx.Statement.SQL.String(), "localname") {
			n.Add(1)
		}
	}
	require.NoError(t, db.Callback().Query().After("gorm:query").Register("count_node_scans", count))
	require.NoError(t, db.Callback().Row().After("gorm:row").Register("count_node_scans_row", count))
	return &n
}

// fakeClock makes the cache TTL controllable.
func fakeClock(f oqFixture) *time.Time {
	now := time.Now()
	f.h.rolloutCache.now = func() time.Time { return now }
	return &now
}

func TestRolloutProgressCachedWithinTTL(t *testing.T) {
	f := setupOsqueryHandlers(t)
	clock := fakeClock(f)
	vals := map[string]string{"env": f.envA.Name}
	startRollout(t, f)
	f.h.rolloutCache.invalidate(f.envA.ID) // the Put response cached its own scan
	scans := countNodeScans(t, f.db)
	for i := 0; i < 3; i++ {
		require.Equal(t, http.StatusOK, oqCall(f.h, envGet, http.MethodGet, "alice", vals, "").Code)
	}
	require.EqualValues(t, 1, scans.Load())
	*clock = clock.Add(rolloutProgressTTL + time.Millisecond)
	require.Equal(t, http.StatusOK, oqCall(f.h, envGet, http.MethodGet, "alice", vals, "").Code)
	require.EqualValues(t, 2, scans.Load())
}

func TestRolloutProgressMutationsInvalidate(t *testing.T) {
	f := setupOsqueryHandlers(t)
	fakeClock(f)
	vals := map[string]string{"env": f.envA.Name}
	st := startRollout(t, f)
	f.h.rolloutCache.invalidate(f.envA.ID) // the Put response cached its own scan
	scans := countNodeScans(t, f.db)
	get := func() { require.Equal(t, http.StatusOK, oqCall(f.h, envGet, http.MethodGet, "alice", vals, "").Code) }
	get()
	get()
	require.EqualValues(t, 1, scans.Load())

	// Put: a new rollout row is a new key, and the entry is dropped anyway
	require.Equal(t, http.StatusOK, oqCall(f.h, envPut, http.MethodPut, "alice", vals, `{"version":"5.13.0"}`).Code)
	require.EqualValues(t, 2, scans.Load())
	get()
	require.EqualValues(t, 2, scans.Load())

	// Resume of a paused rollout: same row and stage, so only invalidation refreshes it
	var r osqueryversions.Rollout
	require.NoError(t, f.db.Where("environment_id = ? AND state = ?", f.envA.ID, "running").First(&r).Error)
	ok, err := f.mgr.PauseRollout(f.envA.ID, r.RequestID, "web-1", "x", time.Now(), time.Now())
	require.NoError(t, err)
	require.True(t, ok)
	get() // paused state is a new key
	require.EqualValues(t, 3, scans.Load())
	require.Equal(t, http.StatusOK, oqCall(f.h, rolloutResume, http.MethodPost, "alice", vals, "").Code)
	require.EqualValues(t, 4, scans.Load())
	get()
	require.EqualValues(t, 4, scans.Load())

	// Abort scans nothing (aborted rollouts are not counted) but must drop the entry
	require.Equal(t, http.StatusOK, oqCall(f.h, rolloutAbort, http.MethodPost, "alice", vals, "").Code)
	require.False(t, f.h.rolloutCache.has(f.envA.ID))

	// Delete
	_ = st
	startRollout(t, f)
	get()
	require.True(t, f.h.rolloutCache.has(f.envA.ID))
	require.Equal(t, http.StatusOK, oqCall(f.h, envDel, http.MethodDelete, "alice", vals, "").Code)
	require.False(t, f.h.rolloutCache.has(f.envA.ID))
}

func TestRolloutProgressKeyMisses(t *testing.T) {
	f := setupOsqueryHandlers(t)
	fakeClock(f)
	vals := map[string]string{"env": f.envA.Name}
	startRollout(t, f)
	f.h.rolloutCache.invalidate(f.envA.ID) // the Put response cached its own scan
	scans := countNodeScans(t, f.db)
	get := func() { require.Equal(t, http.StatusOK, oqCall(f.h, envGet, http.MethodGet, "alice", vals, "").Code) }
	get()
	// the stage opens by itself: the effective stage is part of the key
	require.NoError(t, f.db.Model(&osqueryversions.Rollout{}).Where("environment_id = ?", f.envA.ID).
		Update("stage_opened_at", time.Now().Add(-3*time.Hour)).Error)
	get()
	require.EqualValues(t, 2, scans.Load())
	get()
	require.EqualValues(t, 2, scans.Load())
}

func TestRolloutProgressCacheBounded(t *testing.T) {
	now := time.Now()
	c := &rolloutProgressCache{now: func() time.Time { return now }}
	k := rolloutProgressKey{rolloutID: 1, state: "running"}
	for env := uint(1); env <= rolloutProgressMaxEnvs+50; env++ {
		c.put(env, k, osqueryversions.RolloutProgress{})
		now = now.Add(time.Millisecond)
	}
	require.LessOrEqual(t, c.len(), rolloutProgressMaxEnvs)
	require.False(t, c.has(1), "oldest dropped")
	require.True(t, c.has(rolloutProgressMaxEnvs+50))
	// expired entries go first
	now = now.Add(rolloutProgressTTL + time.Second)
	c.put(9999, k, osqueryversions.RolloutProgress{})
	require.Equal(t, 1, c.len())
}

func TestRolloutProgressCacheCopiesHosts(t *testing.T) {
	c := &rolloutProgressCache{}
	k := rolloutProgressKey{rolloutID: 1, state: "running"}
	in := osqueryversions.RolloutProgress{RolledBackHosts: []osqueryversions.RolledBackHost{{Host: "a"}}}
	c.put(1, k, in)
	in.RolledBackHosts[0].Host = "changed after put"
	got, ok := c.get(1, k)
	require.True(t, ok)
	require.Equal(t, "a", got.RolledBackHosts[0].Host)
	got.RolledBackHosts[0].Host = "changed after get"
	again, _ := c.get(1, k)
	require.Equal(t, "a", again.RolledBackHosts[0].Host)
}
