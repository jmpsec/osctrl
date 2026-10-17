package nodeconfig

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const goodFlags = "--verbose=true\n--host_detail_interval=60"

// newTestFlagsManager builds a FlagsManager, with its own fake cache and SQL
// load counter, on the same in-memory DB as a config Manager.
func newTestFlagsManager(t *testing.T) (*FlagsManager, *Manager, *fakeStore, *int) {
	t.Helper()
	cm, _, _ := newTestManager(t)
	fs := newFakeStore()
	m, err := newFlagsManagerWithStore(cm.db, fs)
	require.NoError(t, err)
	loads := 0
	orig := m.load
	m.load = func(uuid string) (*FlagsOverride, error) {
		loads++
		return orig(uuid)
	}
	return m, cm, fs, &loads
}

func countFlagsRows(t *testing.T, m *FlagsManager) int64 {
	t.Helper()
	var n int64
	require.NoError(t, m.db.Unscoped().Model(&FlagsOverride{}).Count(&n).Error)
	return n
}

func TestFlagsSetValidates(t *testing.T) {
	m, _, _, _ := newTestFlagsManager(t)
	for _, bad := range []string{"--tls_hostname=x", "", "not a flag"} {
		_, err := m.Set(context.Background(), FlagsOverride{NodeUUID: "n1", EnvironmentID: 1, Flags: bad})
		require.Error(t, err, bad)
	}
	assert.Zero(t, countFlagsRows(t, m))
}

func TestFlagsSetUpsertsByNode(t *testing.T) {
	m, _, _, _ := newTestFlagsManager(t)
	ctx := context.Background()
	_, err := m.Set(ctx, FlagsOverride{NodeUUID: "n1", EnvironmentID: 1, Flags: goodFlags, UpdatedBy: "alice"})
	require.NoError(t, err)
	second := "--verbose=false"
	stored, err := m.Set(ctx, FlagsOverride{NodeUUID: "n1", EnvironmentID: 1, Flags: second, UpdatedBy: "bob"})
	require.NoError(t, err)
	assert.Equal(t, second, stored.Flags)
	assert.EqualValues(t, 1, countFlagsRows(t, m))
	got, err := m.Get("n1")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, second, got.Flags)
	assert.Equal(t, "bob", got.UpdatedBy)
}

func TestFlagsGetNone(t *testing.T) {
	m, _, _, _ := newTestFlagsManager(t)
	got, err := m.Get("missing")
	assert.NoError(t, err)
	assert.Nil(t, got)
}

func TestFlagsDeleteRemovesRowAndCachesAbsence(t *testing.T) {
	m, _, _, loads := newTestFlagsManager(t)
	ctx := context.Background()
	_, err := m.Set(ctx, FlagsOverride{NodeUUID: "n1", EnvironmentID: 1, Flags: goodFlags})
	require.NoError(t, err)
	require.NoError(t, m.Delete(ctx, "n1"))
	assert.Zero(t, countFlagsRows(t, m))
	got, err := m.Get("n1")
	require.NoError(t, err)
	assert.Nil(t, got)
	active, err := m.Active(ctx, "n1", 1, time.Now())
	require.NoError(t, err)
	assert.Nil(t, active)
	assert.Zero(t, *loads)
	assert.NoError(t, m.Delete(ctx, "n1"))
}

func TestFlagsActiveCachesAbsence(t *testing.T) {
	m, _, fs, loads := newTestFlagsManager(t)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		got, err := m.Active(ctx, "n1", 1, time.Now())
		require.NoError(t, err)
		assert.Nil(t, got)
	}
	assert.Equal(t, 1, *loads)
	_, ok := fs.data["osctrl:nodeflags:n1"]
	assert.True(t, ok)
}

func TestFlagsActiveSeesSetImmediately(t *testing.T) {
	m, _, _, loads := newTestFlagsManager(t)
	ctx := context.Background()
	got, err := m.Active(ctx, "n1", 1, time.Now())
	require.NoError(t, err)
	assert.Nil(t, got)
	_, err = m.Set(ctx, FlagsOverride{NodeUUID: "n1", EnvironmentID: 1, Flags: goodFlags})
	require.NoError(t, err)
	got, err = m.Active(ctx, "n1", 1, time.Now())
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, goodFlags, got.Flags)
	assert.Equal(t, 1, *loads)
}

func TestFlagsActiveRefillDoesNotOverwriteNewerWrite(t *testing.T) {
	m, _, fs, _ := newTestFlagsManager(t)
	ctx := context.Background()
	const apiValue = `{"present":true,"override":{"NodeUUID":"n1"}}`
	orig := m.load
	m.load = func(uuid string) (*FlagsOverride, error) {
		o, err := orig(uuid)
		fs.data[flagsCacheKey(uuid)] = apiValue
		return o, err
	}
	_, err := m.Active(ctx, "n1", 1, time.Now())
	require.NoError(t, err)
	assert.Equal(t, apiValue, fs.data[flagsCacheKey("n1")])
}

func TestFlagsActiveWrongEnvironment(t *testing.T) {
	m, _, _, _ := newTestFlagsManager(t)
	ctx := context.Background()
	_, err := m.Set(ctx, FlagsOverride{NodeUUID: "n1", EnvironmentID: 1, Flags: goodFlags})
	require.NoError(t, err)
	got, err := m.Active(ctx, "n1", 2, time.Now())
	require.NoError(t, err)
	assert.Nil(t, got)
	got, err = m.Active(ctx, "n1", 1, time.Now())
	require.NoError(t, err)
	assert.NotNil(t, got)
}

func TestFlagsActiveExpired(t *testing.T) {
	m, _, _, _ := newTestFlagsManager(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	before, after := now.Add(-time.Minute), now.Add(time.Minute)
	_, err := m.Set(ctx, FlagsOverride{NodeUUID: "old", EnvironmentID: 1, Flags: goodFlags, ExpiresAt: &before})
	require.NoError(t, err)
	_, err = m.Set(ctx, FlagsOverride{NodeUUID: "new", EnvironmentID: 1, Flags: goodFlags, ExpiresAt: &after})
	require.NoError(t, err)
	got, err := m.Active(ctx, "old", 1, now)
	require.NoError(t, err)
	assert.Nil(t, got)
	got, err = m.Active(ctx, "new", 1, now)
	require.NoError(t, err)
	assert.NotNil(t, got)
}

func TestFlagsActiveFallsBackToSQLWhenRedisFails(t *testing.T) {
	m, _, fs, loads := newTestFlagsManager(t)
	ctx := context.Background()
	_, err := m.Set(ctx, FlagsOverride{NodeUUID: "n1", EnvironmentID: 1, Flags: goodFlags})
	require.NoError(t, err)
	delete(fs.data, flagsCacheKey("n1"))
	fs.err = errors.New("redis down")
	got, err := m.Active(ctx, "n1", 1, time.Now())
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, goodFlags, got.Flags)
	assert.Equal(t, 1, *loads)
	// A failed read does not refill the cache.
	assert.Empty(t, fs.data)
}

func TestFlagsAndConfigOverridesIndependent(t *testing.T) {
	fm, cm, _, _ := newTestFlagsManager(t)
	ctx := context.Background()
	for model, idx := range map[any]string{
		&FlagsOverride{}: "idx_node_flags_overrides_node_uuid",
		&OsctrldStatus{}: "idx_osctrld_status_node_uuid",
	} {
		assert.True(t, cm.db.Migrator().HasIndex(model, idx), idx)
	}
	assert.True(t, cm.db.Migrator().HasIndex(&FlagsOverride{}, "idx_node_flags_overrides_env"))
	assert.True(t, cm.db.Migrator().HasTable(&Override{}))

	_, err := cm.Set(ctx, Override{NodeUUID: "n1", EnvironmentID: 1, Config: goodConfig})
	require.NoError(t, err)
	_, err = fm.Set(ctx, FlagsOverride{NodeUUID: "n1", EnvironmentID: 1, Flags: goodFlags})
	require.NoError(t, err)

	require.NoError(t, fm.Delete(ctx, "n1"))
	c, err := cm.Active(ctx, "n1", 1, time.Now())
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.Equal(t, goodConfig, c.Config)

	_, err = fm.Set(ctx, FlagsOverride{NodeUUID: "n1", EnvironmentID: 1, Flags: goodFlags})
	require.NoError(t, err)
	require.NoError(t, cm.Delete(ctx, "n1"))
	f, err := fm.Active(ctx, "n1", 1, time.Now())
	require.NoError(t, err)
	require.NotNil(t, f)
	assert.Equal(t, goodFlags, f.Flags)
	c, err = cm.Get("n1")
	require.NoError(t, err)
	assert.Nil(t, c)
}

func TestRecordFetchUpsertsAndKeepsApply(t *testing.T) {
	m, _, _, _ := newTestFlagsManager(t)
	t1 := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	applyAt := t1.Add(-time.Minute)
	require.NoError(t, m.RecordFetch("n1", 1, t1, &types.OsctrldApplyStatus{Result: "applied", SHA256: "abc", At: applyAt}))
	t2 := t1.Add(time.Hour)
	require.NoError(t, m.RecordFetch("n1", 2, t2, nil))
	require.NoError(t, m.RecordFetch("n1", 2, t2, nil)) // idempotent

	var n int64
	require.NoError(t, m.db.Model(&OsctrldStatus{}).Count(&n).Error)
	assert.EqualValues(t, 1, n)
	st, err := m.Status("n1")
	require.NoError(t, err)
	require.NotNil(t, st)
	assert.True(t, t2.Equal(st.LastFetchedAt))
	assert.EqualValues(t, 2, st.EnvironmentID)
	assert.Equal(t, "applied", st.ApplyResult)
	assert.Equal(t, "abc", st.ApplySHA256)
	require.NotNil(t, st.ApplyAt)
	assert.True(t, applyAt.Equal(*st.ApplyAt))

	require.NoError(t, m.RecordFetch("n1", 2, t2, &types.OsctrldApplyStatus{Result: "failed", Error: "boom", At: t2}))
	st, err = m.Status("n1")
	require.NoError(t, err)
	assert.Equal(t, "failed", st.ApplyResult)
	assert.Empty(t, st.ApplySHA256)
	assert.Equal(t, "boom", st.ApplyError)
}

func TestRecordFetchTruncatesError(t *testing.T) {
	m, _, _, _ := newTestFlagsManager(t)
	// 1023 ASCII bytes then a 3-byte rune: truncation must not split it.
	long := strings.Repeat("x", 1023) + strings.Repeat("€", 10)
	require.NoError(t, m.RecordFetch("n1", 1, time.Now(), &types.OsctrldApplyStatus{Result: "failed", Error: long, At: time.Now()}))
	st, err := m.Status("n1")
	require.NoError(t, err)
	assert.LessOrEqual(t, len(st.ApplyError), 1024)
	assert.Equal(t, strings.Repeat("x", 1023), st.ApplyError)
}

func TestStatusNone(t *testing.T) {
	m, _, _, _ := newTestFlagsManager(t)
	st, err := m.Status("missing")
	assert.NoError(t, err)
	assert.Nil(t, st)
}

func TestDeleteStatusHardDeletes(t *testing.T) {
	m, _, _, _ := newTestFlagsManager(t)
	require.NoError(t, m.RecordFetch("n1", 1, time.Now(), nil))
	require.NoError(t, m.RecordFetch("n2", 1, time.Now(), nil))
	require.NoError(t, m.DeleteStatus("n1"))
	require.NoError(t, m.DeleteStatus("missing"))
	st, err := m.Status("n1")
	require.NoError(t, err)
	assert.Nil(t, st)
	var n int64
	require.NoError(t, m.db.Unscoped().Model(&OsctrldStatus{}).Where("node_uuid = ?", "n1").Count(&n).Error)
	assert.Zero(t, n)
	st, err = m.Status("n2")
	require.NoError(t, err)
	assert.NotNil(t, st)
}
