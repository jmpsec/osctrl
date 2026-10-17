package nodeconfig

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	redis "github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const goodConfig = `{"options":{"verbose":5}}`

// fakeStore is a map-backed store that can be told to fail.
type fakeStore struct {
	mu   sync.Mutex
	data map[string]string
	err  error
}

func newFakeStore() *fakeStore { return &fakeStore{data: map[string]string{}} }

func (f *fakeStore) get(_ context.Context, key string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return "", false, f.err
	}
	v, ok := f.data[key]
	return v, ok, nil
}

func (f *fakeStore) set(_ context.Context, key, value string, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.data[key] = value
	return nil
}

func (f *fakeStore) setNX(_ context.Context, key, value string, _ time.Duration) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return false, f.err
	}
	if _, ok := f.data[key]; ok {
		return false, nil
	}
	f.data[key] = value
	return true, nil
}

func newTestManager(t *testing.T) (*Manager, *fakeStore, *int) {
	t.Helper()
	dsn := "file:" + strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()) + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	fs := newFakeStore()
	m, err := newManagerWithStore(db, fs)
	require.NoError(t, err)
	loads := 0
	orig := m.load
	m.load = func(uuid string) (*Override, error) {
		loads++
		return orig(uuid)
	}
	return m, fs, &loads
}

func countRows(t *testing.T, m *Manager) int64 {
	t.Helper()
	var n int64
	require.NoError(t, m.db.Unscoped().Model(&Override{}).Count(&n).Error)
	return n
}

func TestSetValidates(t *testing.T) {
	m, _, _ := newTestManager(t)
	_, err := m.Set(context.Background(), Override{NodeUUID: "n1", EnvironmentID: 1, Config: `{"options":{"tls_hostname":"x"}}`})
	require.Error(t, err)
	assert.Zero(t, countRows(t, m))
}

func TestSetUpsertsByNode(t *testing.T) {
	m, _, _ := newTestManager(t)
	ctx := context.Background()
	_, err := m.Set(ctx, Override{NodeUUID: "n1", EnvironmentID: 1, Config: goodConfig, UpdatedBy: "alice"})
	require.NoError(t, err)
	second := `{"options":{"verbose":9}}`
	stored, err := m.Set(ctx, Override{NodeUUID: "n1", EnvironmentID: 1, Config: second, UpdatedBy: "bob"})
	require.NoError(t, err)
	assert.Equal(t, second, stored.Config)
	assert.EqualValues(t, 1, countRows(t, m))
	got, err := m.Get("n1")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, second, got.Config)
	assert.Equal(t, "bob", got.UpdatedBy)
}

func TestGetNone(t *testing.T) {
	m, _, _ := newTestManager(t)
	got, err := m.Get("missing")
	assert.NoError(t, err)
	assert.Nil(t, got)
}

func TestDeleteRemovesRowAndCachesAbsence(t *testing.T) {
	m, _, loads := newTestManager(t)
	ctx := context.Background()
	_, err := m.Set(ctx, Override{NodeUUID: "n1", EnvironmentID: 1, Config: goodConfig})
	require.NoError(t, err)
	require.NoError(t, m.Delete(ctx, "n1"))
	assert.Zero(t, countRows(t, m))
	got, err := m.Get("n1")
	require.NoError(t, err)
	assert.Nil(t, got)
	active, err := m.Active(ctx, "n1", 1, time.Now())
	require.NoError(t, err)
	assert.Nil(t, active)
	assert.Zero(t, *loads)
	// Deleting again is not an error.
	assert.NoError(t, m.Delete(ctx, "n1"))
}

func TestActiveCachesAbsence(t *testing.T) {
	m, _, loads := newTestManager(t)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		got, err := m.Active(ctx, "n1", 1, time.Now())
		require.NoError(t, err)
		assert.Nil(t, got)
	}
	assert.Equal(t, 1, *loads)
}

func TestActiveSeesSetImmediately(t *testing.T) {
	m, _, loads := newTestManager(t)
	ctx := context.Background()
	got, err := m.Active(ctx, "n1", 1, time.Now())
	require.NoError(t, err)
	assert.Nil(t, got)
	_, err = m.Set(ctx, Override{NodeUUID: "n1", EnvironmentID: 1, Config: goodConfig})
	require.NoError(t, err)
	got, err = m.Active(ctx, "n1", 1, time.Now())
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, goodConfig, got.Config)
	assert.Equal(t, 1, *loads)
}

func TestActiveRefillDoesNotOverwriteNewerWrite(t *testing.T) {
	m, fs, _ := newTestManager(t)
	ctx := context.Background()
	const apiValue = `{"present":true,"override":{"NodeUUID":"n1"}}`
	orig := m.load
	m.load = func(uuid string) (*Override, error) {
		o, err := orig(uuid)
		// The API commits and writes the cache between our miss and our refill.
		fs.data[cacheKey(uuid)] = apiValue
		return o, err
	}
	_, err := m.Active(ctx, "n1", 1, time.Now())
	require.NoError(t, err)
	assert.Equal(t, apiValue, fs.data[cacheKey("n1")])
}

func TestActiveWrongEnvironment(t *testing.T) {
	m, _, _ := newTestManager(t)
	ctx := context.Background()
	_, err := m.Set(ctx, Override{NodeUUID: "n1", EnvironmentID: 1, Config: goodConfig})
	require.NoError(t, err)
	got, err := m.Active(ctx, "n1", 2, time.Now())
	require.NoError(t, err)
	assert.Nil(t, got)
	got, err = m.Active(ctx, "n1", 1, time.Now())
	require.NoError(t, err)
	assert.NotNil(t, got)
}

func TestActiveExpired(t *testing.T) {
	m, _, _ := newTestManager(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	before, after := now.Add(-time.Minute), now.Add(time.Minute)
	_, err := m.Set(ctx, Override{NodeUUID: "old", EnvironmentID: 1, Config: goodConfig, ExpiresAt: &before})
	require.NoError(t, err)
	_, err = m.Set(ctx, Override{NodeUUID: "new", EnvironmentID: 1, Config: goodConfig, ExpiresAt: &after})
	require.NoError(t, err)
	got, err := m.Active(ctx, "old", 1, now)
	require.NoError(t, err)
	assert.Nil(t, got)
	got, err = m.Active(ctx, "new", 1, now)
	require.NoError(t, err)
	assert.NotNil(t, got)
}

func TestActiveFallsBackToSQLWhenRedisFails(t *testing.T) {
	m, fs, loads := newTestManager(t)
	ctx := context.Background()
	_, err := m.Set(ctx, Override{NodeUUID: "n1", EnvironmentID: 1, Config: goodConfig})
	require.NoError(t, err)
	fs.err = errors.New("redis down")
	got, err := m.Active(ctx, "n1", 1, time.Now())
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, goodConfig, got.Config)
	assert.Equal(t, 1, *loads)
}

func TestRedisStoreLive(t *testing.T) {
	url := os.Getenv("REDIS_URL")
	if url == "" {
		t.Skip("REDIS_URL not set")
	}
	opts, err := redis.ParseURL(url)
	require.NoError(t, err)
	s := redisStore{client: redis.NewClient(opts)}
	ctx := context.Background()
	key := "osctrl:nodeconfig:test-" + t.Name()
	t.Cleanup(func() { s.client.Del(ctx, key) })
	s.client.Del(ctx, key)

	_, ok, err := s.get(ctx, key)
	require.NoError(t, err)
	assert.False(t, ok)
	require.NoError(t, s.set(ctx, key, "a", time.Minute))
	v, ok, err := s.get(ctx, key)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "a", v)
	won, err := s.setNX(ctx, key, "b", time.Minute)
	require.NoError(t, err)
	assert.False(t, won)
	s.client.Del(ctx, key)
	won, err = s.setNX(ctx, key, "c", time.Minute)
	require.NoError(t, err)
	assert.True(t, won)
}
