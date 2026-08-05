package environments

import (
	"context"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/backend"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeDegradedReader is a test-only DegradedReader whose state flips
// via setDegraded.
type fakeDegradedReader struct {
	degraded bool
}

func (f *fakeDegradedReader) IsDegraded() bool   { return f.degraded }
func (f *fakeDegradedReader) setDegraded(b bool) { f.degraded = b }

// TestEnvCache_StaleServeOnDegraded verifies that when the DB health
// monitor reports the database as degraded, GetByUUID serves the
// stale in-memory cached entry instead of returning an error after
// the env is deleted from the DB (simulating a DB outage where the
// row is no longer reachable).
func TestEnvCache_StaleServeOnDegraded(t *testing.T) {
	db := setupTestDB(t)

	env := TLSEnvironment{UUID: "uuid-stale", Name: "stale-env", Hostname: "h.example.com"}
	require.NoError(t, db.Create(&env).Error)

	mgr := CreateEnvironment(db)
	ec := NewEnvCache(*mgr)
	defer ec.Close()

	health := &fakeDegradedReader{}
	ec.SetDBHealth(health)

	ctx := context.Background()

	// Prime the in-memory cache.
	got, err := ec.GetByUUID(ctx, "uuid-stale")
	require.NoError(t, err)
	assert.Equal(t, "stale-env", got.Name)

	// Simulate DB outage: soft-delete the row so GetByUUID's DB
	// query returns "record not found".
	require.NoError(t, db.Where("uuid = ?", "uuid-stale").Delete(&TLSEnvironment{}).Error)

	// With degradation OFF, the expired cache entry should NOT be
	// served — GetByUUID returns the DB error.
	health.setDegraded(false)
	// Mark the cache entry as expired without letting the cleanup
	// goroutine evict it (long cleanup interval in NewEnvCache by
	// default is envCacheTTL = 5m).
	ec.cache.Set(ctx, "uuid-stale", env, 5*time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	_, err = ec.GetByUUID(ctx, "uuid-stale")
	assert.Error(t, err, "without degradation, an expired entry + DB miss should error")

	// Re-prime the cache, then expire it again.
	ec.cache.Set(ctx, "uuid-stale", env, 5*time.Millisecond)
	time.Sleep(20 * time.Millisecond)

	// With degradation ON, the expired-but-present entry should be
	// served as stale instead of erroring.
	health.setDegraded(true)
	got, err = ec.GetByUUID(ctx, "uuid-stale")
	assert.NoError(t, err, "degraded mode should serve stale entry without error")
	assert.Equal(t, "stale-env", got.Name)
}

// TestEnvCache_NoStaleServeWhenNotDegraded verifies the default
// behavior is unchanged when no DB health monitor is wired: a DB
// miss returns an error.
func TestEnvCache_NoStaleServeWhenNotDegraded(t *testing.T) {
	db := setupTestDB(t)
	mgr := CreateEnvironment(db)
	ec := NewEnvCache(*mgr)
	defer ec.Close()

	// No SetDBHealth call — dbHealth is nil.
	_, err := ec.GetByUUID(context.Background(), "never-existed")
	assert.Error(t, err)
}

// TestEnvCache_NilDegradedReaderIsNoOp verifies that a nil
// DegradedReader (the default) keeps GetByUUID on the normal path.
func TestEnvCache_SetDBHealthNilIsNoOp(t *testing.T) {
	db := setupTestDB(t)
	env := TLSEnvironment{UUID: "uuid-nil", Name: "nil-health", Hostname: "h.example.com"}
	require.NoError(t, db.Create(&env).Error)

	mgr := CreateEnvironment(db)
	ec := NewEnvCache(*mgr)
	defer ec.Close()

	ec.SetDBHealth(nil) // no-op
	got, err := ec.GetByUUID(context.Background(), "uuid-nil")
	require.NoError(t, err)
	assert.Equal(t, "nil-health", got.Name)
}

// Compile-time check that *fakeDegradedReader satisfies the interface.
var _ backend.DegradedReader = (*fakeDegradedReader)(nil)
