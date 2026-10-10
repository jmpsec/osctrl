package vulns

import (
	"context"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/health"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHealthComponent(t *testing.T) {
	r := evidenceReader(t)
	now := r.now()

	c := r.HealthComponent(context.Background())
	assert.Equal(t, "vulnerabilities", c.ID)
	assert.Equal(t, health.StatusUnknown, c.Status, "before the first sync")

	require.NoError(t, recordSuccess(r.DB, "osv:Debian", now, SyncResult{}, now))
	require.NoError(t, recordSuccess(r.DB, sourceKEV, now, SyncResult{}, now))
	c = r.HealthComponent(context.Background())
	assert.Equal(t, health.StatusOperational, c.Status)

	later := now.Add(time.Minute)
	recordFailure(r.DB, sourceKEV, assert.AnError, later)
	c = r.HealthComponent(context.Background())
	assert.Equal(t, health.StatusDegraded, c.Status)
	assert.Contains(t, c.Summary, "kev")

	require.NoError(t, recordSuccess(r.DB, sourceKEV, later.Add(time.Minute), SyncResult{}, later.Add(time.Minute)))
	stale := now.Add(19 * time.Hour)
	r.now = func() time.Time { return stale }
	c = r.HealthComponent(context.Background())
	assert.Equal(t, health.StatusStale, c.Status)
}

// The health page must answer while the database stalls: the component
// honors the request's deadline instead of hanging the whole response.
func TestHealthComponentHonorsTheRequestContext(t *testing.T) {
	r := evidenceReader(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := r.HealthComponent(ctx)
	assert.Equal(t, health.StatusUnknown, c.Status)
	assert.Contains(t, c.Summary, "unavailable")
}
