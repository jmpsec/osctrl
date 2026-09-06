package health

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDatabaseComponentStatuses(t *testing.T) {
	require.Equal(t, StatusOperational, DatabaseComponent(false, nil, 2*time.Millisecond).Status)
	require.Equal(t, StatusDegraded, DatabaseComponent(true, nil, 2*time.Millisecond).Status)
	require.Equal(t, StatusDown, DatabaseComponent(false, errors.New("boom"), 0).Status)
}

func TestRedisComponentStatuses(t *testing.T) {
	require.Equal(t, StatusOperational, RedisComponent(nil, time.Millisecond).Status)
	down := RedisComponent(errors.New("connection refused"), 0)
	require.Equal(t, StatusDown, down.Status)
	require.Contains(t, down.Summary, "connection refused")
}

func TestServiceComponentHeartbeatAges(t *testing.T) {
	now := time.Now()
	fresh := ServiceStatus{Service: "tls", Version: "0.5.8", ReportedAt: now.Add(-30 * time.Second), StartedAt: now.Add(-time.Hour)}
	require.Equal(t, StatusOperational, ServiceComponent(fresh, nil, now, "0.5.8").Status)

	stale := fresh
	stale.ReportedAt = now.Add(-4 * time.Minute)
	got := ServiceComponent(stale, nil, now, "0.5.8")
	require.Equal(t, StatusStale, got.Status)
	require.Contains(t, got.Summary, "last reported")

	missing := ServiceComponent(ServiceStatus{}, ErrNotReporting, now, "0.5.8")
	require.Equal(t, StatusUnknown, missing.Status)
	require.Contains(t, missing.Summary, "--health-enabled")
}

func TestServiceComponentFlagsVersionSkew(t *testing.T) {
	now := time.Now()
	row := ServiceStatus{Service: "tls", Version: "0.5.7", ReportedAt: now, StartedAt: now.Add(-time.Hour)}
	got := ServiceComponent(row, nil, now, "0.5.8")
	require.Equal(t, StatusDegraded, got.Status)
	require.Contains(t, got.Summary, "0.5.7")
	require.Equal(t, true, got.Details["version_mismatch"])
}

func TestWorkersComponentReportsDrops(t *testing.T) {
	now := time.Now()
	healthy := ServiceStatus{Service: "tls", ReportedAt: now,
		Payload: `{"alerts":{"enabled":true,"queue_depth":3,"queue_capacity":8192,"dropped":0}}`}
	require.Equal(t, StatusOperational, WorkersComponent(healthy, nil, now).Status)

	dropping := healthy
	dropping.Payload = `{"alerts":{"enabled":true,"queue_depth":8100,"queue_capacity":8192,"dropped":12}}`
	got := WorkersComponent(dropping, nil, now)
	require.Equal(t, StatusDegraded, got.Status)
	require.Contains(t, got.Summary, "12")

	require.Equal(t, StatusUnknown, WorkersComponent(ServiceStatus{}, ErrNotReporting, now).Status)
}
