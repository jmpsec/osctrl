package main

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/alerts"
	"github.com/jmpsec/osctrl/pkg/events"
	"github.com/jmpsec/osctrl/pkg/health"
	"github.com/stretchr/testify/require"
)

type testEventStats struct{ stats events.Stats }

func (t testEventStats) Snapshot() events.Stats { return t.stats }

func TestBuildHealthPayloadWithoutAlerts(t *testing.T) {
	var payload health.WorkerPayload
	require.NoError(t, json.Unmarshal([]byte(buildHealthPayload(nil, nil, time.Now().Add(-time.Hour))), &payload))
	require.Nil(t, payload.Alerts, "a disabled subsystem must be omitted, not reported as zeroes")
	require.Nil(t, payload.Events, "a disabled subsystem must be omitted, not reported as zeroes")
	require.NotNil(t, payload.Runtime, "runtime state rides every heartbeat, alerts or not")
	require.Greater(t, payload.Runtime.HeapAlloc, uint64(0))
	require.InDelta(t, 3600, payload.Runtime.UptimeSeconds, 5)
}

func TestBuildHealthPayloadWithAlerts(t *testing.T) {
	w := alerts.NewWorker(alerts.NewStore(), nil, nil, nil, 32, 1)
	defer w.Close()

	var payload health.WorkerPayload
	require.NoError(t, json.Unmarshal([]byte(buildHealthPayload(w, nil, time.Now().Add(-time.Hour))), &payload))
	require.NotNil(t, payload.Alerts)
	require.True(t, payload.Alerts.Enabled)
	require.Equal(t, 32, payload.Alerts.QueueCapacity)
}

func TestBuildHealthPayloadWithEvents(t *testing.T) {
	var payload health.WorkerPayload
	stats := events.Stats{Enabled: true, Healthy: true, Dropped: 3}
	require.NoError(t, json.Unmarshal([]byte(buildHealthPayload(nil, testEventStats{stats: stats}, time.Now().Add(-time.Hour))), &payload))
	require.NotNil(t, payload.Events)
	require.Equal(t, stats, *payload.Events)
}

func TestHeartbeatTicksEveryTwelfthPoll(t *testing.T) {
	// 5s poll interval × 12 ticks = the 60s heartbeat interval.
	require.Equal(t, int(health.HeartbeatInterval/serviceCommandPollInterval), heartbeatEveryNTicks)
	require.Equal(t, 12, heartbeatEveryNTicks)

	// The loop calls shouldHeartbeat with its tick counter; only every
	// twelfth tick writes, so one minute of polling costs one row.
	var writes int
	for tick := 1; tick <= 24; tick++ {
		if shouldHeartbeat(tick) {
			writes++
		}
	}
	require.Equal(t, 2, writes, "two minutes of polling must produce two heartbeats")
	require.False(t, shouldHeartbeat(1))
	require.True(t, shouldHeartbeat(12))
}
