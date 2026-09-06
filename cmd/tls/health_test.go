package main

import (
	"encoding/json"
	"testing"

	"github.com/jmpsec/osctrl/pkg/alerts"
	"github.com/jmpsec/osctrl/pkg/health"
	"github.com/stretchr/testify/require"
)

func TestBuildHealthPayloadWithoutAlerts(t *testing.T) {
	var payload health.WorkerPayload
	require.NoError(t, json.Unmarshal([]byte(buildHealthPayload(nil)), &payload))
	require.Nil(t, payload.Alerts, "a disabled subsystem must be omitted, not reported as zeroes")
}

func TestBuildHealthPayloadWithAlerts(t *testing.T) {
	w := alerts.NewWorker(alerts.NewStore(), nil, nil, nil, 32, 1)
	defer w.Close()

	var payload health.WorkerPayload
	require.NoError(t, json.Unmarshal([]byte(buildHealthPayload(w)), &payload))
	require.NotNil(t, payload.Alerts)
	require.True(t, payload.Alerts.Enabled)
	require.Equal(t, 32, payload.Alerts.QueueCapacity)
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
