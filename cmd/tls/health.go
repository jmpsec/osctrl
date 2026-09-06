package main

import (
	"encoding/json"
	"runtime"
	"time"

	"github.com/jmpsec/osctrl/pkg/alerts"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/health"
	"github.com/rs/zerolog/log"
)

// heartbeatEveryNTicks is how many service-command polls pass between
// heartbeats. The heartbeat rides that existing loop rather than starting a
// ticker of its own: 5s × 12 = the 60s interval, and no new goroutine.
const heartbeatEveryNTicks = int(health.HeartbeatInterval / serviceCommandPollInterval)

// shouldHeartbeat reports whether this poll tick is a heartbeat tick. Split
// out of the loop so the cadence is testable without waiting a minute.
func shouldHeartbeat(tick int) bool { return tick%heartbeatEveryNTicks == 0 }

// buildHealthPayload renders the worker counters and runtime state carried
// by the heartbeat.
// Every value read here is a plain atomic or a channel length — nothing that
// stops the world.
func buildHealthPayload(w *alerts.Worker, processStartedAt time.Time) string {
	// Sampled through runtime/metrics, never ReadMemStats: this runs on the
	// 60s heartbeat inside the log-ingest service, where a stop-the-world
	// pause is exactly what the design refuses to pay.
	runtimeStats := health.SampleRuntimeMetrics(processStartedAt)
	payload := health.WorkerPayload{Runtime: &runtimeStats}
	if w != nil {
		snap := w.MetricsSnapshot()
		payload.Alerts = &health.AlertsWorkerStats{
			Enabled:       true,
			QueueDepth:    snap.QueueDepth,
			QueueCapacity: snap.QueueCapacity,
			Matched:       snap.Matched,
			Dispatched:    snap.Dispatched,
			Collapsed:     snap.Collapsed,
			Dropped:       snap.Dropped,
			Failed:        snap.Failed,
		}
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "{}"
	}
	return string(raw)
}

// reportHealth writes one heartbeat. A failure is logged and dropped: health
// reporting must never take the service down, and a DB outage is exactly when
// the write fails anyway.
func reportHealth(mgr *health.Manager, w *alerts.Worker, startedAt time.Time, buildVersion string) {
	if mgr == nil {
		return
	}
	if err := mgr.Report(health.ServiceStatus{
		Service:    config.ServiceTLS,
		Version:    buildVersion,
		StartedAt:  startedAt,
		ReportedAt: time.Now(),
		Goroutines: runtimeNumGoroutine(),
		Payload:    buildHealthPayload(w, startedAt),
	}); err != nil {
		log.Err(err).Msg("error writing health heartbeat")
	}
}

// runtimeNumGoroutine is split out so the heartbeat's only runtime call is
// obvious and cheap. NumGoroutine is a plain load; ReadMemStats (which stops
// the world) is deliberately NOT called here.
func runtimeNumGoroutine() int { return runtime.NumGoroutine() }
