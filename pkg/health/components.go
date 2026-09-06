package health

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Status values a component can report.
const (
	StatusOperational = "operational"
	StatusDegraded    = "degraded"
	StatusDown        = "down"
	StatusStale       = "stale"
	StatusUnknown     = "unknown"
)

// Component is one row on the health page.
type Component struct {
	ID      string         `json:"id"`
	Name    string         `json:"name"`
	Status  string         `json:"status"`
	Summary string         `json:"summary"`
	Details map[string]any `json:"details,omitempty"`
}

// WorkerPayload is the JSON osctrl-tls writes in ServiceStatus.Payload.
// Everything in it is free to read — atomics, channel lengths, and
// runtime/metrics counters; nothing here stops the world. Subsystems that are
// disabled are omitted, so the page shows what the deployment actually runs.
type WorkerPayload struct {
	Alerts *AlertsWorkerStats `json:"alerts,omitempty"`
	// Runtime is the reporting service's Go runtime state, sampled through
	// runtime/metrics rather than ReadMemStats — see SampleRuntimeMetrics for
	// why, and for the two fields that sampler cannot fill.
	Runtime *RuntimeStats `json:"runtime,omitempty"`
}

// AlertsWorkerStats mirrors alerts.WorkerSnapshot.
type AlertsWorkerStats struct {
	Enabled       bool   `json:"enabled"`
	QueueDepth    int    `json:"queue_depth"`
	QueueCapacity int    `json:"queue_capacity"`
	Matched       uint64 `json:"matched"`
	Dispatched    uint64 `json:"dispatched"`
	Collapsed     uint64 `json:"collapsed"`
	Dropped       uint64 `json:"dropped"`
	Failed        uint64 `json:"failed"`
}

// decodePayload reads the heartbeat's JSON payload. A payload that will not
// decode is reported as such by the caller rather than silently rendering as
// "nothing enabled".
func decodePayload(row ServiceStatus) (WorkerPayload, error) {
	var payload WorkerPayload
	if row.Payload == "" {
		return payload, nil
	}
	err := json.Unmarshal([]byte(row.Payload), &payload)
	return payload, err
}

// DatabaseComponent reports the backend database. degraded comes from the
// existing pkg/backend health monitor; pingErr from a live ping.
func DatabaseComponent(degraded bool, pingErr error, latency time.Duration) Component {
	c := Component{ID: "database", Name: "Database", Details: map[string]any{
		"latency_ms": latency.Milliseconds(),
		"degraded":   degraded,
	}}
	switch {
	case pingErr != nil:
		c.Status = StatusDown
		c.Summary = pingErr.Error()
	case degraded:
		c.Status = StatusDegraded
		c.Summary = "health monitor reports the database as degraded"
	default:
		c.Status = StatusOperational
		c.Summary = fmt.Sprintf("reachable in %dms", latency.Milliseconds())
	}
	return c
}

// RedisComponent reports Redis reachability from a PING.
func RedisComponent(pingErr error, latency time.Duration) Component {
	c := Component{ID: "redis", Name: "Redis", Details: map[string]any{
		"latency_ms": latency.Milliseconds(),
	}}
	if pingErr != nil {
		c.Status = StatusDown
		c.Summary = pingErr.Error()
		return c
	}
	c.Status = StatusOperational
	c.Summary = fmt.Sprintf("PING ok in %dms", latency.Milliseconds())
	return c
}

// ServiceComponent turns a heartbeat row into a component. apiVersion is the
// version of the process serving the request, so skew between services is
// visible rather than silent.
func ServiceComponent(row ServiceStatus, err error, now time.Time, apiVersion string) Component {
	c := Component{ID: "tls", Name: "osctrl-tls"}
	if err != nil {
		c.Status = StatusUnknown
		if errors.Is(err, ErrNotReporting) {
			c.Summary = "not reporting — enable --health-enabled on osctrl-tls"
		} else {
			c.Summary = err.Error()
		}
		return c
	}

	age := now.Sub(row.ReportedAt)
	mismatch := apiVersion != "" && row.Version != "" && row.Version != apiVersion
	c.Details = map[string]any{
		"version":          row.Version,
		"reported_at":      row.ReportedAt,
		"uptime_seconds":   int64(now.Sub(row.StartedAt).Seconds()),
		"goroutines":       row.Goroutines,
		"version_mismatch": mismatch,
	}
	// The SPA renders a runtime card for any component carrying "runtime", so
	// forwarding the sampled block is all it takes for osctrl-tls to appear
	// beside osctrl-api under System status. Unlike the API's, these numbers
	// are up to one heartbeat interval old — "reported_at" above is what says
	// how old.
	if payload, err := decodePayload(row); err == nil && payload.Runtime != nil {
		c.Details["runtime"] = payload.Runtime
	}

	switch {
	case age > StaleAfter:
		c.Status = StatusStale
		c.Summary = fmt.Sprintf("last reported %s ago", age.Round(time.Second))
	case mismatch:
		c.Status = StatusDegraded
		c.Summary = fmt.Sprintf("running %s while osctrl-api runs %s", row.Version, apiVersion)
	default:
		c.Status = StatusOperational
		c.Summary = fmt.Sprintf("up %s, %d goroutines", now.Sub(row.StartedAt).Round(time.Minute), row.Goroutines)
	}
	return c
}

// WorkersComponent reports the background workers inside osctrl-tls, decoded
// from the heartbeat payload. It inherits staleness from the heartbeat:
// counters from a dead process say nothing about now.
func WorkersComponent(row ServiceStatus, err error, now time.Time) Component {
	c := Component{ID: "workers", Name: "Workers"}
	if err != nil {
		c.Status = StatusUnknown
		if errors.Is(err, ErrNotReporting) {
			c.Summary = "no worker data — osctrl-tls is not reporting"
		} else {
			c.Summary = fmt.Sprintf("worker data unavailable: %s", err.Error())
		}
		return c
	}
	if now.Sub(row.ReportedAt) > StaleAfter {
		c.Status = StatusStale
		c.Summary = "worker counters are stale"
		return c
	}

	payload, decodeErr := decodePayload(row)
	if decodeErr != nil {
		c.Status = StatusUnknown
		c.Summary = "worker payload could not be decoded"
		return c
	}
	if payload.Alerts == nil || !payload.Alerts.Enabled {
		c.Status = StatusOperational
		c.Summary = "no workers enabled"
		return c
	}

	a := payload.Alerts
	c.Details = map[string]any{"alerts": a}
	nearlyFull := a.QueueCapacity > 0 && a.QueueDepth*10 >= a.QueueCapacity*9
	switch {
	case a.Dropped > 0:
		c.Status = StatusDegraded
		c.Summary = fmt.Sprintf("alerts worker dropped %d hits", a.Dropped)
	case nearlyFull:
		c.Status = StatusDegraded
		c.Summary = fmt.Sprintf("alerts queue %d/%d", a.QueueDepth, a.QueueCapacity)
	default:
		c.Status = StatusOperational
		c.Summary = fmt.Sprintf("alerts worker: %d dispatched, queue %d/%d", a.Dispatched, a.QueueDepth, a.QueueCapacity)
	}
	return c
}
