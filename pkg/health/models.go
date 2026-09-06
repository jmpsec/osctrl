// Package health reports whether an osctrl deployment is working: the
// database and Redis it depends on, the services that make it up, and the
// background workers inside them.
//
// Two collection strategies, because osctrl-api and osctrl-tls are separate
// processes in separate containers:
//
//   - Anything osctrl-api can reach itself (DB ping, Redis PING, its own Go
//     runtime) is computed when the operator asks for it.
//   - osctrl-tls upserts one heartbeat row that osctrl-api reads. The
//     database is the only channel between the two, the same conclusion
//     pkg/servicecommands reached for restarts.
package health

import (
	"time"

	"gorm.io/gorm"
)

const (
	// HeartbeatInterval is how often a service upserts its row. Fixed, not
	// a setting: the staleness threshold is derived from it and a second
	// knob would only let the two drift apart.
	HeartbeatInterval = 60 * time.Second
	// StaleAfter is when a heartbeat stops counting as live. Three missed
	// writes: one or two are scheduling noise, three mean something broke.
	StaleAfter = 3 * HeartbeatInterval
)

// ServiceStatus is the heartbeat one service writes for the others to read.
// Upserted on Service, so the table holds one row per service forever and
// needs no retention sweep.
type ServiceStatus struct {
	gorm.Model
	// Service is "tls" or "api". v1 only ever writes "tls": osctrl-api
	// reports live because it serves the request. The column accepts both
	// so a future API-side writer needs no migration.
	Service string `gorm:"uniqueIndex;size:16"`
	// Version is the build version of the reporting process, so the API can
	// spot version skew between services.
	Version string `gorm:"size:64"`
	// StartedAt is when the reporting process booted (uptime = now - this).
	StartedAt time.Time
	// ReportedAt is when this row was last written (liveness).
	ReportedAt time.Time
	// Goroutines is runtime.NumGoroutine() at write time — a plain load,
	// free to sample, unlike ReadMemStats which stops the world.
	Goroutines int
	// Payload is the JSON worker snapshot. See WorkerPayload.
	Payload string `gorm:"type:text"`
}

// TableName pins the table so a struct rename cannot silently orphan rows.
func (ServiceStatus) TableName() string { return "service_status" }
