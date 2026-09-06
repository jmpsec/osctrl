package health

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ErrNotReporting is returned when a service has no heartbeat row: it never
// ran with --health-enabled, or never started. It is deliberately distinct
// from "unhealthy" — the API renders it as unknown, not down.
var ErrNotReporting = errors.New("service has never reported health")

// Manager owns the service_status table.
type Manager struct {
	DB *gorm.DB
}

// NewManager initializes the manager and auto-migrates its table. It is
// only called when --health-enabled is set, so a deployment with the
// feature off never creates the table.
func NewManager(db *gorm.DB) *Manager {
	m := &Manager{DB: db}
	if err := db.AutoMigrate(&ServiceStatus{}); err != nil {
		panic(fmt.Sprintf("Failed to AutoMigrate health tables: %v", err))
	}
	return m
}

// Report upserts one service's heartbeat.
func (m *Manager) Report(s ServiceStatus) error {
	if m == nil {
		return nil
	}
	return m.DB.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "service"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"version", "started_at", "reported_at", "goroutines", "payload", "updated_at",
		}),
	}).Create(&s).Error
}

// Get returns one service's heartbeat, or ErrNotReporting.
func (m *Manager) Get(service string) (ServiceStatus, error) {
	return m.GetContext(context.Background(), service)
}

// GetContext is Get with a caller-supplied context, so callers that need a
// bounded deadline (e.g. the health endpoint) are not left waiting forever
// on a saturated connection pool.
func (m *Manager) GetContext(ctx context.Context, service string) (ServiceStatus, error) {
	if m == nil {
		return ServiceStatus{}, ErrNotReporting
	}
	var row ServiceStatus
	if err := m.DB.WithContext(ctx).Where("service = ?", service).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ServiceStatus{}, ErrNotReporting
		}
		return ServiceStatus{}, err
	}
	return row, nil
}
