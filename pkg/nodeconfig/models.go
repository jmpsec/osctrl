package nodeconfig

import (
	"time"

	"gorm.io/gorm"
)

// Override is a per-node osquery configuration override.
type Override struct {
	gorm.Model
	NodeUUID      string `gorm:"uniqueIndex;size:255"`
	EnvironmentID uint   `gorm:"index"`
	Config        string
	ExpiresAt     *time.Time
	UpdatedBy     string
}

// TableName keeps the table name stable.
func (Override) TableName() string { return "node_config_overrides" }

// Expired reports whether the override has an expiry that is not after now.
func (o *Override) Expired(now time.Time) bool {
	return o.ExpiresAt != nil && !now.Before(*o.ExpiresAt)
}
