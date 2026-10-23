package osqueryversions

import (
	"time"

	"gorm.io/gorm"
)

// DigestEntry is the SHA-256 of one official osquery package (a version, for
// one platform, arch and format). It is the GORM model and the exchange type.
type DigestEntry struct {
	ID        uint      `gorm:"primaryKey" json:"-"`
	Version   string    `gorm:"uniqueIndex:idx_osq_digest;size:32" json:"version"`
	Platform  string    `gorm:"uniqueIndex:idx_osq_digest;size:16" json:"platform"`
	Arch      string    `gorm:"uniqueIndex:idx_osq_digest;size:16" json:"arch"`
	Format    string    `gorm:"uniqueIndex:idx_osq_digest;size:16" json:"format"`
	SHA256    string    `gorm:"size:64" json:"sha256"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

// TableName keeps the table name stable independent of the struct name.
func (DigestEntry) TableName() string { return "osquery_package_digests" }

// VersionView is a library version with its digests.
type VersionView struct {
	Version string        `json:"version"`
	Entries []DigestEntry `json:"entries"`
	// InUse is set when a target or an unexpired pin references the version.
	InUse bool `json:"in_use"`
}

// EnvTarget is the osquery version an environment is rolled out to.
// RequestID changes on every set so osctrld can tell a re-set from a repeat.
type EnvTarget struct {
	gorm.Model
	EnvironmentID uint   `gorm:"uniqueIndex:idx_osq_env_target_env"`
	Version       string `gorm:"size:32"`
	RequestID     string `gorm:"size:32"`
	UpdatedBy     string
}

// TableName keeps the table name stable.
func (EnvTarget) TableName() string { return "osquery_env_targets" }

// NodePin overrides the environment target for one node, optionally until ExpiresAt.
type NodePin struct {
	gorm.Model
	NodeUUID      string `gorm:"uniqueIndex:idx_osq_node_pin_uuid;size:255"`
	EnvironmentID uint   `gorm:"index:idx_osq_node_pin_env"`
	Version       string `gorm:"size:32"`
	RequestID     string `gorm:"size:32"`
	UpdatedBy     string
	ExpiresAt     *time.Time
}

// TableName keeps the table name stable.
func (NodePin) TableName() string { return "osquery_node_pins" }

// Expired reports whether the pin has an expiry that is not after now.
func (p NodePin) Expired(now time.Time) bool {
	return p.ExpiresAt != nil && !now.Before(*p.ExpiresAt)
}
