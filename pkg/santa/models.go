package santa

import (
	"time"

	"gorm.io/gorm"
)

// EnvConfig is the per-environment Santa sync configuration.
type EnvConfig struct {
	ID                    uint      `gorm:"primarykey" json:"id"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
	EnvironmentID         uint      `gorm:"uniqueIndex" json:"environment_id"`
	TokenHash             string    `gorm:"type:varchar(64)" json:"-"`
	ClientMode            string    `gorm:"type:varchar(16)" json:"client_mode"` // MONITOR | LOCKDOWN
	BatchSize             uint32    `json:"batch_size"`                          // 0 means the Santa default (50)
	EnableTransitiveRules bool      `json:"enable_transitive_rules"`
	// Deprecated: derived from removable_media, sent only for older Santa clients
	BlockUSBMount bool `json:"block_usb_mount"`
	// ALLOW | BLOCK | REMOUNT
	RemovableMedia string `gorm:"type:varchar(16)" json:"removable_media"`
	// Mount options used with REMOUNT
	RemovableMediaFlags []string `gorm:"serializer:json;type:varchar(255)" json:"removable_media_flags"`
	// Override for encrypted volumes: ALLOW | BLOCK | REMOUNT; empty uses removable_media
	EncryptedRemovableMedia string `gorm:"type:varchar(16)" json:"encrypted_removable_media"`
	// Mount options used with encrypted REMOUNT
	EncryptedRemovableMediaFlags []string `gorm:"serializer:json;type:varchar(255)" json:"encrypted_removable_media_flags"`
}

// TableName for EnvConfig
func (EnvConfig) TableName() string { return "santa_env_configs" }

// Rule is a Santa allow/block rule scoped to an environment, tag or node.
type Rule struct {
	ID            uint      `gorm:"primarykey" json:"id"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	EnvironmentID uint      `gorm:"uniqueIndex:idx_santa_rule_unique" json:"environment_id"`
	Identifier    string    `gorm:"type:varchar(255);uniqueIndex:idx_santa_rule_unique" json:"identifier"`
	RuleType      string    `gorm:"type:varchar(16);uniqueIndex:idx_santa_rule_unique" json:"rule_type"` // BINARY|CERTIFICATE|TEAMID|SIGNINGID|CDHASH
	Policy        string    `gorm:"type:varchar(32)" json:"policy"`                                      // ALLOWLIST|ALLOWLIST_COMPILER|BLOCKLIST|SILENT_BLOCKLIST|CEL
	CELExpr       string    `gorm:"type:text" json:"cel_expr"`
	CustomMsg     string    `gorm:"type:varchar(255)" json:"custom_msg"`
	CustomURL     string    `gorm:"type:varchar(1024)" json:"custom_url"`
	Scope         string    `gorm:"type:varchar(8);uniqueIndex:idx_santa_rule_unique" json:"scope"`         // env|tag|node
	ScopeValue    string    `gorm:"type:varchar(255);uniqueIndex:idx_santa_rule_unique" json:"scope_value"` // ""| tag name | node UUID (uppercase)
	CreatedBy     string    `gorm:"type:varchar(255)" json:"created_by"`
}

// TableName for Rule
func (Rule) TableName() string { return "santa_rules" }

// Machine is a Santa client that has synced with osctrl.
type Machine struct {
	ID              uint       `gorm:"primarykey" json:"id"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	EnvironmentID   uint       `gorm:"uniqueIndex:idx_santa_machine_env" json:"environment_id"`
	MachineID       string     `gorm:"type:varchar(64);uniqueIndex:idx_santa_machine_env" json:"machine_id"` // uppercase UUID
	NodeID          uint       `gorm:"index" json:"node_id"`
	SerialNumber    string     `json:"serial_number"`
	Hostname        string     `json:"hostname"`
	OSVersion       string     `json:"os_version"`
	SantaVersion    string     `json:"santa_version"`
	PrimaryUser     string     `json:"primary_user"`
	ClientMode      string     `json:"client_mode"`   // reported by the client
	AssignedMode    string     `json:"assigned_mode"` // sent at the last preflight
	ModeSource      string     `json:"mode_source"`   // env | tag | node
	RuleCount       uint32     `json:"rule_count"`
	AppliedDigest   string     `json:"applied_digest"`    // set at postflight
	PendingDigest   string     `json:"pending_digest"`    // set at preflight
	PendingSyncType string     `json:"pending_sync_type"` // NORMAL | CLEAN_RULES
	LastPreflightAt *time.Time `json:"last_preflight_at"`
	LastSyncAt      *time.Time `json:"last_sync_at"`
}

// TableName for Machine
func (Machine) TableName() string { return "santa_machines" }

// ModeOverride sets the client mode for a tag or a node, overriding the environment's.
type ModeOverride struct {
	ID            uint      `gorm:"primarykey" json:"id"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	EnvironmentID uint      `gorm:"uniqueIndex:idx_santa_mode_unique" json:"environment_id"`
	Scope         string    `gorm:"type:varchar(8);uniqueIndex:idx_santa_mode_unique" json:"scope"`         // tag|node
	ScopeValue    string    `gorm:"type:varchar(255);uniqueIndex:idx_santa_mode_unique" json:"scope_value"` // tag name | node UUID (uppercase)
	ClientMode    string    `gorm:"type:varchar(16)" json:"client_mode"`                                    // MONITOR | LOCKDOWN
	CreatedBy     string    `gorm:"type:varchar(255)" json:"created_by"`
}

// TableName for ModeOverride
func (ModeOverride) TableName() string { return "santa_mode_overrides" }

// Event is an execution event uploaded by a Santa client.
type Event struct {
	ID            uint      `gorm:"primarykey" json:"id"`
	CreatedAt     time.Time `gorm:"index" json:"created_at"`
	EnvironmentID uint      `gorm:"index" json:"environment_id"`
	NodeID        uint      `gorm:"index" json:"node_id"`
	MachineID     string    `json:"machine_id"`
	FileSHA256    string    `json:"file_sha256"`
	FilePath      string    `json:"file_path"`
	FileName      string    `json:"file_name"`
	ExecutingUser string    `json:"executing_user"`
	Decision      string    `json:"decision"`
	TeamID        string    `json:"team_id"`
	SigningID     string    `json:"signing_id"`
	CDHash        string    `json:"cd_hash"`
	BundleID      string    `json:"bundle_id"`
	ExecutedAt    time.Time `json:"executed_at"`
}

// TableName for Event
func (Event) TableName() string { return "santa_events" }

// Migrate creates the Santa tables and fills RemovableMedia for configs saved
// before it existed, from the deprecated BlockUSBMount.
func Migrate(db *gorm.DB) error {
	if err := db.AutoMigrate(&EnvConfig{}, &Rule{}, &Machine{}, &Event{}, &ModeOverride{}); err != nil {
		return err
	}
	const unset = "(removable_media = '' OR removable_media IS NULL)"
	if err := db.Model(&EnvConfig{}).Where(unset+" AND block_usb_mount = ?", true).
		UpdateColumn("removable_media", MediaBlock).Error; err != nil {
		return err
	}
	return db.Model(&EnvConfig{}).Where(unset).UpdateColumn("removable_media", MediaAllow).Error
}
