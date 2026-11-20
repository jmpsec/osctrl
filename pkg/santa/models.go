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
	// 0 means the Santa default (600); otherwise MinSyncInterval..MaxSyncInterval
	FullSyncIntervalSeconds uint32 `json:"full_sync_interval_seconds"`
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
	// Base https URL of the osctrl UI. When set, the Santa block dialog links to
	// its approval request page; empty turns approval requests off.
	ApprovalURL string `gorm:"type:varchar(255)" json:"approval_url"`
	// Alert channel IDs told about each new approval request, with single-use
	// approve and deny links. Needs ApprovalURL.
	NotifyChannels []uint `gorm:"serializer:json;type:varchar(255)" json:"notify_channels"`
	// Email alert channel whose relay emails each requester, at their osctrl
	// account address, when their request is decided and when an approved
	// MONITOR window ends; 0 is off.
	RequesterChannel uint `json:"requester_channel"`
	// Votes for a blocked file that allow it on each voter's machine; 0 is off.
	VoteLocalThreshold uint32 `json:"vote_local_threshold"`
	// Votes that allow the file in the whole environment; 0 is off.
	VoteGlobalThreshold uint32 `json:"vote_global_threshold"`
	// Votes older than this many days are deleted; 0 keeps them
	VoteExpiryDays uint32 `json:"vote_expiry_days"`
	// Overrides the action of MDM-deployed file access rules: NONE | AUDIT_ONLY | DISABLE;
	// empty sends nothing, leaving each client's setting unchanged
	OverrideFileAccessAction string `gorm:"type:varchar(16)" json:"override_file_access_action"`
	// Clients hash the bundle of a blocked binary and upload its other binaries on request
	EnableBundles bool `json:"enable_bundles"`
	// Upload every execution decision, not only blocks and would-be blocks
	EnableAllEventUpload bool `json:"enable_all_event_upload"`
	// Skip uploading executions that LOCKDOWN would block
	DisableUnknownEventUpload bool `json:"disable_unknown_event_upload"`
	// Executions from matching paths are allowed or blocked when no rule matches; empty is off
	AllowedPathRegex string `gorm:"type:varchar(1024)" json:"allowed_path_regex"`
	BlockedPathRegex string `gorm:"type:varchar(1024)" json:"blocked_path_regex"`
	// https URL of the block dialog button, with Santa placeholders; overrides the
	// approval request link. EventDetailText is the button label.
	EventDetailURL  string `gorm:"type:varchar(1024)" json:"event_detail_url"`
	EventDetailText string `gorm:"type:varchar(64)" json:"event_detail_text"`
	// IdP groups whose members' machines get a tag, matched on the Santa primary user
	GroupTags []GroupTag `gorm:"serializer:json;type:text" json:"group_tags"`
	// How the primary user matches an osctrl user: "" (exact username) | local_part | email
	GroupMatch string `gorm:"type:varchar(16)" json:"group_match"`
	// Changes that weaken enforcement wait for a second environment admin
	RequireSecondAdmin bool `json:"require_second_admin"`
	// osctrl users and IdP groups who decide approval requests
	// without being environment admins
	ApproverUsers  []string `gorm:"serializer:json;type:text" json:"approver_users"`
	ApproverGroups []string `gorm:"serializer:json;type:text" json:"approver_groups"`
}

// GroupTag maps an IdP group to a node tag of the environment.
type GroupTag struct {
	Group string `json:"group"`
	Tag   string `json:"tag"`
}

// UserGroups holds the IdP groups of an osctrl user from their last SSO login.
type UserGroups struct {
	Username  string    `gorm:"type:varchar(255);primaryKey" json:"username"` // lowercase
	Groups    []string  `gorm:"serializer:json;type:text" json:"groups"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TableName for UserGroups
func (UserGroups) TableName() string { return "santa_user_groups" }

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
	// Who asked for a temporary override through an approval request; empty otherwise.
	Requester string `gorm:"type:varchar(255)" json:"requester,omitempty"`
	// Set for a temporary override; it stops applying at this time. Nil is permanent.
	ExpiresAt *time.Time `gorm:"index" json:"expires_at"`
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
	BundleName    string    `json:"bundle_name"`
	BundleVersion string    `json:"bundle_version"`
	BundlePath    string    `json:"bundle_path"`
	// Hash of the binary's bundle, lowercase hex; set when bundles are enabled
	BundleHash string `gorm:"type:varchar(64);index" json:"bundle_hash"`
	// Leaf certificate first, as the client reported it; empty for unsigned files
	// and for events stored before the chain was kept.
	SigningChain []Cert `gorm:"serializer:json;type:text" json:"signing_chain"`
	// Name of the osquery carve started from this event to retrieve the file; set by osctrl.
	CarveName string `gorm:"type:varchar(255)" json:"carve_name"`
}

// Cert is one certificate of a signing chain, as reported by the Santa client.
type Cert struct {
	SHA256     string    `json:"sha256"`
	CN         string    `json:"cn"`
	Org        string    `json:"org"`
	OU         string    `json:"ou"`
	ValidFrom  time.Time `json:"valid_from"`
	ValidUntil time.Time `json:"valid_until"`
}

// TableName for Event
func (Event) TableName() string { return "santa_events" }

// FileAccessEvent is a violation of a file access rule, uploaded by a Santa
// client. Every field but the IDs is written by the client.
type FileAccessEvent struct {
	ID            uint      `gorm:"primarykey" json:"id"`
	CreatedAt     time.Time `gorm:"index" json:"created_at"`
	EnvironmentID uint      `gorm:"index" json:"environment_id"`
	NodeID        uint      `gorm:"index" json:"node_id"`
	MachineID     string    `gorm:"type:varchar(64)" json:"machine_id"`
	RuleName      string    `json:"rule_name"`
	RuleVersion   string    `json:"rule_version"`
	// The path that was accessed
	Target string `gorm:"type:varchar(1024)" json:"target"`
	// DENIED | DENIED_INVALID_SIGNATURE | AUDIT_ONLY
	Decision   string    `json:"decision"`
	AccessedAt time.Time `json:"accessed_at"`
	// The accessing process first, then its parents
	ProcessChain []Process `gorm:"serializer:json;type:text" json:"process_chain"`
}

// TableName for FileAccessEvent
func (FileAccessEvent) TableName() string { return "santa_file_access_events" }

// Process is one process of a file access event's process chain.
type Process struct {
	Pid        int32  `json:"pid"`
	FilePath   string `json:"file_path"`
	FileSHA256 string `json:"file_sha256"`
	SigningID  string `json:"signing_id"`
	TeamID     string `json:"team_id"`
	CDHash     string `json:"cd_hash"`
}

// Request statuses.
const (
	RequestPending  = "pending"
	RequestApproved = "approved"
	RequestDenied   = "denied"
	RequestExpired  = "expired"
)

// RequestKindMonitor is a request for temporary MONITOR mode on the machine.
// The empty kind is a request to allow a blocked file.
const RequestKindMonitor = "monitor"

// Request is a user's request to allow a binary that Santa blocked on a machine.
// The file fields are copied from the linked event, which is pruned earlier
// than the request; they are written by the Santa client.
type Request struct {
	ID            uint      `gorm:"primarykey" json:"id"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	EnvironmentID uint      `gorm:"index:idx_santa_request_target" json:"environment_id"`
	MachineID     string    `gorm:"type:varchar(64);index:idx_santa_request_target" json:"machine_id"`
	FileSHA256    string    `gorm:"type:varchar(64);index:idx_santa_request_target" json:"file_sha256"`
	EventID       uint      `json:"event_id"`
	FileName      string    `json:"file_name"`
	FilePath      string    `json:"file_path"`
	SigningID     string    `json:"signing_id"`
	TeamID        string    `json:"team_id"`
	ExecutingUser string    `json:"executing_user"`
	Requester     string    `gorm:"type:varchar(255);index" json:"requester"`
	Justification string    `gorm:"type:varchar(1000)" json:"justification"`
	Status        string    `gorm:"type:varchar(16);index" json:"status"` // pending|approved|denied|expired
	// Set when the request is approved or denied.
	DecidedBy string     `gorm:"type:varchar(255)" json:"decided_by"`
	DecidedAt *time.Time `json:"decided_at"`
	// Why it was denied; optional note on an approval.
	Reason string `gorm:"type:varchar(1000)" json:"reason"`
	// The allow rule an approval created or reused; 0 otherwise.
	RuleID uint `json:"rule_id"`
	// "" (allow the file) or monitor (temporary MONITOR mode, no file fields)
	Kind string `gorm:"type:varchar(16)" json:"kind"`
	// Hours of MONITOR mode asked for, with kind monitor
	MonitorHours uint `json:"monitor_hours"`
	// The approver allowed the file although a risk check flagged it
	RiskOverride bool `json:"risk_override"`
	// Type of the allow rule an approval created: BINARY, SIGNINGID, TEAMID or
	// CERTIFICATE; empty for MONITOR and before the type could be chosen
	RuleType string `gorm:"type:varchar(16)" json:"rule_type"`
	// Leaf certificate of the blocked file, from its event; not stored
	CertSHA256 string `gorm:"-" json:"cert_sha256,omitempty"`
	// Binaries the client uploaded for the file's bundle; not stored
	BundleBinaries int `gorm:"-" json:"bundle_binaries,omitempty"`
	// Cached risk verdict of the file, when risk checks are on; not stored
	Risk *Risk `gorm:"-" json:"risk,omitempty"`
}

// TableName for Request
func (Request) TableName() string { return "santa_requests" }

// RequestLink is a single-use approve or deny link sent with the notification
// of a new request. Only the SHA-256 of its token is stored.
type RequestLink struct {
	ID            uint       `gorm:"primarykey" json:"id"`
	CreatedAt     time.Time  `json:"created_at"`
	EnvironmentID uint       `json:"environment_id"`
	RequestID     uint       `gorm:"index" json:"request_id"`
	Approve       bool       `json:"approve"`
	TokenHash     string     `gorm:"type:varchar(64);uniqueIndex" json:"-"`
	ExpiresAt     time.Time  `gorm:"index" json:"expires_at"`
	UsedAt        *time.Time `json:"used_at"`
	UsedBy        string     `gorm:"type:varchar(255)" json:"used_by"`
}

// TableName for RequestLink
func (RequestLink) TableName() string { return "santa_request_links" }

// Vote is one user's vote to allow a file Santa blocked on their machine. A
// user has one vote per file in an environment.
type Vote struct {
	ID            uint      `gorm:"primarykey" json:"id"`
	CreatedAt     time.Time `json:"created_at"`
	EnvironmentID uint      `gorm:"uniqueIndex:idx_santa_vote" json:"environment_id"`
	FileSHA256    string    `gorm:"type:varchar(64);uniqueIndex:idx_santa_vote" json:"file_sha256"`
	Voter         string    `gorm:"type:varchar(255);uniqueIndex:idx_santa_vote" json:"voter"`
	MachineID     string    `gorm:"type:varchar(64)" json:"machine_id"`
}

// TableName for Vote
func (Vote) TableName() string { return "santa_votes" }

// Migrate creates the Santa tables and fills RemovableMedia for configs saved
// before it existed, from the deprecated BlockUSBMount.
func Migrate(db *gorm.DB) error {
	if err := db.AutoMigrate(&EnvConfig{}, &Rule{}, &Machine{}, &Event{}, &ModeOverride{}, &Request{}, &RequestLink{}, &Vote{}, &Verdict{}, &FileAccessEvent{}, &UserGroups{}); err != nil {
		return err
	}
	const unset = "(removable_media = '' OR removable_media IS NULL)"
	if err := db.Model(&EnvConfig{}).Where(unset+" AND block_usb_mount = ?", true).
		UpdateColumn("removable_media", MediaBlock).Error; err != nil {
		return err
	}
	return db.Model(&EnvConfig{}).Where(unset).UpdateColumn("removable_media", MediaAllow).Error
}
