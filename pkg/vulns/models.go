// Package vulns reports which nodes run software affected by known
// vulnerabilities. osctrl-tls stores each node's inventory (inventory.go);
// osctrl-api downloads advisory data, matches it and serves the findings
// (worker.go, read.go). Everything is inert unless --vuln-enabled is set.
package vulns

import (
	"time"

	"gorm.io/gorm"
)

// QueryPrefix names the scheduled queries whose results are inventory.
const QueryPrefix = "osctrl:vuln:"

// Finding confidence. Only confirmed findings are produced today: an exact
// package-ecosystem match against an advisory.
const (
	ConfidenceConfirmed = "confirmed"
	ConfidencePossible  = "possible"
)

// Severity buckets, derived from a CVSS score.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityUnknown  = "unknown"
)

// NodeSoftware is one installed package on one node, from the latest
// inventory snapshot for its category.
type NodeSoftware struct {
	ID            uint      `gorm:"primarykey" json:"-"`
	NodeUUID      string    `gorm:"type:varchar(64);index:idx_vuln_sw_node" json:"node_uuid"`
	EnvironmentID uint      `gorm:"index" json:"environment_id"`
	Category      string    `gorm:"type:varchar(32);index:idx_vuln_sw_node" json:"category"`
	Name          string    `gorm:"type:varchar(255)" json:"name"`
	SourceName    string    `gorm:"type:varchar(255)" json:"source_name"`
	Version       string    `gorm:"type:varchar(255)" json:"version"`
	Arch          string    `gorm:"type:varchar(32)" json:"arch"`
	Vendor        string    `gorm:"type:varchar(255)" json:"vendor"`
	LastSeen      time.Time `json:"last_seen"`
}

func (NodeSoftware) TableName() string { return "node_software" }

// NodeState is per-node bookkeeping: the OS (which picks the advisory
// ecosystem for distro packages) and whether findings are current. A node
// needs matching when MatchedAt is NULL or older than InventoryAt.
type NodeState struct {
	NodeUUID      string     `gorm:"primaryKey;type:varchar(64)" json:"node_uuid"`
	EnvironmentID uint       `gorm:"index" json:"environment_id"`
	OSPlatform    string     `gorm:"type:varchar(64)" json:"os_platform"`
	OSVersion     string     `gorm:"type:varchar(128)" json:"os_version"`
	OSMajor       string     `gorm:"type:varchar(16)" json:"os_major"`
	InventoryAt   time.Time  `gorm:"index" json:"inventory_at"`
	MatchedAt     *time.Time `gorm:"index" json:"matched_at"`
	NotAssessed   int        `json:"not_assessed"`
}

func (NodeState) TableName() string { return "vuln_node_state" }

// Advisory is one vulnerability record (an OSV id such as DSA-5678-1 or
// RHSA-2026:1234). KEV is owned by the KEV sync, never by the record.
type Advisory struct {
	ID         string    `gorm:"primaryKey;type:varchar(128)" json:"id"`
	Summary    string    `gorm:"type:text" json:"summary"`
	Details    string    `gorm:"type:text" json:"details"`
	CVSSVector string    `gorm:"type:varchar(255)" json:"cvss_vector"`
	CVSSScore  float64   `json:"cvss_score"`
	Severity   string    `gorm:"type:varchar(16);index" json:"severity"`
	KEV        bool      `gorm:"index" json:"kev"`
	RefURLs    string    `gorm:"type:text" json:"-"` // JSON array of URLs
	Published  time.Time `json:"published"`
	Modified   time.Time `json:"modified"`
}

func (Advisory) TableName() string { return "vuln_advisories" }

// Alias links an advisory to another identifier for it, usually a CVE.
type Alias struct {
	AdvisoryID string `gorm:"primaryKey;type:varchar(128)"`
	Alias      string `gorm:"primaryKey;type:varchar(128);index"`
}

func (Alias) TableName() string { return "vuln_aliases" }

// Affected is one (ecosystem, package) an advisory affects. Ecosystem is the
// normalized key from AdvisoryKey; Package is the PackageKey of the name.
type Affected struct {
	ID         uint   `gorm:"primarykey"`
	AdvisoryID string `gorm:"type:varchar(128);index"`
	Ecosystem  string `gorm:"type:varchar(64);index:idx_vuln_affected_pkg"`
	Package    string `gorm:"type:varchar(255);index:idx_vuln_affected_pkg"`
	Ranges     string `gorm:"type:text"` // JSON []Range
	Versions   string `gorm:"type:text"` // JSON []string
}

func (Affected) TableName() string { return "vuln_affected" }

// KEV is one CVE in the CISA Known Exploited Vulnerabilities catalog.
type KEV struct {
	CVEID string `gorm:"primaryKey;type:varchar(32)"`
}

func (KEV) TableName() string { return "vuln_kev" }

// Finding is one advisory affecting one package on one node. Resolved
// findings are kept (ResolvedAt set) so "fixed on" stays visible.
type Finding struct {
	ID               uint       `gorm:"primarykey" json:"id"`
	NodeUUID         string     `gorm:"type:varchar(64);uniqueIndex:idx_vuln_finding" json:"node_uuid"`
	EnvironmentID    uint       `gorm:"index" json:"environment_id"`
	AdvisoryID       string     `gorm:"type:varchar(128);uniqueIndex:idx_vuln_finding;index" json:"advisory_id"`
	Ecosystem        string     `gorm:"type:varchar(64);uniqueIndex:idx_vuln_finding" json:"ecosystem"`
	Package          string     `gorm:"type:varchar(255);uniqueIndex:idx_vuln_finding" json:"package"`
	InstalledVersion string     `gorm:"type:varchar(255)" json:"installed_version"`
	FixedVersion     string     `gorm:"type:varchar(255)" json:"fixed_version"`
	Confidence       string     `gorm:"type:varchar(16);index" json:"confidence"`
	Severity         string     `gorm:"type:varchar(16);index" json:"severity"`
	KEV              bool       `json:"kev"`
	FirstSeen        time.Time  `json:"first_seen"`
	LastSeen         time.Time  `json:"last_seen"`
	ResolvedAt       *time.Time `gorm:"index" json:"resolved_at"`
}

func (Finding) TableName() string { return "vuln_findings" }

// SyncState is one feed's progress: "osv:<dir>" or "kev". Cursor only
// advances after a successful sync.
type SyncState struct {
	Source      string     `gorm:"primaryKey;type:varchar(128)" json:"source"`
	Cursor      time.Time  `json:"cursor"`
	LastSuccess *time.Time `json:"last_success"`
	LastWritten int        `json:"last_written"`
	LastSkipped int        `json:"last_skipped"`
	LastError   string     `gorm:"type:text" json:"last_error"`
	LastErrorAt *time.Time `json:"last_error_at"`
}

func (SyncState) TableName() string { return "vuln_sync_state" }

// WorkerState is the single coordination row shared by every osctrl-api
// replica: who holds the lease and what the worker last did.
type WorkerState struct {
	Name            string     `gorm:"primaryKey;type:varchar(32)" json:"-"`
	Owner           string     `gorm:"type:varchar(128)" json:"-"`
	LeaseUntil      time.Time  `json:"-"`
	SyncRequestedAt *time.Time `json:"sync_requested_at"`
	LastSyncAt      *time.Time `json:"last_sync_at"`
	LastSyncFailed  bool       `json:"last_sync_failed"`
	LastHousekeepAt *time.Time `json:"-"`
}

func (WorkerState) TableName() string { return "vuln_worker_state" }

// Migrate creates the vulnerability tables. Called only when the feature is
// enabled, so a disabled deployment never has them.
func Migrate(db *gorm.DB) error {
	return db.AutoMigrate(&NodeSoftware{}, &NodeState{}, &Advisory{}, &Alias{},
		&Affected{}, &KEV{}, &Finding{}, &SyncState{}, &WorkerState{})
}
