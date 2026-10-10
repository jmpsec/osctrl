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

// Finding confidence. Confirmed is an exact package-ecosystem match against
// an advisory; possible is a name-and-version match against NVD CPE data,
// shown but never alerted on or scored.
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

// Advisory sources: the feed that owns a record.
const (
	AdvisorySourceOSV = "osv"
	AdvisorySourceNVD = "nvd"
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
	// Assessed counts packages matched against an exact ecosystem feed
	// (OSV). It is what a clean result means for scoring; CPE matches never
	// count.
	Assessed int `json:"assessed"`
}

func (NodeState) TableName() string { return "vuln_node_state" }

// Advisory is one vulnerability record (an OSV id such as DSA-5678-1 or
// RHSA-2026:1234). KEV is owned by the KEV sync, never by the record.
type Advisory struct {
	ID string `gorm:"primaryKey;type:varchar(128)" json:"id"`
	// Source is the feed that owns the record. Existing rows predate NVD
	// support and are OSV records.
	Source     string  `gorm:"type:varchar(8);default:osv;index" json:"source"`
	Summary    string  `gorm:"type:text" json:"summary"`
	Details    string  `gorm:"type:text" json:"details"`
	CVSSVector string  `gorm:"type:varchar(255)" json:"cvss_vector"`
	CVSSScore  float64 `json:"cvss_score"`
	Severity   string  `gorm:"type:varchar(16);index" json:"severity"`
	// CVSSFrom is the aliased NVD CVE an OSV record without its own CVSS
	// borrowed its score from. Empty when the score is the record's own.
	CVSSFrom  string    `gorm:"type:varchar(32);default:''" json:"cvss_from"`
	KEV       bool      `gorm:"index" json:"kev"`
	RefURLs   string    `gorm:"type:text" json:"-"` // JSON array of URLs
	Published time.Time `json:"published"`
	Modified  time.Time `json:"modified"`
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

// CPEProduct is one vendor:product that a stored NVD CVE lists. It is the
// CPE dictionary name matching looks names up in: only products some CVE
// affects can produce a finding, so the full NVD dictionary would add
// nothing.
type CPEProduct struct {
	Vendor  string `gorm:"primaryKey;type:varchar(128)"`
	Product string `gorm:"primaryKey;type:varchar(128);index"`
}

func (CPEProduct) TableName() string { return "vuln_cpe_products" }

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
	// PeakSeverity and EverKEV are the highest state the finding reached:
	// escalations are measured against them, so falling and coming back is
	// not news. ReopenedAt is the last reopen: escalations recorded before
	// it are not news either.
	PeakSeverity string     `gorm:"type:varchar(16);default:''" json:"-"`
	EverKEV      bool       `gorm:"default:false" json:"-"`
	ReopenedAt   *time.Time `json:"-"`
}

func (Finding) TableName() string { return "vuln_findings" }

// Escalation records an open confirmed finding that became known-exploited
// or rose in severity: news the alert watcher reports once, by ID, like a
// new finding. Rows are pruned after escalationRetention.
type Escalation struct {
	ID           uint   `gorm:"primarykey"`
	FindingID    uint   `gorm:"index"`
	PrevSeverity string `gorm:"type:varchar(16)"`
	PrevKEV      bool
	CreatedAt    time.Time `gorm:"index"`
}

func (Escalation) TableName() string { return "vuln_escalations" }

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
	// ResumeIndex and ResumeStart let a full NVD sync that failed part-way
	// continue from its next page; ResumeStart is when that sync began.
	ResumeIndex int        `json:"-"`
	ResumeStart *time.Time `json:"-"`
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
	// NVDActiveAt is the last tick of a replica with --vuln-nvd-enabled.
	// Replicas with NVD off keep NVD data while it is recent.
	NVDActiveAt *time.Time `json:"-"`
	// NVDActiveBy is the host that stamped NVDActiveAt: a host's own stamp,
	// from before it restarted with NVD off, does not delay the drop.
	NVDActiveBy string `gorm:"type:varchar(255)" json:"-"`
}

func (WorkerState) TableName() string { return "vuln_worker_state" }

// Migrate creates the vulnerability tables. Called only when the feature is
// enabled, so a disabled deployment never has them.
func Migrate(db *gorm.DB) error {
	// vuln_node_state.assessed arrived with NVD support. Earlier rows read 0,
	// which posture treats as "nothing assessed", so adding the column
	// re-matches every node once instead of after the next advisory change.
	rematch := false
	if db.Migrator().HasTable(&NodeState{}) {
		has, err := hasColumn(db, &NodeState{}, "assessed")
		if err != nil {
			return err
		}
		rematch = !has
	}
	if err := db.AutoMigrate(&NodeSoftware{}, &NodeState{}, &Advisory{}, &Alias{},
		&Affected{}, &KEV{}, &CPEProduct{}, &Finding{}, &Escalation{}, &SyncState{}, &WorkerState{}); err != nil {
		return err
	}
	if rematch {
		return db.Model(&NodeState{}).Where("1 = 1").Update("matched_at", nil).Error
	}
	return nil
}

// hasColumn checks a column by exact name. GORM's SQLite HasColumn matches
// the table's SQL text, where "not_assessed" contains "assessed".
func hasColumn(db *gorm.DB, model any, name string) (bool, error) {
	cols, err := db.Migrator().ColumnTypes(model)
	if err != nil {
		return false, err
	}
	for _, c := range cols {
		if c.Name() == name {
			return true, nil
		}
	}
	return false, nil
}
