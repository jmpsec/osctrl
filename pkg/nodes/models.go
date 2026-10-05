package nodes

import (
	"time"

	"gorm.io/gorm"

	"github.com/jmpsec/osctrl/pkg/dbutil"
)

// OsqueryNode as abstraction of a node
type OsqueryNode struct {
	ID              uint           `gorm:"primarykey" json:"id"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
	DeletedAt       gorm.DeletedAt `gorm:"index" json:"-"`
	NodeKey         string         `gorm:"index" json:"-"`
	UUID            string         `gorm:"index" json:"uuid"`
	Platform        string         `json:"platform"`
	PlatformVersion string         `json:"platform_version"`
	OsqueryVersion  string         `json:"osquery_version"`
	Hostname        string         `json:"hostname"`
	Localname       string         `json:"localname"`
	IPAddress       string         `json:"ip_address"`
	Username        string         `json:"username"`
	OsqueryUser     string         `json:"osquery_user"`
	Environment     string         `json:"environment"`
	CPU             string         `json:"cpu"`
	Memory          string         `json:"memory"`
	HardwareSerial  string         `json:"hardware_serial"`
	DaemonHash      string         `json:"daemon_hash"`
	ConfigHash      string         `json:"config_hash"`
	BytesReceived   int            `json:"bytes_received"`
	RawEnrollment   string         `json:"-"`
	LastSeen        time.Time      `json:"last_seen"`
	// LastQueryRead is when the node last polled the distributed query
	// read endpoint. Interactive features (console, file explorer) use it
	// to predict the node's next read and size their warmup timeouts.
	// Hidden from JSON: it is server-side timing data, not node metadata.
	LastQueryRead time.Time `json:"-"`
	UserID        uint      `json:"user_id"`
	EnvironmentID uint      `json:"environment_id"`
	ExtraData     string    `json:"extra_data"`
}

// ArchiveOsqueryNode as abstraction of an archived node
type ArchiveOsqueryNode struct {
	ID              uint           `gorm:"primarykey" json:"id"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
	DeletedAt       gorm.DeletedAt `gorm:"index" json:"-"`
	NodeKey         string         `gorm:"index" json:"-"`
	UUID            string         `gorm:"index" json:"uuid"`
	Trigger         string         `json:"trigger"`
	Platform        string         `json:"platform"`
	PlatformVersion string         `json:"platform_version"`
	OsqueryVersion  string         `json:"osquery_version"`
	Hostname        string         `json:"hostname"`
	Localname       string         `json:"localname"`
	IPAddress       string         `json:"ip_address"`
	Username        string         `json:"username"`
	OsqueryUser     string         `json:"osquery_user"`
	Environment     string         `json:"environment"`
	CPU             string         `json:"cpu"`
	Memory          string         `json:"memory"`
	HardwareSerial  string         `json:"hardware_serial"`
	ConfigHash      string         `json:"config_hash"`
	DaemonHash      string         `json:"daemon_hash"`
	BytesReceived   int            `json:"bytes_received"`
	RawEnrollment   string         `json:"-"`
	LastSeen        time.Time      `json:"last_seen"`
	UserID          uint           `json:"user_id"`
	EnvironmentID   uint           `json:"environment_id"`
	ExtraData       string         `json:"extra_data"`
}

// NodeMetadata to hold metadata for a node
type NodeMetadata struct {
	IPAddress       string
	Username        string
	OsqueryUser     string
	Hostname        string
	Localname       string
	ConfigHash      string
	DaemonHash      string
	OsqueryVersion  string
	Platform        string
	PlatformVersion string
	BytesReceived   int
}

// Indexes are the secondary indexes for osquery_nodes beyond those in the
// struct tags, created by dbutil.EnsureIndexes. environment serves the
// per-environment counts and paged lists; hostname and localname let the
// uuid-or-hostname-or-localname lookups use an index for every branch.
//
// last_seen, ip_address and bytes_received are deliberately not indexed:
// every check-in or log batch rewrites them, and while no indexed column
// changes, Postgres can apply those updates in place (HOT) without touching
// any index on the table.
func Indexes() []dbutil.Index {
	return []dbutil.Index{
		{Model: &OsqueryNode{}, Name: "idx_osquery_nodes_environment", Columns: []string{"environment"}},
		{Model: &OsqueryNode{}, Name: "idx_osquery_nodes_hostname", Columns: []string{"hostname"}},
		{Model: &OsqueryNode{}, Name: "idx_osquery_nodes_localname", Columns: []string{"localname"}},
	}
}
