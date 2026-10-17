package extensions

import (
	"time"

	"gorm.io/gorm"
)

// Extension is an osquery extension in the library. All rows in this
// package are hard-deleted.
type Extension struct {
	gorm.Model
	Name             string `gorm:"uniqueIndex:idx_ext_name;size:64"`
	Description      string
	Version          string `gorm:"size:64"`
	CommandExecution bool
	CreatedBy        string
	UpdatedBy        string
}

// ExtensionFile is the binary of an extension for one platform and arch.
type ExtensionFile struct {
	gorm.Model
	ExtensionID uint   `gorm:"uniqueIndex:idx_ext_file_platform"`
	Platform    string `gorm:"uniqueIndex:idx_ext_file_platform;size:16"`
	Arch        string `gorm:"uniqueIndex:idx_ext_file_platform;size:16"`
	Size        int64
	SHA256      string `gorm:"index:idx_ext_file_sha;size:64"`
	Filename    string
	UpdatedBy   string
}

// ExtensionChunk is one ChunkSize piece of a file's content, keyed by the
// whole file's SHA-256 so identical files share chunks. Data maps to
// longblob (MySQL), bytea (Postgres) and blob (SQLite); do not add a size tag
// below 64 KiB.
type ExtensionChunk struct {
	ID     uint
	SHA256 string `gorm:"index:idx_ext_chunk_sha;size:64"`
	Seq    int
	Data   []byte
}

// EnvExtension assigns an ordinary extension to an environment.
type EnvExtension struct {
	gorm.Model
	EnvironmentID uint `gorm:"uniqueIndex:idx_ext_env"`
	ExtensionID   uint `gorm:"uniqueIndex:idx_ext_env"`
	CreatedBy     string
}

// NodeExtension assigns a command-execution extension to one node.
type NodeExtension struct {
	gorm.Model
	NodeUUID      string `gorm:"uniqueIndex:idx_ext_node;size:255"`
	ExtensionID   uint   `gorm:"uniqueIndex:idx_ext_node"`
	EnvironmentID uint   `gorm:"index:idx_ext_node_env"`
	ExpiresAt     *time.Time
	CreatedBy     string
}

// NodeExtensionStatus is the last status osctrld reported for an extension.
type NodeExtensionStatus struct {
	gorm.Model
	NodeUUID      string `gorm:"uniqueIndex:idx_ext_status;size:255"`
	Name          string `gorm:"uniqueIndex:idx_ext_status;size:64"`
	EnvironmentID uint
	SHA256        string
	Result        string
	Error         string
	At            *time.Time
	ReportedAt    time.Time
}

// ExtensionView is a library entry with its files and assignment counts.
type ExtensionView struct {
	Extension
	Files           []ExtensionFile
	EnvAssignments  int64
	NodeAssignments int64
}
