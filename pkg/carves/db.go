package carves

import (
	"time"

	"github.com/jmpsec/osctrl/pkg/dbutil"
	"gorm.io/gorm"
)

// CarvedFile to keep track of carved files from nodes
type CarvedFile struct {
	gorm.Model
	CarveID         string `gorm:"unique;index"`
	RequestID       string
	SessionID       string
	QueryName       string
	UUID            string `gorm:"index"`
	NodeID          uint
	Environment     string
	Path            string
	CarveSize       int
	BlockSize       int
	TotalBlocks     int
	CompletedBlocks int
	Status          string
	CompletedAt     time.Time
	Carver          string
	Archived        bool
	ArchivePath     string
	EnvironmentID   uint
}

// CarvedBlock to store each block from a carve
type CarvedBlock struct {
	gorm.Model
	RequestID     string `gorm:"index"`
	SessionID     string `gorm:"index"`
	Environment   string
	BlockID       int
	Data          string
	Size          int
	Carver        string
	EnvironmentID uint
}

// Indexes are the secondary indexes for carved_files beyond those in the
// struct tags, created by dbutil.EnsureIndexes: the carves list looks up each
// carve's files by query name within an environment.
func Indexes() []dbutil.Index {
	return []dbutil.Index{
		{Model: &CarvedFile{}, Name: "idx_carved_files_env_query", Columns: []string{"environment_id", "query_name"}},
	}
}
