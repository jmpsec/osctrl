package carves

import (
	"time"

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
}

// CarvedBlock to store each block from a carve
type CarvedBlock struct {
	gorm.Model
	RequestID   string `gorm:"index"`
	SessionID   string `gorm:"index"`
	Environment string
	BlockID     int
	Data        string
	Size        int
	Carver      string
}
