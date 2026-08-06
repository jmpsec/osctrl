package fileexplorer

import (
	"time"

	"gorm.io/gorm"
)

const (
	ActionList    = "list"
	ActionStat    = "stat"
	ActionPriming = "priming"

	StatusQueued    = "queued"
	StatusCompleted = "completed"
	StatusError     = "error"
	StatusExpired   = "expired"
)

type Session struct {
	ID            uint           `gorm:"primarykey" json:"id"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	DeletedAt     gorm.DeletedAt `gorm:"index" json:"-"`
	EnvironmentID uint           `gorm:"not null;index" json:"environment_id"`
	NodeID        uint           `gorm:"not null;index" json:"node_id"`
	NodeUUID      string         `gorm:"not null;index" json:"node_uuid"`
	Creator       string         `gorm:"not null;index" json:"creator"`
	Platform      string         `json:"platform"`
	Root          string         `gorm:"not null" json:"root"`
	Active        bool           `gorm:"not null;default:true" json:"active"`
	ClosedAt      *time.Time     `json:"closed_at,omitempty"`
}

func (Session) TableName() string {
	return "file_explorer_sessions"
}

type Request struct {
	ID                   uint           `gorm:"primarykey" json:"id"`
	CreatedAt            time.Time      `json:"created_at"`
	UpdatedAt            time.Time      `json:"updated_at"`
	DeletedAt            gorm.DeletedAt `gorm:"index" json:"-"`
	SessionID            uint           `gorm:"not null;index" json:"session_id"`
	Action               string         `gorm:"not null;index" json:"action"`
	Path                 string         `gorm:"not null" json:"path"`
	TranslatedSQL        string         `json:"translated_sql"`
	DistributedQueryName string         `gorm:"index" json:"distributed_query_name,omitempty"`
	Status               string         `gorm:"not null;index" json:"status"`
	Error                string         `json:"error,omitempty"`
	Priming              bool           `gorm:"not null;default:false;index" json:"priming"`
	CompletedAt          *time.Time     `json:"completed_at,omitempty"`
	ExpiredAt            *time.Time     `json:"expired_at,omitempty"`
}

func (Request) TableName() string {
	return "file_explorer_requests"
}

type Entry struct {
	Path      string `json:"path"`
	Filename  string `json:"filename"`
	Directory string `json:"directory"`
	Type      string `json:"type"`
	Size      int64  `json:"size,omitempty"`
	Mode      string `json:"mode,omitempty"`
	UID       string `json:"uid,omitempty"`
	GID       string `json:"gid,omitempty"`
	MTime     int64  `json:"mtime,omitempty"`
	ATime     int64  `json:"atime,omitempty"`
	CTime     int64  `json:"ctime,omitempty"`
}
