package console

import (
	"time"

	"gorm.io/gorm"
)

const (
	CommandLocal    = "local"
	CommandRemote   = "remote"
	CommandCarve    = "carve"
	CommandMode     = "mode"
	CommandExitMode = "exit-mode"

	StatusQueued    = "queued"
	StatusDelivered = "delivered"
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
	CWD           string         `gorm:"not null" json:"cwd"`
	Platform      string         `json:"platform"`
	Active        bool           `gorm:"not null;default:true" json:"active"`
	ClosedAt      *time.Time     `json:"closed_at,omitempty"`
}

func (Session) TableName() string {
	return "console_sessions"
}

type Command struct {
	ID                   uint           `gorm:"primarykey" json:"id"`
	CreatedAt            time.Time      `json:"created_at"`
	UpdatedAt            time.Time      `json:"updated_at"`
	DeletedAt            gorm.DeletedAt `gorm:"index" json:"-"`
	SessionID            uint           `gorm:"not null;index" json:"session_id"`
	Input                string         `gorm:"not null" json:"input"`
	TranslatedSQL        string         `json:"translated_sql"`
	DistributedQueryName string         `gorm:"index" json:"distributed_query_name,omitempty"`
	Status               string         `gorm:"not null;index" json:"status"`
	Error                string         `json:"error,omitempty"`
	DeliveredAt          *time.Time     `json:"delivered_at,omitempty"`
	CompletedAt          *time.Time     `json:"completed_at,omitempty"`
	ExpiredAt            *time.Time     `json:"expired_at,omitempty"`
}

func (Command) TableName() string {
	return "console_commands"
}

type ParsedCommand struct {
	Kind    string `json:"kind"`
	Command string `json:"command"`
	Mode    string `json:"mode,omitempty"`
	Path    string `json:"path,omitempty"`
	SQL     string `json:"sql,omitempty"`
	Output  string `json:"output,omitempty"`
	Message string `json:"message,omitempty"`
}

type HistoryEntry struct {
	Command Command          `json:"command"`
	Results []map[string]any `json:"results"`
}
