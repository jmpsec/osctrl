package nodes

import (
	"time"

	"gorm.io/gorm"
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
	UserID          uint           `json:"user_id"`
	EnvironmentID   uint           `json:"environment_id"`
	ExtraData       string         `json:"extra_data"`
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
