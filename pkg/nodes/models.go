package nodes

import (
	"time"

	"gorm.io/gorm"
)

// OsqueryNode as abstraction of a node
type OsqueryNode struct {
	gorm.Model
	NodeKey         string `gorm:"index"`
	UUID            string `gorm:"index"`
	Platform        string
	PlatformVersion string
	OsqueryVersion  string
	Hostname        string
	Localname       string
	IPAddress       string
	Username        string
	OsqueryUser     string
	Environment     string
	CPU             string
	Memory          string
	HardwareSerial  string
	DaemonHash      string
	ConfigHash      string
	BytesReceived   int
	RawEnrollment   string
	LastSeen        time.Time
	UserID          uint
	EnvironmentID   uint
	ExtraData       string
}

// ArchiveOsqueryNode as abstraction of an archived node
type ArchiveOsqueryNode struct {
	gorm.Model
	NodeKey         string `gorm:"index"`
	UUID            string `gorm:"index"`
	Trigger         string
	Platform        string
	PlatformVersion string
	OsqueryVersion  string
	Hostname        string
	Localname       string
	IPAddress       string
	Username        string
	OsqueryUser     string
	Environment     string
	CPU             string
	Memory          string
	HardwareSerial  string
	ConfigHash      string
	DaemonHash      string
	BytesReceived   int
	RawEnrollment   string
	LastSeen        time.Time
	UserID          uint
	EnvironmentID   uint
	ExtraData       string
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
