package main

import (
	"encoding/json"

	"github.com/javuto/osctrl/nodes"
	"github.com/javuto/osctrl/queries"

	"github.com/jinzhu/gorm"
)

// JSONConfigurationDB to hold all backend configuration values
type JSONConfigurationDB struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// JSONConfigurationTLS to hold all TLS endpoint configuration values
type JSONConfigurationTLS struct {
	Listener string `json:"listener"`
	Port     string `json:"port"`
	Host     string `json:"host"`
	Auth     string `json:"auth"`
}

// JSONConfigurationAdmin to hold all Admin configuration values
type JSONConfigurationAdmin struct {
	Listener string `json:"listener"`
	Port     string `json:"port"`
	Host     string `json:"host"`
	Auth     string `json:"auth"`
}

// JSONConfigurationLogging to keep all the logging configuration values
type JSONConfigurationLogging struct {
	Stdout     bool                     `json:"stdout"`
	Graylog    bool                     `json:"graylog"`
	GraylogCfg LoggingConfigurationData `json:"graylogcfg"`
	Splunk     bool                     `json:"splunk"`
	SplunkCfg  LoggingConfigurationData `json:"slunkcfg"`
	Postgres   bool                     `json:"postgres"`
}

// LoggingConfigurationData to keep a map with details for each logging entry
type LoggingConfigurationData map[string]string

// JSONConfigurationGeoLocation to keep all the geo location configuration values
type JSONConfigurationGeoLocation struct {
	Maps          bool                         `json:"maps"`
	IPStackCfg    GeoLocationConfigurationData `json:"ipstackcfg"`
	GoogleMapsCfg GeoLocationConfigurationData `json:"googlemapscfg"`
}

// GeoLocationConfigurationData to keep a map with details for each geo location entry
type GeoLocationConfigurationData map[string]string

// GenericRequest to some endpoints
type GenericRequest struct {
	NodeKey string `json:"node_key"`
}

// GenericResponse for osquery nodes
type GenericResponse struct {
	NodeInvalid bool `json:"node_invalid"`
}

// DistributedQuery as abstraction of a distributed query
type DistributedQuery struct {
	gorm.Model
	Name       string `gorm:"not null;unique;index"`
	Creator    string
	Query      string
	Executions int
	Errors     int
	Active     bool
	Completed  bool
	Deleted    bool
	Repeat     uint
}

// DistributedQueryTarget to keep target logic for queries
type DistributedQueryTarget struct {
	gorm.Model
	Name  string `gorm:"index"`
	Type  string
	Value string
}

// DistributedQueryExecution to keep track of queries executing
type DistributedQueryExecution struct {
	gorm.Model
	Name   string `gorm:"index"`
	UUID   string `gorm:"index"`
	Result int
}

// OSVersionTable provided on enrollment, table os_version
type OSVersionTable struct {
	ID           string `json:"_id"`
	Codename     string `json:"codename"`
	Major        string `json:"major"`
	Minor        string `json:"minor"`
	Name         string `json:"name"`
	Patch        string `json:"patch"`
	Platform     string `json:"platform"`
	PlatformLike string `json:"platform_like"`
	Version      string `json:"version"`
}

// OsqueryInfoTable provided on enrollment, table osquery_info
type OsqueryInfoTable struct {
	BuildDistro   string `json:"build_distro"`
	BuildPlatform string `json:"build_platform"`
	ConfigHash    string `json:"config_hash"`
	ConfigValid   string `json:"config_valid"`
	Extension     string `json:"extensions"`
	InstanceID    string `json:"instance_id"`
	PID           string `json:"pid"`
	StartTime     string `json:"start_time"`
	UUID          string `json:"uuid"`
	Version       string `json:"version"`
	Watcher       string `json:"watcher"`
}

// PlatformInfoTable provided on enrollment, table platform_info
type PlatformInfoTable struct {
	Address    string `json:"address"`
	Date       string `json:"date"`
	Extra      string `json:"extra"`
	Revision   string `json:"revision"`
	Size       string `json:"size"`
	Vendor     string `json:"vendor"`
	Version    string `json:"version"`
	VolumeSize string `json:"volume_size"`
}

// SystemInfoTable provided on enrollment, table system_info
type SystemInfoTable struct {
	ComputerName     string `json:"computer_name"`
	CPUBrand         string `json:"cpu_brand"`
	CPULogicalCores  string `json:"cpu_logical_cores"`
	CPUPhysicalCores string `json:"cpu_physical_cores"`
	CPUSubtype       string `json:"cpu_subtype"`
	CPUType          string `json:"cpu_type"`
	HardwareModel    string `json:"hardware_model"`
	HardwareSerial   string `json:"hardware_serial"`
	HardwareVendor   string `json:"hardware_vendor"`
	HardwareVersion  string `json:"hardware_version"`
	Hostname         string `json:"hostname"`
	LocalHostname    string `json:"local_hostname"`
	PhysicalMemory   string `json:"physical_memory"`
	UUID             string `json:"uuid"`
}

// EnrollRequest received when nodes enroll
type EnrollRequest struct {
	EnrollSecret   string `json:"enroll_secret"`
	HostIdentifier string `json:"host_identifier"`
	PlatformType   string `json:"platform_type"`
	HostDetails    struct {
		EnrollOSVersion    OSVersionTable    `json:"os_version"`
		EnrollOsqueryInfo  OsqueryInfoTable  `json:"osquery_info"`
		EnrollSystemInfo   SystemInfoTable   `json:"system_info"`
		EnrollPlatformInfo PlatformInfoTable `json:"platform_info"`
	} `json:"host_details"`
}

// EnrollResponse to be returned to agents
type EnrollResponse struct {
	NodeKey     string `json:"node_key"`
	NodeInvalid bool   `json:"node_invalid"`
}

// ConfigRequest received when nodes request configuration
type ConfigRequest GenericRequest

// ConfigResponse for configuration requests from nodes
type ConfigResponse GenericResponse

// LogRequest received to process logs
type LogRequest struct {
	NodeKey string          `json:"node_key"`
	LogType string          `json:"log_type"`
	Data    json.RawMessage `json:"data"`
}

// LogResponse for log requests from nodes
type LogResponse GenericResponse

// LogDecorations for decorations field in node logs requests
type LogDecorations struct {
	Username       string `json:"username"`
	OsqueryUser    string `json:"osquery_user"`
	LocalHostname  string `json:"local_hostname"`
	Hostname       string `json:"hostname"`
	OsqueryVersion string `json:"osquery_version"`
	ConfigHash     string `json:"config_hash"`
}

// LogResultData to be used processing result logs from nodes
type LogResultData struct {
	Name           string          `json:"name"`
	Epoch          int64           `json:"epoch"`
	Action         string          `json:"action"`
	Columns        json.RawMessage `json:"columns"`
	Counter        int             `json:"counter"`
	UnixTime       int             `json:"unixTime"`
	Decorations    LogDecorations  `json:"decorations"`
	CalendarTime   string          `json:"calendarTime"`
	HostIdentifier string          `json:"hostIdentifier"`
}

// LogStatusData to be used processing status logs from nodes
type LogStatusData struct {
	Line           string         `json:"line"`
	Message        string         `json:"message"`
	Version        string         `json:"version"`
	Filename       string         `json:"filename"`
	Severity       string         `json:"severity"`
	UnixTime       string         `json:"unixTime"`
	Decorations    LogDecorations `json:"decorations"`
	CalendarTime   string         `json:"calendarTime"`
	HostIdentifier string         `json:"hostIdentifier"`
}

// LogGenericData to parse both status and result logs
type LogGenericData struct {
	HostIdentifier string         `json:"hostIdentifier"`
	Decorations    LogDecorations `json:"decorations"`
	Version        string         `json:"version"`
}

// QueryReadRequest received to get on-demand queries
type QueryReadRequest GenericRequest

// QueryReadQueries to hold the on-demand queries
type QueryReadQueries map[string]string

// QueryReadResponse for on-demand queries from nodes
type QueryReadResponse struct {
	Queries     queries.QueryReadQueries `json:"queries"`
	NodeInvalid bool                     `json:"node_invalid"`
}

// QueryWriteQueries to hold the on-demand queries results
type QueryWriteQueries map[string]json.RawMessage

// QueryWriteStatuses to hold the on-demand queries statuses
type QueryWriteStatuses map[string]int

// QueryWriteRequest to receive on-demand queries results
type QueryWriteRequest struct {
	Queries  QueryWriteQueries  `json:"queries"`
	Statuses QueryWriteStatuses `json:"statuses"`
	NodeKey  string             `json:"node_key"`
}

// QueryWriteResponse for on-demand queries results from nodes
type QueryWriteResponse GenericResponse

// QueryWriteData to store result of on-demand queries
type QueryWriteData struct {
	Name   string          `json:"name"`
	Result json.RawMessage `json:"result"`
	Status int             `json:"status"`
}

// OsqueryTable to show tables to query
type OsqueryTable struct {
	Name      string   `json:"name"`
	URL       string   `json:"url"`
	Platforms []string `json:"platforms"`
}

// LoginTemplateData for passing data to the login template
type LoginTemplateData struct {
	Title string
}

// TableTemplateData for passing data to the table template
type TableTemplateData struct {
	Title         string
	Selector      string
	SelectorName  string
	Target        string
	ContextStats  nodes.StatsData
	PlatformStats nodes.StatsData
}

// ConfTemplateData for passing data to the conf template
type ConfTemplateData struct {
	Title              string
	Context            string
	ConfigurationBlob  string
	ConfigurationHash  string
	QuickAddShell      string
	QuickAddPowershell string
	ContextStats       nodes.StatsData
	PlatformStats      nodes.StatsData
}

// QueryRunTemplateData for passing data to the query template
type QueryRunTemplateData struct {
	Title         string
	ContextStats  nodes.StatsData
	PlatformStats nodes.StatsData
	UUIDs         []string
	Hosts         []string
	Tables        []OsqueryTable
	TablesVersion string
}

// QueryTableTemplateData for passing data to the query template
type QueryTableTemplateData struct {
	Title         string
	ContextStats  nodes.StatsData
	PlatformStats nodes.StatsData
	Target        string
	Queries       []DistributedQuery
}

// QueryLogsTemplateData for passing data to the query template
type QueryLogsTemplateData struct {
	Title         string
	ContextStats  nodes.StatsData
	PlatformStats nodes.StatsData
	Query         DistributedQuery
	QueryTargets  []DistributedQueryTarget
}

// LocationData to hold all location related data, when enabled
type LocationData struct {
	GoogleMapsURL string
	LastLocation  nodes.GeoLocationIPAddress
}

// NodeTemplateData for passing data to the query template
type NodeTemplateData struct {
	Title         string
	PostgresLogs  bool
	Node          nodes.OsqueryNode
	ContextStats  nodes.StatsData
	PlatformStats nodes.StatsData
	Location      LocationData
	LocationShow  bool
}

// SidebarStats to get all stats
type SidebarStats struct {
	Context  nodes.StatsData `json:"context"`
	Platform nodes.StatsData `json:"platform"`
}

// LoginRequest to receive login credentials
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LogoutRequest to receive logout requests
type LogoutRequest struct {
	CSRFToken string `json:"csrftoken"`
}

// DistributedQueryRequest to receive query requests
type DistributedQueryRequest struct {
	CSRFToken string   `json:"csrftoken"`
	Context   string   `json:"context"`
	Platform  string   `json:"platform"`
	UUIDs     []string `json:"uuid_list"`
	Hosts     []string `json:"host_list"`
	Query     string   `json:"query"`
	Repeat    int      `json:"repeat"`
}

// DistributedQueryActionRequest to receive query requests
type DistributedQueryActionRequest struct {
	CSRFToken string   `json:"csrftoken"`
	Names     []string `json:"names"`
	Action    string   `json:"action"`
}

// NodeActionRequest to receive node action requests
type NodeActionRequest struct {
	CSRFToken string `json:"csrftoken"`
	Action    string `json:"action"`
}

// NodeMultiActionRequest to receive node action requests
type NodeMultiActionRequest struct {
	CSRFToken string   `json:"csrftoken"`
	Action    string   `json:"action"`
	UUIDs     []string `json:"uuids"`
}

// AdminResponse to be returned to requests
type AdminResponse struct {
	Message string `json:"message"`
}
