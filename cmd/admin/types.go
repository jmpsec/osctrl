package main

import (
	ctx "github.com/javuto/osctrl/context"
	"github.com/javuto/osctrl/nodes"
	"github.com/javuto/osctrl/queries"
)

// JSONConfigurationDB to hold all backend configuration values
type JSONConfigurationDB struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// JSONConfigurationAdmin to hold all Admin configuration values
type JSONConfigurationAdmin struct {
	Listener string `json:"listener"`
	Port     string `json:"port"`
	Host     string `json:"host"`
	Auth     string `json:"auth"`
}

// JSONConfigurationSAML to keep all SAML details for auth
type JSONConfigurationSAML struct {
	CertPath    string `json:"certpath"`
	KeyPath     string `json:"keypath"`
	MetaDataURL string `json:"metadataurl"`
	RootURL     string `json:"rooturl"`
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

// OsqueryTable to show tables to query
type OsqueryTable struct {
	Name      string   `json:"name"`
	URL       string   `json:"url"`
	Platforms []string `json:"platforms"`
	Filter    string
}

// LoginTemplateData for passing data to the login template
type LoginTemplateData struct {
	Title   string
	Project string
}

// SettingsData for passing settings data to templates
type SettingsData struct {
	TLSDebugHTTP   bool
	AdminDebugHTTP bool
}

// TableTemplateData for passing data to the table template
type TableTemplateData struct {
	Title        string
	Selector     string
	SelectorName string
	Target       string
	Contexts     []ctx.TLSContext
	Platforms    []string
	Settings     SettingsData
}

// ConfTemplateData for passing data to the conf template
type ConfTemplateData struct {
	Title                 string
	Context               string
	ConfigurationBlob     string
	ConfigurationHash     string
	QuickAddShell         string
	QuickRemoveShell      string
	QuickAddPowershell    string
	QuickRemovePowershell string
	Contexts              []ctx.TLSContext
	Platforms             []string
	Settings              SettingsData
}

// QueryRunTemplateData for passing data to the query template
type QueryRunTemplateData struct {
	Title         string
	Contexts      []ctx.TLSContext
	Platforms     []string
	UUIDs         []string
	Hosts         []string
	Tables        []OsqueryTable
	TablesVersion string
	Settings      SettingsData
}

// QueryTableTemplateData for passing data to the query template
type QueryTableTemplateData struct {
	Title     string
	Contexts  []ctx.TLSContext
	Platforms []string
	Target    string
	Queries   []queries.DistributedQuery
	Settings  SettingsData
}

// QueryLogsTemplateData for passing data to the query template
type QueryLogsTemplateData struct {
	Title        string
	Contexts     []ctx.TLSContext
	Platforms    []string
	Query        queries.DistributedQuery
	QueryTargets []queries.DistributedQueryTarget
	Settings     SettingsData
}

// LocationData to hold all location related data, when enabled
type LocationData struct {
	GoogleMapsURL string
	LastLocation  nodes.GeoLocationIPAddress
}

// NodeTemplateData for passing data to the query template
type NodeTemplateData struct {
	Title        string
	PostgresLogs bool
	Node         nodes.OsqueryNode
	Contexts     []ctx.TLSContext
	Platforms    []string
	Location     LocationData
	LocationShow bool
	Settings     SettingsData
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

// SettingsRequest to receive changes to settings
type SettingsRequest struct {
	CSRFToken string `json:"csrftoken"`
	Service   string `json:"service"`
	DebugHTTP bool   `json:"debughttp"`
}

// ConfigurationRequest to receive changes to configuration
type ConfigurationRequest struct {
	CSRFToken        string `json:"csrftoken"`
	ConfigurationB64 string `json:"configuration"`
}

// AdminResponse to be returned to requests
type AdminResponse struct {
	Message string `json:"message"`
}
