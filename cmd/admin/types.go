package main

import (
	ctx "github.com/javuto/osctrl/pkg/context"
	"github.com/javuto/osctrl/pkg/nodes"
	"github.com/javuto/osctrl/pkg/queries"
	"github.com/javuto/osctrl/pkg/settings"
	"github.com/javuto/osctrl/pkg/users"
)

// JSONConfigurationDB to hold all backend configuration values
type JSONConfigurationDB struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// JSONConfigurationService to hold all service configuration values
type JSONConfigurationService struct {
	Listener   string                   `json:"listener"`
	Port       string                   `json:"port"`
	Host       string                   `json:"host"`
	Auth       string                   `json:"auth"`
	Logging    string                   `json:"logging"`
	LoggingCfg LoggingConfigurationData `json:"loggingcfg"`
}

// JSONConfigurationUsers to hold all Admin users
type JSONConfigurationUsers struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Admin    bool   `json:"admin"`
}

// JSONConfigurationSAML to keep all SAML details for auth
type JSONConfigurationSAML struct {
	CertPath    string `json:"certpath"`
	KeyPath     string `json:"keypath"`
	MetaDataURL string `json:"metadataurl"`
	RootURL     string `json:"rooturl"`
}

// LoggingConfigurationData to keep a map with details for each logging entry
type LoggingConfigurationData map[string]string

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

// TableTemplateData for passing data to the table template
type TableTemplateData struct {
	Title          string
	Selector       string
	SelectorName   string
	Target         string
	Contexts       []ctx.TLSContext
	Platforms      []string
	TLSDebug       bool
	AdminDebug     bool
	AdminDebugHTTP bool
}

// ConfTemplateData for passing data to the conf template
type ConfTemplateData struct {
	Title          string
	Context        ctx.TLSContext
	Contexts       []ctx.TLSContext
	Platforms      []string
	TLSDebug       bool
	AdminDebug     bool
	AdminDebugHTTP bool
}

// EnrollTemplateData for passing data to the conf template
type EnrollTemplateData struct {
	Title                 string
	Context               string
	EnrollExpiry          string
	EnrollExpired         bool
	RemoveExpiry          string
	RemoveExpired         bool
	QuickAddShell         string
	QuickRemoveShell      string
	QuickAddPowershell    string
	QuickRemovePowershell string
	Contexts              []ctx.TLSContext
	Platforms             []string
	TLSDebug              bool
	AdminDebug            bool
	AdminDebugHTTP        bool
}

// QueryRunTemplateData for passing data to the query template
type QueryRunTemplateData struct {
	Title          string
	Contexts       []ctx.TLSContext
	Platforms      []string
	UUIDs          []string
	Hosts          []string
	Tables         []OsqueryTable
	TablesVersion  string
	TLSDebug       bool
	AdminDebug     bool
	AdminDebugHTTP bool
}

// QueryTableTemplateData for passing data to the query template
type QueryTableTemplateData struct {
	Title          string
	Contexts       []ctx.TLSContext
	Platforms      []string
	Target         string
	Queries        []queries.DistributedQuery
	TLSDebug       bool
	AdminDebug     bool
	AdminDebugHTTP bool
}

// QueryLogsTemplateData for passing data to the query template
type QueryLogsTemplateData struct {
	Title          string
	Contexts       []ctx.TLSContext
	Platforms      []string
	Query          queries.DistributedQuery
	QueryTargets   []queries.DistributedQueryTarget
	TLSDebug       bool
	AdminDebug     bool
	AdminDebugHTTP bool
}

// ContextsTemplateData for passing data to the contexts template
type ContextsTemplateData struct {
	Title          string
	Contexts       []ctx.TLSContext
	Platforms      []string
	TLSDebug       bool
	AdminDebug     bool
	AdminDebugHTTP bool
}

// SettingsTemplateData for passing data to the settings template
type SettingsTemplateData struct {
	Title           string
	Service         string
	Contexts        []ctx.TLSContext
	Platforms       []string
	CurrentSettings []settings.SettingValue
	TLSDebug        bool
	AdminDebug      bool
	AdminDebugHTTP  bool
}

// UsersTemplateData for passing data to the settings template
type UsersTemplateData struct {
	Title          string
	Contexts       []ctx.TLSContext
	Platforms      []string
	CurrentUsers   []users.AdminUser
	TLSDebug       bool
	AdminDebug     bool
	AdminDebugHTTP bool
}

// NodeTemplateData for passing data to the query template
type NodeTemplateData struct {
	Title          string
	Logs           string
	Node           nodes.OsqueryNode
	Contexts       []ctx.TLSContext
	Platforms      []string
	TLSDebug       bool
	AdminDebug     bool
	AdminDebugHTTP bool
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
	Action    string `json:"action"`
	Boolean   bool   `json:"boolean"`
	Type      string `json:"type"`
	Name      string `json:"name"`
	Value     string `json:"value"`
}

// ConfigurationRequest to receive changes to configuration
type ConfigurationRequest struct {
	CSRFToken        string `json:"csrftoken"`
	ConfigurationB64 string `json:"configuration"`
}

// IntervalsRequest to receive changes to intervals
type IntervalsRequest struct {
	CSRFToken      string `json:"csrftoken"`
	ConfigInterval int    `json:"config"`
	LogInterval    int    `json:"log"`
	QueryInterval  int    `json:"query"`
}

// ExpirationRequest to receive expiration changes to enroll/remove nodes
type ExpirationRequest struct {
	CSRFToken string `json:"csrftoken"`
	Action    string `json:"action"`
	Type      string `json:"type"`
}

// ContextsRequest to receive changes to contexts
type ContextsRequest struct {
	CSRFToken string `json:"csrftoken"`
	Action    string `json:"action"`
	Name      string `json:"name"`
	Hostname  string `json:"hostname"`
	Type      string `json:"type"`
	Icon      string `json:"icon"`
	DebugHTTP bool   `json:"debughttp"`
}

// UsersRequest to receive user action requests
type UsersRequest struct {
	CSRFToken string `json:"csrftoken"`
	Action    string `json:"action"`
	Username  string `json:"username"`
	Fullname  string `json:"fullname"`
	Password  string `json:"password"`
	Admin     bool   `json:"admin"`
}

// AdminResponse to be returned to requests
type AdminResponse struct {
	Message string `json:"message"`
}
