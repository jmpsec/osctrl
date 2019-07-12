package main

import (
	"github.com/javuto/osctrl/pkg/environments"
	"github.com/javuto/osctrl/pkg/nodes"
	"github.com/javuto/osctrl/pkg/queries"
	"github.com/javuto/osctrl/pkg/settings"
	"github.com/javuto/osctrl/pkg/types"
	"github.com/javuto/osctrl/pkg/users"
)

// LoginTemplateData for passing data to the login template
type LoginTemplateData struct {
	Title   string
	Project string
}

// TableTemplateData for passing data to the table template
type TableTemplateData struct {
	Title          string
	Username       string
	CSRFToken      string
	Selector       string
	SelectorName   string
	Target         string
	Environments   []environments.TLSEnvironment
	Platforms      []string
	TLSDebug       bool
	AdminDebug     bool
	AdminDebugHTTP bool
}

// ConfTemplateData for passing data to the conf template
type ConfTemplateData struct {
	Title          string
	Username       string
	CSRFToken      string
	Environment    environments.TLSEnvironment
	Environments   []environments.TLSEnvironment
	Platforms      []string
	TLSDebug       bool
	AdminDebug     bool
	AdminDebugHTTP bool
}

// EnrollTemplateData for passing data to the conf template
type EnrollTemplateData struct {
	Title                 string
	Username              string
	CSRFToken             string
	EnvName               string
	EnrollExpiry          string
	EnrollExpired         bool
	RemoveExpiry          string
	RemoveExpired         bool
	QuickAddShell         string
	QuickRemoveShell      string
	QuickAddPowershell    string
	QuickRemovePowershell string
	Environments          []environments.TLSEnvironment
	Platforms             []string
	TLSDebug              bool
	AdminDebug            bool
	AdminDebugHTTP        bool
}

// QueryRunTemplateData for passing data to the query template
type QueryRunTemplateData struct {
	Title          string
	Username       string
	CSRFToken      string
	Environments   []environments.TLSEnvironment
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
	Username       string
	CSRFToken      string
	Environments   []environments.TLSEnvironment
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
	Username       string
	CSRFToken      string
	Environments   []environments.TLSEnvironment
	Platforms      []string
	Query          queries.DistributedQuery
	QueryTargets   []queries.DistributedQueryTarget
	TLSDebug       bool
	AdminDebug     bool
	AdminDebugHTTP bool
}

// EnvironmentsTemplateData for passing data to the environments template
type EnvironmentsTemplateData struct {
	Title          string
	Username       string
	CSRFToken      string
	Environments   []environments.TLSEnvironment
	Platforms      []string
	TLSDebug       bool
	AdminDebug     bool
	AdminDebugHTTP bool
}

// SettingsTemplateData for passing data to the settings template
type SettingsTemplateData struct {
	Title           string
	Username        string
	CSRFToken       string
	Service         string
	Environments    []environments.TLSEnvironment
	Platforms       []string
	CurrentSettings []settings.SettingValue
	ServiceConfig   types.JSONConfigurationService
	TLSDebug        bool
	AdminDebug      bool
	AdminDebugHTTP  bool
}

// UsersTemplateData for passing data to the settings template
type UsersTemplateData struct {
	Title          string
	Username       string
	CSRFToken      string
	Environments   []environments.TLSEnvironment
	Platforms      []string
	CurrentUsers   []users.AdminUser
	TLSDebug       bool
	AdminDebug     bool
	AdminDebugHTTP bool
}

// NodeTemplateData for passing data to the query template
type NodeTemplateData struct {
	Title          string
	Username       string
	CSRFToken      string
	Logs           string
	Node           nodes.OsqueryNode
	Environments   []environments.TLSEnvironment
	Platforms      []string
	TLSDebug       bool
	AdminDebug     bool
	AdminDebugHTTP bool
}
