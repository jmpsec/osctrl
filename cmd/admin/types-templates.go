package main

import (
	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
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
	Level          string
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
	Level          string
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
	Level                 string
	EnvName               string
	EnrollExpiry          string
	EnrollExpired         bool
	RemoveExpiry          string
	RemoveExpired         bool
	QuickAddShell         string
	QuickRemoveShell      string
	QuickAddPowershell    string
	QuickRemovePowershell string
	Secret                string
	Flags                 string
	Certificate           string
	Environments          []environments.TLSEnvironment
	Platforms             []string
	TLSDebug              bool
	AdminDebug            bool
	AdminDebugHTTP        bool
}

// QueryRunTemplateData for passing data to the query run template
type QueryRunTemplateData struct {
	Title          string
	Username       string
	CSRFToken      string
	Level          string
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

// CarvesRunTemplateData for passing data to the carves run template
type CarvesRunTemplateData QueryRunTemplateData

// GenericTableTemplateData for passing data to a table template
type GenericTableTemplateData struct {
	Title          string
	Username       string
	CSRFToken      string
	Level          string
	Environments   []environments.TLSEnvironment
	Platforms      []string
	Target         string
	TLSDebug       bool
	AdminDebug     bool
	AdminDebugHTTP bool
}

// QueryTableTemplateData for passing data to the query template
type QueryTableTemplateData GenericTableTemplateData

// CarvesTableTemplateData for passing data to the carves template
type CarvesTableTemplateData GenericTableTemplateData

// CarvesDetailsTemplateData for passing data to the carves details
type CarvesDetailsTemplateData struct {
	Title          string
	Username       string
	CSRFToken      string
	Level          string
	Environments   []environments.TLSEnvironment
	Platforms      []string
	Query          queries.DistributedQuery
	QueryTargets   []queries.DistributedQueryTarget
	Carves         []carves.CarvedFile
	CarveBlocks    map[string][]carves.CarvedBlock
	TLSDebug       bool
	AdminDebug     bool
	AdminDebugHTTP bool
}

// QueryLogsTemplateData for passing data to the query template
type QueryLogsTemplateData struct {
	Title          string
	Username       string
	CSRFToken      string
	Level          string
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
	Level          string
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
	Level           string
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
	Level          string
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
	Level          string
	Logs           string
	Node           nodes.OsqueryNode
	Environments   []environments.TLSEnvironment
	Platforms      []string
	TLSDebug       bool
	AdminDebug     bool
	AdminDebugHTTP bool
}
