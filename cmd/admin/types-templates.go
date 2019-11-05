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

// TemplateMetadata to pass some metadata to templates
type TemplateMetadata struct {
	Username       string
	Level          string
	Service        string
	Version        string
	TLSDebug       bool
	AdminDebug     bool
	AdminDebugHTTP bool
	CSRFToken      string
}

// TableTemplateData for passing data to the table template
type TableTemplateData struct {
	Title        string
	Selector     string
	SelectorName string
	Target       string
	Environments []environments.TLSEnvironment
	Platforms    []string
	Metadata     TemplateMetadata
}

// ConfTemplateData for passing data to the conf template
type ConfTemplateData struct {
	Title        string
	Environment  environments.TLSEnvironment
	Environments []environments.TLSEnvironment
	Platforms    []string
	Metadata     TemplateMetadata
}

// EnrollTemplateData for passing data to the conf template
type EnrollTemplateData struct {
	Title                 string
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
	Metadata              TemplateMetadata
}

// QueryRunTemplateData for passing data to the query run template
type QueryRunTemplateData struct {
	Title         string
	Environments  []environments.TLSEnvironment
	Platforms     []string
	UUIDs         []string
	Hosts         []string
	Tables        []OsqueryTable
	TablesVersion string
	Metadata      TemplateMetadata
}

// CarvesRunTemplateData for passing data to the carves run template
type CarvesRunTemplateData QueryRunTemplateData

// GenericTableTemplateData for passing data to a table template
type GenericTableTemplateData struct {
	Title        string
	Environments []environments.TLSEnvironment
	Platforms    []string
	Target       string
	Metadata     TemplateMetadata
}

// QueryTableTemplateData for passing data to the query template
type QueryTableTemplateData GenericTableTemplateData

// CarvesTableTemplateData for passing data to the carves template
type CarvesTableTemplateData GenericTableTemplateData

// CarvesDetailsTemplateData for passing data to the carves details
type CarvesDetailsTemplateData struct {
	Title        string
	Environments []environments.TLSEnvironment
	Platforms    []string
	Query        queries.DistributedQuery
	QueryTargets []queries.DistributedQueryTarget
	Carves       []carves.CarvedFile
	CarveBlocks  map[string][]carves.CarvedBlock
	Metadata     TemplateMetadata
}

// QueryLogsTemplateData for passing data to the query template
type QueryLogsTemplateData struct {
	Title        string
	Environments []environments.TLSEnvironment
	Platforms    []string
	Query        queries.DistributedQuery
	ResultsLink  string
	QueryTargets []queries.DistributedQueryTarget
	Metadata     TemplateMetadata
}

// EnvironmentsTemplateData for passing data to the environments template
type EnvironmentsTemplateData struct {
	Title        string
	Environments []environments.TLSEnvironment
	Platforms    []string
	Metadata     TemplateMetadata
}

// SettingsTemplateData for passing data to the settings template
type SettingsTemplateData struct {
	Title           string
	Service         string
	Environments    []environments.TLSEnvironment
	Platforms       []string
	CurrentSettings []settings.SettingValue
	ServiceConfig   types.JSONConfigurationService
	Metadata        TemplateMetadata
}

// UsersTemplateData for passing data to the settings template
type UsersTemplateData struct {
	Title        string
	Environments []environments.TLSEnvironment
	Platforms    []string
	CurrentUsers []users.AdminUser
	Metadata     TemplateMetadata
}

// NodeTemplateData for passing data to the query template
type NodeTemplateData struct {
	Title        string
	Logs         string
	Node         nodes.OsqueryNode
	Environments []environments.TLSEnvironment
	Platforms    []string
	Metadata     TemplateMetadata
}
