package main


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
