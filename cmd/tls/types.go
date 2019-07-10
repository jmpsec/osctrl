package main

// JSONConfigurationService to hold all service configuration values
type JSONConfigurationService struct {
	Listener string `json:"listener"`
	Port     string `json:"port"`
	Host     string `json:"host"`
	Auth     string `json:"auth"`
	Logging  string `json:"logging"`
}
