package main

import "github.com/jinzhu/gorm"

// DBConf to hold all backend configuration values
type DBConf struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// TLSConf to hold all TLS configuration values
type TLSConf struct {
	Listener  string                `json:"listener"`
	Port      string                `json:"port"`
	Host      string                `json:"host"`
	Auth      string                `json:"auth"`
	DebugHTTP bool                  `json:"debughttp"`
	Contexts  map[string]TLSContext `json:"contexts"`
}

// TLSContext to hold each context where machines will be enrolled
type TLSContext map[string]string

// ConfigurationOsctrl to hold all configuration
type ConfigurationOsctrl struct {
	gorm.Model
}

// _TLSContext
type _TLSContext struct {
	gorm.Model
	Name                 string
	Secret               string
	SecretMD5            string
	Flags                string
	OsqueryConfiguration string
	EnrollPath           string
	LogPath              string
	ConfigPath           string
	QueryReadPath        string
	QueryWritePath       string
}
