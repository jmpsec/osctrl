package main

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
	Listener string `json:"listener"`
	Port     string `json:"port"`
	Host     string `json:"host"`
	Auth     string `json:"auth"`
}

// AdminConf to hold all Admin configuration values
type AdminConf struct {
	Listener string `json:"listener"`
	Port     string `json:"port"`
	Host     string `json:"host"`
	Auth     string `json:"auth"`
}
