package main

// JSONConfigurationBackend to hold all backend configuration values
type JSONConfigurationBackend struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
}
