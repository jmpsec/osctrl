package main

import "github.com/jmpsec/osctrl/pkg/config"

// Helper to compose paths for API
func _apiPath(target string) string {
	return apiPrefixPath + apiVersionPath + target
}

// Helper to convert YAML settings loaded from file to settings
func loadedYAMLToServiceParams(yml config.APIConfiguration, loadedFile string) *config.ServiceParameters {
	return &config.ServiceParameters{
		ConfigFlag:        true,
		ServiceConfigFile: loadedFile,
		Service:           &yml.Service,
		DB:                &yml.DB,
		Redis:             &yml.Redis,
		JWT:               &yml.JWT,
		TLS:               &yml.TLS,
		Debug:             &yml.Debug,
	}
}
