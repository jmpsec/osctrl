package main

import (
	"github.com/jmpsec/osctrl/pkg/config"
)

// Helper to convert YAML settings loaded from file to settings
func loadedYAMLToServiceParams(yml config.TLSConfiguration, loadedFile string) *config.ServiceParameters {
	return &config.ServiceParameters{
		ConfigFlag:        true,
		ServiceConfigFile: loadedFile,
		Service:           &yml.Service,
		DB:                &yml.DB,
		BatchWriter:       &yml.BatchWriter,
		Redis:             &yml.Redis,
		Osquery:           &yml.Osquery,
		ConfigEndpoints:   &yml.ConfigEndpoints,
		Osctrld:           &yml.Osctrld,
		Metrics:           &yml.Metrics,
		TLS:               &yml.TLS,
		Logger:            &yml.Logger,
		Carver:            &yml.Carver,
		Debug:             &yml.Debug,
	}
}
