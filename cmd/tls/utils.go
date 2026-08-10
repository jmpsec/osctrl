package main

import (
	"github.com/jmpsec/osctrl/pkg/config"
)

// Helper to convert YAML settings loaded from file to settings. Optional
// sections are only set when present in the YAML (non-nil); missing sections
// stay nil in ServiceParameters so Seed/Resolve can fill them from the DB.
func loadedYAMLToServiceParams(yml config.TLSConfiguration, loadedFile string) *config.ServiceParameters {
	params := &config.ServiceParameters{
		ConfigFlag:        true,
		ServiceConfigFile: loadedFile,
		Service:           &yml.Service,
		DB:                &yml.DB,
		Redis:             &yml.Redis,
	}
	// Optional sections — only set when the YAML provided them.
	if yml.BatchWriter != nil {
		params.BatchWriter = yml.BatchWriter
	}
	if yml.Osquery != nil {
		params.Osquery = yml.Osquery
	}
	if yml.ConfigEndpoints != nil {
		params.ConfigEndpoints = yml.ConfigEndpoints
	}
	if yml.Osctrld != nil {
		params.Osctrld = yml.Osctrld
	}
	if yml.Metrics != nil {
		params.Metrics = yml.Metrics
	}
	if yml.TLS != nil {
		params.TLS = yml.TLS
	}
	if yml.Logger != nil {
		params.Logger = yml.Logger
	}
	if yml.Carver != nil {
		params.Carver = yml.Carver
	}
	if yml.Debug != nil {
		params.Debug = yml.Debug
	}
	return params
}
