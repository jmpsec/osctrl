package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v2"
)

// ConfigFilePath returns the YAML file this service was configured from, or
// an empty string when it was configured by flags and environment variables
// instead. ServiceConfigFile always holds the flag default, so it is not on
// its own evidence that a file is in use.
func (p *ServiceParameters) ConfigFilePath() string {
	if !p.ConfigFlag {
		return ""
	}
	return p.ServiceConfigFile
}

// Helper to generate an example TLS configuration file
func GenerateTLSConfigFile(path string, cfg *ServiceParameters, overwrite bool) error {
	cfgTLS := TLSConfiguration{
		Version:         ConfigVersion,
		Service:         *cfg.Service,
		DB:              *cfg.DB,
		Redis:           *cfg.Redis,
		BatchWriter:     cfg.BatchWriter,
		Osquery:         cfg.Osquery,
		ConfigEndpoints: cfg.ConfigEndpoints,
		Osctrld:         cfg.Osctrld,
		Metrics:         cfg.Metrics,
		TLS:             cfg.TLS,
		Logger:          cfg.Logger,
		Carver:          cfg.Carver,
		Debug:           cfg.Debug,
		RateLimits:      cfg.RateLimits,
	}
	return GenerateGenericConfigFile(path, cfgTLS, overwrite)
}

// Helper to generate an example API configuration file
func GenerateAPIConfigFile(path string, cfg *ServiceParameters, overwrite bool) error {
	cfgAPI := APIConfiguration{
		Version:    ConfigVersion,
		Service:    *cfg.Service,
		DB:         *cfg.DB,
		Redis:      *cfg.Redis,
		Osquery:    cfg.Osquery,
		SAML:       cfg.SAML,
		OIDC:       cfg.OIDC,
		JWT:        cfg.JWT,
		TLS:        cfg.TLS,
		Logger:     cfg.Logger,
		Carver:     cfg.Carver,
		Debug:      cfg.Debug,
		MCP:        cfg.MCP,
		RateLimits: cfg.RateLimits,
	}
	return GenerateGenericConfigFile(path, cfgAPI, overwrite)
}

// Helper to generate an example configuration file
func GenerateGenericConfigFile(path string, cfg any, overwrite bool) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal configuration: %w", err)
	}
	if path == "" {
		return fmt.Errorf("output path cannot be empty")
	}
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}
	if !overwrite {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("file %s already exists (use --force to overwrite)", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("failed to check if %s exists: %w", path, err)
		}
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("failed to write configuration to %s: %w", path, err)
	}
	return nil
}
