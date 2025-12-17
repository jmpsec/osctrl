package main

import (
	"fmt"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/rs/zerolog/log"
)

// Function to load all settings for the service
func loadingSettings(mgr *settings.Settings, cfg *config.ServiceParameters) error {
	log.Debug().Msg("Initializing settings")
	// Check if service settings for metrics is ready, initialize if so
	if !mgr.IsValue(config.ServiceAPI, settings.ServiceMetrics, settings.NoEnvironmentID) {
		if err := mgr.NewBooleanValue(config.ServiceAPI, settings.ServiceMetrics, false, settings.NoEnvironmentID); err != nil {
			return fmt.Errorf("failed to add %s to settings: %w", settings.ServiceMetrics, err)
		}
	}
	// Check if service settings for environments refresh is ready
	if !mgr.IsValue(config.ServiceAPI, settings.RefreshEnvs, settings.NoEnvironmentID) {
		if err := mgr.NewIntegerValue(config.ServiceAPI, settings.RefreshEnvs, int64(defaultRefresh), settings.NoEnvironmentID); err != nil {
			return fmt.Errorf("failed to add %s to settings: %w", settings.RefreshEnvs, err)
		}
	}
	// Check if service settings for settings refresh is ready
	if !mgr.IsValue(config.ServiceAPI, settings.RefreshSettings, settings.NoEnvironmentID) {
		if err := mgr.NewIntegerValue(config.ServiceAPI, settings.RefreshSettings, int64(defaultRefresh), settings.NoEnvironmentID); err != nil {
			return fmt.Errorf("failed to add %s to settings: %w", settings.RefreshSettings, err)
		}
	}
	// Write JSON config to settings
	if err := mgr.SetAPIJSON(cfg, settings.NoEnvironmentID); err != nil {
		return fmt.Errorf("failed to add JSON values to configuration: %w", err)
	}
	return nil
}
