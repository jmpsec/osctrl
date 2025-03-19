package main

import (
	"fmt"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/rs/zerolog/log"
)

// Function to load all settings for the service
func loadingSettings(mgr *settings.Settings) error {
	// Check if service settings for debug service is ready
	if mgr.DebugService(config.ServiceAPI) {
		log.Debug().Msg("DebugService: Initializing settings")
	}
	// Check if service settings for debug service is ready
	if !mgr.IsValue(config.ServiceAPI, settings.DebugService, settings.NoEnvironmentID) {
		if err := mgr.NewBooleanValue(config.ServiceAPI, settings.DebugService, false, settings.NoEnvironmentID); err != nil {
			return fmt.Errorf("Failed to add %s to settings: %w", settings.DebugService, err)
		}
	}
	// Check if service settings for debug HTTP is ready
	if !mgr.IsValue(config.ServiceAPI, settings.DebugHTTP, settings.NoEnvironmentID) {
		if err := mgr.NewBooleanValue(config.ServiceAPI, settings.DebugHTTP, false, settings.NoEnvironmentID); err != nil {
			return fmt.Errorf("Failed to add %s to settings: %w", settings.DebugHTTP, err)
		}
	}
	// Check if service settings for metrics is ready, initialize if so
	if !mgr.IsValue(config.ServiceAPI, settings.ServiceMetrics, settings.NoEnvironmentID) {
		if err := mgr.NewBooleanValue(config.ServiceAPI, settings.ServiceMetrics, false, settings.NoEnvironmentID); err != nil {
			return fmt.Errorf("Failed to add %s to settings: %w", settings.ServiceMetrics, err)
		}
	}
	// Check if service settings for environments refresh is ready
	if !mgr.IsValue(config.ServiceAPI, settings.RefreshEnvs, settings.NoEnvironmentID) {
		if err := mgr.NewIntegerValue(config.ServiceAPI, settings.RefreshEnvs, int64(defaultRefresh), settings.NoEnvironmentID); err != nil {
			return fmt.Errorf("Failed to add %s to settings: %w", settings.RefreshEnvs, err)
		}
	}
	// Check if service settings for settings refresh is ready
	if !mgr.IsValue(config.ServiceAPI, settings.RefreshSettings, settings.NoEnvironmentID) {
		if err := mgr.NewIntegerValue(config.ServiceAPI, settings.RefreshSettings, int64(defaultRefresh), settings.NoEnvironmentID); err != nil {
			return fmt.Errorf("Failed to add %s to settings: %w", settings.RefreshSettings, err)
		}
	}
	// Write JSON config to settings
	if err := mgr.SetAPIJSON(apiConfig, settings.NoEnvironmentID); err != nil {
		return fmt.Errorf("Failed to add JSON values to configuration: %w", err)
	}
	return nil
}
