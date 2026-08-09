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
	// Check if service settings for settings refresh is ready
	if !mgr.IsValue(config.ServiceAPI, settings.RefreshSettings, settings.NoEnvironmentID) {
		if err := mgr.NewIntegerValue(config.ServiceAPI, settings.RefreshSettings, int64(defaultRefresh), settings.NoEnvironmentID); err != nil {
			return fmt.Errorf("failed to add %s to settings: %w", settings.RefreshSettings, err)
		}
	}
	// Ensure the inactive_hours setting exists so the API service can
	// correctly classify nodes as active/inactive. We seed it here
	// defensively in case no other service has created it yet.
	if !mgr.IsValue(config.ServiceAPI, settings.InactiveHours, settings.NoEnvironmentID) {
		if err := mgr.NewIntegerValue(config.ServiceAPI, settings.InactiveHours, settings.DefaultInactiveHours, settings.NoEnvironmentID); err != nil {
			return fmt.Errorf("failed to add %s to configuration: %w", settings.InactiveHours, err)
		}
	}
	return nil
}
