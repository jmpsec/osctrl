package main

import (
	"fmt"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/rs/zerolog/log"
)

// Function to load all settings for the service
func loadingSettings(mgr *settings.Settings, cfg config.JSONConfigurationService) error {
	// Check if service settings for debug service is ready
	log.Debug().Msg("Initializing settings")
	// Check if service settings for sessions cleanup is ready
	if !mgr.IsValue(config.ServiceAdmin, settings.CleanupSessions, settings.NoEnvironmentID) {
		if err := mgr.NewIntegerValue(config.ServiceAdmin, settings.CleanupSessions, int64(defaultRefresh), settings.NoEnvironmentID); err != nil {
			return fmt.Errorf("Failed to add %s to configuration: %w", settings.CleanupSessions, err)
		}
	}
	// Check if service settings for queries/carves cleanup is ready
	if !mgr.IsValue(config.ServiceAdmin, settings.CleanupExpired, settings.NoEnvironmentID) {
		if err := mgr.NewIntegerValue(config.ServiceAdmin, settings.CleanupExpired, int64(defaultExpiration), settings.NoEnvironmentID); err != nil {
			return fmt.Errorf("Failed to add %s to configuration: %w", settings.CleanupExpired, err)
		}
	}
	// Check if service settings for node inactive hours is ready
	if !mgr.IsValue(config.ServiceAdmin, settings.InactiveHours, settings.NoEnvironmentID) {
		if err := mgr.NewIntegerValue(config.ServiceAdmin, settings.InactiveHours, int64(defaultInactive), settings.NoEnvironmentID); err != nil {
			return fmt.Errorf("Failed to add %s to configuration: %w", settings.InactiveHours, err)
		}
	}
	// Check if service settings for display dashboard is ready
	if !mgr.IsValue(config.ServiceAdmin, settings.NodeDashboard, settings.NoEnvironmentID) {
		if err := mgr.NewBooleanValue(config.ServiceAdmin, settings.NodeDashboard, false, settings.NoEnvironmentID); err != nil {
			return fmt.Errorf("Failed to add %s to settings: %w", settings.NodeDashboard, err)
		}
	}
	// Write JSON config to settings
	if err := mgr.SetAdminJSON(cfg, settings.NoEnvironmentID); err != nil {
		return fmt.Errorf("Failed to add JSON values to configuration: %w", err)
	}
	return nil
}
