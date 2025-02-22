package main

import (
	"fmt"

	"github.com/jmpsec/osctrl/metrics"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/rs/zerolog/log"
)

// Function to load the metrics settings
func loadingMetrics(mgr *settings.Settings) (*metrics.Metrics, error) {
	// Check if service settings for metrics is ready, initialize if so
	if !mgr.IsValue(settings.ServiceAdmin, settings.ServiceMetrics, settings.NoEnvironmentID) {
		if err := mgr.NewBooleanValue(settings.ServiceAdmin, settings.ServiceMetrics, false, settings.NoEnvironmentID); err != nil {
			return nil, fmt.Errorf("Failed to add %s to configuration: %v", settings.ServiceMetrics, err)
		}
	}
	if mgr.ServiceMetrics(settings.ServiceAdmin) {
		_mCfg, err := metrics.LoadConfiguration()
		if err != nil {
			if err := mgr.SetBoolean(false, settings.ServiceAdmin, settings.ServiceMetrics, settings.NoEnvironmentID); err != nil {
				return nil, fmt.Errorf("Failed to disable metrics: %v", err)
			}
			return nil, fmt.Errorf("Failed to initialize metrics: %v", err)
		}
		_m, err := metrics.CreateMetrics(_mCfg.Protocol, _mCfg.Host, _mCfg.Port, serviceName)
		if err != nil {
			if err := mgr.SetBoolean(false, settings.ServiceAdmin, settings.ServiceMetrics, settings.NoEnvironmentID); err != nil {
				return nil, fmt.Errorf("Failed to disable metrics: %v", err)
			}
			return nil, fmt.Errorf("Failed to initialize metrics: %v", err)
		}
		return _m, nil
	}
	return nil, nil
}

// Function to load all settings for the service
func loadingSettings(mgr *settings.Settings) error {
	// Check if service settings for debug service is ready
	if mgr.DebugService(settings.ServiceAdmin) {
		log.Debug().Msg("DebugService: Initializing settings")
	}
	// Check if service settings for debug service is ready
	if !mgr.IsValue(settings.ServiceAdmin, settings.DebugService, settings.NoEnvironmentID) {
		if err := mgr.NewBooleanValue(settings.ServiceAdmin, settings.DebugService, false, settings.NoEnvironmentID); err != nil {
			return fmt.Errorf("Failed to add %s to settings: %v", settings.DebugService, err)
		}
	}
	// Check if service settings for debug HTTP is ready
	if !mgr.IsValue(settings.ServiceAdmin, settings.DebugHTTP, settings.NoEnvironmentID) {
		if err := mgr.NewBooleanValue(settings.ServiceAdmin, settings.DebugHTTP, false, settings.NoEnvironmentID); err != nil {
			return fmt.Errorf("Failed to add %s to settings: %v", settings.DebugHTTP, err)
		}
	}
	// Check if service settings for sessions cleanup is ready
	if !mgr.IsValue(settings.ServiceAdmin, settings.CleanupSessions, settings.NoEnvironmentID) {
		if err := mgr.NewIntegerValue(settings.ServiceAdmin, settings.CleanupSessions, int64(defaultRefresh), settings.NoEnvironmentID); err != nil {
			return fmt.Errorf("Failed to add %s to configuration: %v", settings.CleanupSessions, err)
		}
	}
	// Check if service settings for queries/carves cleanup is ready
	if !mgr.IsValue(settings.ServiceAdmin, settings.CleanupExpired, settings.NoEnvironmentID) {
		if err := mgr.NewIntegerValue(settings.ServiceAdmin, settings.CleanupExpired, int64(defaultExpiration), settings.NoEnvironmentID); err != nil {
			return fmt.Errorf("Failed to add %s to configuration: %v", settings.CleanupExpired, err)
		}
	}
	// Check if service settings for node inactive hours is ready
	if !mgr.IsValue(settings.ServiceAdmin, settings.InactiveHours, settings.NoEnvironmentID) {
		if err := mgr.NewIntegerValue(settings.ServiceAdmin, settings.InactiveHours, int64(defaultInactive), settings.NoEnvironmentID); err != nil {
			return fmt.Errorf("Failed to add %s to configuration: %v", settings.InactiveHours, err)
		}
	}
	// Check if service settings for display dashboard is ready
	if !mgr.IsValue(settings.ServiceAdmin, settings.NodeDashboard, settings.NoEnvironmentID) {
		if err := mgr.NewBooleanValue(settings.ServiceAdmin, settings.NodeDashboard, false, settings.NoEnvironmentID); err != nil {
			return fmt.Errorf("Failed to add %s to settings: %v", settings.NodeDashboard, err)
		}
	}
	// Write JSON config to settings
	if err := mgr.SetAdminJSON(adminConfig, settings.NoEnvironmentID); err != nil {
		return fmt.Errorf("Failed to add JSON values to configuration: %v", err)
	}
	return nil
}
