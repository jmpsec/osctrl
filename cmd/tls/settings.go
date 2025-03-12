package main

import (
	"fmt"

	"github.com/jmpsec/osctrl/pkg/settings"
)

// Function to load all settings for the service
func loadingSettings(mgr *settings.Settings) error {
	// Check if service settings for debug service is ready
	if !mgr.IsValue(settings.ServiceTLS, settings.DebugService, settings.NoEnvironmentID) {
		if err := mgr.NewBooleanValue(settings.ServiceTLS, settings.DebugService, false, settings.NoEnvironmentID); err != nil {
			return fmt.Errorf("Failed to add %s to configuration: %v", settings.DebugService, err)
		}
	}
	// Check if service settings for accelerated seconds is ready
	if !mgr.IsValue(settings.ServiceTLS, settings.AcceleratedSeconds, settings.NoEnvironmentID) {
		if err := mgr.NewIntegerValue(settings.ServiceTLS, settings.AcceleratedSeconds, int64(defaultAccelerate), settings.NoEnvironmentID); err != nil {
			return fmt.Errorf("Failed to add %s to configuration: %v", settings.AcceleratedSeconds, err)
		}
	}
	// Check if service settings for environments refresh is ready
	if !mgr.IsValue(settings.ServiceTLS, settings.RefreshEnvs, settings.NoEnvironmentID) {
		if err := mgr.NewIntegerValue(settings.ServiceTLS, settings.RefreshEnvs, int64(defaultRefresh), settings.NoEnvironmentID); err != nil {
			return fmt.Errorf("Failed to add %s to configuration: %v", settings.RefreshEnvs, err)
		}
	}
	// Check if service settings for enroll/remove oneliner links is ready
	if !mgr.IsValue(settings.ServiceTLS, settings.OnelinerExpiration, settings.NoEnvironmentID) {
		if err := mgr.NewBooleanValue(settings.ServiceTLS, settings.OnelinerExpiration, defaultOnelinerExpiration, settings.NoEnvironmentID); err != nil {
			return fmt.Errorf("Failed to add %s to configuration: %v", settings.OnelinerExpiration, err)
		}
	}
	// Write JSON config to settings
	if err := mgr.SetTLSJSON(tlsConfig, settings.NoEnvironmentID); err != nil {
		return fmt.Errorf("Failed to add JSON values to configuration: %v", err)
	}
	return nil
}
