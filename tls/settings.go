package main

import (
	"fmt"

	"github.com/jmpsec/osctrl/metrics"
	"github.com/jmpsec/osctrl/settings"
)

// Function to load metrics for the service
func loadingMetrics(mgr *settings.Settings) (*metrics.Metrics, error) {
	// Check if service settings for metrics is ready, initialize if so
	if !mgr.IsValue(settings.ServiceTLS, settings.ServiceMetrics) {
		if err := mgr.NewBooleanValue(settings.ServiceTLS, settings.ServiceMetrics, false); err != nil {
			return nil, fmt.Errorf("Failed to add %s to configuration: %v", settings.ServiceMetrics, err)
		}
	} else if mgr.ServiceMetrics(settings.ServiceTLS) {
		_mCfg, err := metrics.LoadConfiguration()
		if err != nil {
			if err := mgr.SetBoolean(false, settings.ServiceTLS, settings.ServiceMetrics); err != nil {
				return nil, fmt.Errorf("Failed to disable metrics: %v", err)
			}
			return nil, fmt.Errorf("Failed to initialize metrics: %v", err)
		}
		_m, err := metrics.CreateMetrics(_mCfg.Protocol, _mCfg.Host, _mCfg.Port, serviceName)
		if err != nil {
			if err := mgr.SetBoolean(false, settings.ServiceTLS, settings.ServiceMetrics); err != nil {
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
	if !mgr.IsValue(settings.ServiceTLS, settings.DebugService) {
		if err := mgr.NewBooleanValue(settings.ServiceTLS, settings.DebugService, false); err != nil {
			return fmt.Errorf("Failed to add %s to configuration: %v", settings.DebugService, err)
		}
	}
	// Check if service settings for accelerated seconds is ready
	if !mgr.IsValue(settings.ServiceTLS, settings.AcceleratedSeconds) {
		if err := mgr.NewIntegerValue(settings.ServiceTLS, settings.AcceleratedSeconds, int64(defaultAccelerate)); err != nil {
			return fmt.Errorf("Failed to add %s to configuration: %v", settings.AcceleratedSeconds, err)
		}
	}
	// Check if service settings for environments refresh is ready
	if !mgr.IsValue(settings.ServiceTLS, settings.RefreshEnvs) {
		if err := mgr.NewIntegerValue(settings.ServiceTLS, settings.RefreshEnvs, int64(defaultRefresh)); err != nil {
			return fmt.Errorf("Failed to add %s to configuration: %v", settings.RefreshEnvs, err)
		}
	}
	// Check if service settings for settings refresh is ready
	if !mgr.IsValue(settings.ServiceTLS, settings.RefreshSettings) {
		if err := mgr.NewIntegerValue(settings.ServiceTLS, settings.RefreshSettings, int64(defaultRefresh)); err != nil {
			return fmt.Errorf("Failed to add %s to configuration: %v", settings.RefreshSettings, err)
		}
	}
	// Write JSON config to settings
	if err := mgr.SetAllJSON(settings.ServiceTLS, tlsConfig.Listener, tlsConfig.Port, tlsConfig.Host, tlsConfig.Auth, tlsConfig.Logger); err != nil {
		return fmt.Errorf("Failed to add JSON values to configuration: %v", err)
	}

	return nil
}
