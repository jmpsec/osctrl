package main

import (
	"fmt"

	"github.com/jmpsec/osctrl/metrics"
	"github.com/jmpsec/osctrl/settings"
)

// Function to load metrics for the service
func loadingMetrics(mgr *settings.Settings) (*metrics.Metrics, error) {
	// Check if service settings for metrics is ready, initialize if so
	if !mgr.IsValue(settings.ServiceTLS, settings.ServiceMetrics, settings.NoEnvironment) {
		if err := mgr.NewBooleanValue(settings.ServiceTLS, settings.ServiceMetrics, false, settings.NoEnvironment); err != nil {
			return nil, fmt.Errorf("Failed to add %s to configuration: %v", settings.ServiceMetrics, err)
		}
	} else if mgr.ServiceMetrics(settings.ServiceTLS) {
		_mCfg, err := metrics.LoadConfiguration()
		if err != nil {
			if err := mgr.SetBoolean(false, settings.ServiceTLS, settings.ServiceMetrics, settings.NoEnvironment); err != nil {
				return nil, fmt.Errorf("Failed to disable metrics: %v", err)
			}
			return nil, fmt.Errorf("Failed to initialize metrics: %v", err)
		}
		_m, err := metrics.CreateMetrics(_mCfg.Protocol, _mCfg.Host, _mCfg.Port, serviceName)
		if err != nil {
			if err := mgr.SetBoolean(false, settings.ServiceTLS, settings.ServiceMetrics, settings.NoEnvironment); err != nil {
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
	if !mgr.IsValue(settings.ServiceTLS, settings.DebugService, settings.NoEnvironment) {
		if err := mgr.NewBooleanValue(settings.ServiceTLS, settings.DebugService, false, settings.NoEnvironment); err != nil {
			return fmt.Errorf("Failed to add %s to configuration: %v", settings.DebugService, err)
		}
	}
	// Check if service settings for accelerated seconds is ready
	if !mgr.IsValue(settings.ServiceTLS, settings.AcceleratedSeconds, settings.NoEnvironment) {
		if err := mgr.NewIntegerValue(settings.ServiceTLS, settings.AcceleratedSeconds, int64(defaultAccelerate), settings.NoEnvironment); err != nil {
			return fmt.Errorf("Failed to add %s to configuration: %v", settings.AcceleratedSeconds, err)
		}
	}
	// Check if service settings for environments refresh is ready
	if !mgr.IsValue(settings.ServiceTLS, settings.RefreshEnvs, settings.NoEnvironment) {
		if err := mgr.NewIntegerValue(settings.ServiceTLS, settings.RefreshEnvs, int64(defaultRefresh), settings.NoEnvironment); err != nil {
			return fmt.Errorf("Failed to add %s to configuration: %v", settings.RefreshEnvs, err)
		}
	}
	// Check if service settings for enroll/remove oneliner links is ready
	if !mgr.IsValue(settings.ServiceTLS, settings.OnelinerExpiration, settings.NoEnvironment) {
		if err := mgr.NewBooleanValue(settings.ServiceTLS, settings.OnelinerExpiration, defaultOnelinerExpiration, settings.NoEnvironment); err != nil {
			return fmt.Errorf("Failed to add %s to configuration: %v", settings.OnelinerExpiration, err)
		}
	}
	// Write JSON config to settings
	if err := mgr.SetTLSJSON(tlsConfig, settings.NoEnvironment); err != nil {
		return fmt.Errorf("Failed to add JSON values to configuration: %v", err)
	}
	return nil
}
