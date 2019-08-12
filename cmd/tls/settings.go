package main

import (
	"log"

	"github.com/jmpsec/osctrl/pkg/metrics"
	"github.com/jmpsec/osctrl/pkg/settings"
)

// Function to load all settings for the service
func loadingSettings() {
	// Check if service settings for debug service is ready
	if !settingsmgr.IsValue(settings.ServiceTLS, settings.DebugService) {
		if err := settingsmgr.NewBooleanValue(settings.ServiceTLS, settings.DebugService, false); err != nil {
			log.Fatalf("Failed to add %s to configuration: %v", settings.DebugService, err)
		}
	}
	// Check if service settings for metrics is ready
	if !settingsmgr.IsValue(settings.ServiceTLS, settings.ServiceMetrics) {
		if err := settingsmgr.NewBooleanValue(settings.ServiceTLS, settings.ServiceMetrics, false); err != nil {
			log.Fatalf("Failed to add %s to configuration: %v", settings.ServiceMetrics, err)
		}
	} else if settingsmgr.ServiceMetrics(settings.ServiceTLS) {
		// Initialize metrics if enabled
		mProtocol, err := settingsmgr.GetString(settings.ServiceTLS, settings.MetricsProtocol)
		if err != nil {
			log.Fatalf("Failed to initialize metrics (protocol): %v", err)
		}
		mHost, err := settingsmgr.GetString(settings.ServiceTLS, settings.MetricsHost)
		if err != nil {
			log.Fatalf("Failed to initialize metrics (host): %v", err)
		}
		mPort, err := settingsmgr.GetInteger(settings.ServiceTLS, settings.MetricsPort)
		if err != nil {
			log.Fatalf("Failed to initialize metrics (port): %v", err)
		}
		_metrics, err = metrics.CreateMetrics(mProtocol, mHost, int(mPort), settings.ServiceTLS)
		if err != nil {
			log.Fatalf("Failed to initialize metrics: %v", err)
		}
	}
	// Check if service settings for environments refresh is ready
	if !settingsmgr.IsValue(settings.ServiceTLS, settings.RefreshEnvs) {
		if err := settingsmgr.NewIntegerValue(settings.ServiceTLS, settings.RefreshEnvs, int64(defaultRefresh)); err != nil {
			log.Fatalf("Failed to add %s to configuration: %v", settings.RefreshEnvs, err)
		}
	}
	// Check if service settings for settings refresh is ready
	if !settingsmgr.IsValue(settings.ServiceTLS, settings.RefreshSettings) {
		if err := settingsmgr.NewIntegerValue(settings.ServiceTLS, settings.RefreshSettings, int64(defaultRefresh)); err != nil {
			log.Fatalf("Failed to add %s to configuration: %v", settings.RefreshSettings, err)
		}
	}
	// Write JSON config to settings
	if err := settingsmgr.SetAllJSON(settings.ServiceTLS, tlsConfig.Listener, tlsConfig.Port, tlsConfig.Host, tlsConfig.Auth, tlsConfig.Logging); err != nil {
		log.Fatalf("Failed to add JSON values to configuration: %v", err)
	}
}
