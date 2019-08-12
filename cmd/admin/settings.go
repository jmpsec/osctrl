package main

import (
	"log"

	"github.com/jmpsec/osctrl/pkg/metrics"
	"github.com/jmpsec/osctrl/pkg/settings"
)

// Function to load all settings for the service
func loadingSettings() {
	// Check if service settings for debug service is ready
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Initializing settings")
	}
	// Check if service settings for debug service is ready
	if !settingsmgr.IsValue(settings.ServiceAdmin, settings.DebugService) {
		if err := settingsmgr.NewBooleanValue(settings.ServiceAdmin, settings.DebugService, false); err != nil {
			log.Fatalf("Failed to add %s to settings: %v", settings.DebugService, err)
		}
	}
	// Check if service settings for debug HTTP is ready
	if !settingsmgr.IsValue(settings.ServiceAdmin, settings.DebugHTTP) {
		if err := settingsmgr.NewBooleanValue(settings.ServiceAdmin, settings.DebugHTTP, false); err != nil {
			log.Fatalf("Failed to add %s to settings: %v", settings.DebugHTTP, err)
		}
	}
	// Check if service settings for metrics is ready
	if !settingsmgr.IsValue(settings.ServiceAdmin, settings.ServiceMetrics) {
		if err := settingsmgr.NewBooleanValue(settings.ServiceAdmin, settings.ServiceMetrics, false); err != nil {
			log.Fatalf("Failed to add %s to settings: %v", settings.ServiceMetrics, err)
		}
	} else if settingsmgr.ServiceMetrics(settings.ServiceAdmin) {
		// Initialize metrics if enabled
		mProtocol, err := settingsmgr.GetString(settings.ServiceAdmin, settings.MetricsProtocol)
		if err != nil {
			log.Fatalf("Failed to initialize metrics (protocol): %v", err)
		}
		mHost, err := settingsmgr.GetString(settings.ServiceAdmin, settings.MetricsHost)
		if err != nil {
			log.Fatalf("Failed to initialize metrics (host): %v", err)
		}
		mPort, err := settingsmgr.GetInteger(settings.ServiceAdmin, settings.MetricsPort)
		if err != nil {
			log.Fatalf("Failed to initialize metrics (port): %v", err)
		}
		_metrics, err = metrics.CreateMetrics(mProtocol, mHost, int(mPort), settings.ServiceAdmin)
		if err != nil {
			log.Fatalf("Failed to initialize metrics: %v", err)
		}
	}
	// Check if service settings for default environment is ready
	if !settingsmgr.IsValue(settings.ServiceAdmin, settings.DefaultEnv) {
		if err := settingsmgr.NewStringValue(settings.ServiceAdmin, settings.DefaultEnv, "dev"); err != nil {
			log.Fatalf("Failed to add %s to settings: %v", settings.DefaultEnv, err)
		}
	}
	// Check if service settings for sessions cleanup is ready
	if !settingsmgr.IsValue(settings.ServiceAdmin, settings.CleanupSessions) {
		if err := settingsmgr.NewIntegerValue(settings.ServiceAdmin, settings.CleanupSessions, int64(defaultRefresh)); err != nil {
			log.Fatalf("Failed to add %s to configuration: %v", settings.CleanupSessions, err)
		}
	}
	// Check if service settings for node inactive hours is ready
	if !settingsmgr.IsValue(settings.ServiceAdmin, settings.InactiveHours) {
		if err := settingsmgr.NewIntegerValue(settings.ServiceAdmin, settings.InactiveHours, int64(defaultInactive)); err != nil {
			log.Fatalf("Failed to add %s to configuration: %v", settings.InactiveHours, err)
		}
	}
	// Write JSON config to settings
	if err := settingsmgr.SetAllJSON(settings.ServiceAdmin, adminConfig.Listener, adminConfig.Port, adminConfig.Host, adminConfig.Auth, adminConfig.Logging); err != nil {
		log.Fatalf("Failed to add JSON values to configuration: %v", err)
	}
}
