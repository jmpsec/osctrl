package main

import (
	"log"

	"github.com/jmpsec/osctrl/metrics"
	"github.com/jmpsec/osctrl/settings"
)

// Function to load the metrics settings
func loadingMetrics() {
	// Check if service settings for metrics is ready, initialize if so
	if !settingsmgr.IsValue(settings.ServiceAdmin, settings.ServiceMetrics) {
		if err := settingsmgr.NewBooleanValue(settings.ServiceAdmin, settings.ServiceMetrics, false); err != nil {
			log.Printf("Failed to add %s to configuration: %v", settings.ServiceMetrics, err)
		}
	} else if settingsmgr.ServiceMetrics(settings.ServiceAdmin) {
		_mCfg, err := metrics.LoadConfiguration()
		if err != nil {
			if err := settingsmgr.SetBoolean(false, settings.ServiceAdmin, settings.ServiceMetrics); err != nil {
				log.Fatalf("Failed to disable metrics: %v", err)
			}
			log.Printf("Failed to initialize metrics: %v", err)
		} else {
			_metrics, err = metrics.CreateMetrics(_mCfg.Protocol, _mCfg.Host, _mCfg.Port, serviceName)
			if err != nil {
				log.Fatalf("Failed to initialize metrics: %v", err)
				if err := settingsmgr.SetBoolean(false, settings.ServiceAdmin, settings.ServiceMetrics); err != nil {
					log.Fatalf("Failed to disable metrics: %v", err)
				}
			}
		}
	}
}

// Function to load the logging settings
func loadingLogging() {
	// Check if logging settings for query results link is ready
	if !settingsmgr.IsValue(settings.ServiceAdmin, settings.QueryResultLink) {
		if err := settingsmgr.NewStringValue(settings.ServiceAdmin, settings.QueryResultLink, settings.QueryLink); err != nil {
			log.Fatalf("Failed to add %s to settings: %v", settings.QueryResultLink, err)
		}
	}
	// Check if logging settings for status logs link is ready
	if !settingsmgr.IsValue(settings.ServiceAdmin, settings.StatusLogsLink) {
		if err := settingsmgr.NewStringValue(settings.ServiceAdmin, settings.StatusLogsLink, settings.StatusLink); err != nil {
			log.Fatalf("Failed to add %s to settings: %v", settings.DebugHTTP, err)
		}
	}
	// Check if logging settings for result logs link is ready
	if !settingsmgr.IsValue(settings.ServiceAdmin, settings.ResultLogsLink) {
		if err := settingsmgr.NewStringValue(settings.ServiceAdmin, settings.ResultLogsLink, settings.ResultsLink); err != nil {
			log.Fatalf("Failed to add %s to settings: %v", settings.DebugHTTP, err)
		}
	}
}

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
	// Metrics
	loadingMetrics()
	// Logging
	loadingLogging()
	// Write JSON config to settings
	if err := settingsmgr.SetAllJSON(settings.ServiceAdmin, adminConfig.Listener, adminConfig.Port, adminConfig.Host, adminConfig.Auth, adminConfig.Logging); err != nil {
		log.Fatalf("Failed to add JSON values to configuration: %v", err)
	}
}
