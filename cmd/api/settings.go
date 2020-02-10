package main

import (
	"log"

	"github.com/jmpsec/osctrl/pkg/metrics"
	"github.com/jmpsec/osctrl/pkg/settings"
)

// Function to load the metrics settings
func loadingMetrics() {
	// Check if service settings for metrics is ready, initialize if so
	if !settingsmgr.IsValue(settings.ServiceAPI, settings.ServiceMetrics) {
		if err := settingsmgr.NewBooleanValue(settings.ServiceAPI, settings.ServiceMetrics, false); err != nil {
			log.Printf("Failed to add %s to configuration: %v", settings.ServiceMetrics, err)
		}
	} else if settingsmgr.ServiceMetrics(settings.ServiceAPI) {
		_mCfg, err := metrics.LoadConfiguration()
		if err != nil {
			if err := settingsmgr.SetBoolean(false, settings.ServiceAPI, settings.ServiceMetrics); err != nil {
				log.Fatalf("Failed to disable metrics: %v", err)
			}
			log.Printf("Failed to initialize metrics: %v", err)
		} else {
			_metrics, err = metrics.CreateMetrics(_mCfg.Protocol, _mCfg.Host, _mCfg.Port, serviceName)
			if err != nil {
				log.Fatalf("Failed to initialize metrics: %v", err)
				if err := settingsmgr.SetBoolean(false, settings.ServiceAPI, settings.ServiceMetrics); err != nil {
					log.Fatalf("Failed to disable metrics: %v", err)
				}
			}
		}
	}
}

// Function to load all settings for the service
func loadingSettings() {
	// Check if service settings for debug service is ready
	if !settingsmgr.IsValue(settings.ServiceAPI, settings.DebugService) {
		if err := settingsmgr.NewBooleanValue(settings.ServiceAPI, settings.DebugService, false); err != nil {
			log.Fatalf("Failed to add %s to configuration: %v", settings.DebugService, err)
		}
	}
	// Check if service settings for metrics is ready, initialize if so
	if !settingsmgr.IsValue(settings.ServiceAPI, settings.ServiceMetrics) {
		if err := settingsmgr.NewBooleanValue(settings.ServiceAPI, settings.ServiceMetrics, false); err != nil {
			log.Printf("Failed to add %s to configuration: %v", settings.ServiceMetrics, err)
		}
	} else if settingsmgr.ServiceMetrics(settings.ServiceAPI) {
		_mCfg, err := metrics.LoadConfiguration()
		if err != nil {
			if err := settingsmgr.SetBoolean(false, settings.ServiceAPI, settings.ServiceMetrics); err != nil {
				log.Fatalf("Failed to disable metrics: %v", err)
			}
			log.Printf("Failed to initialize metrics: %v", err)
		} else {
			_metrics, err = metrics.CreateMetrics(_mCfg.Protocol, _mCfg.Host, _mCfg.Port, serviceName)
			if err != nil {
				log.Fatalf("Failed to initialize metrics: %v", err)
				if err := settingsmgr.SetBoolean(false, settings.ServiceAPI, settings.ServiceMetrics); err != nil {
					log.Fatalf("Failed to disable metrics: %v", err)
				}
			}
		}
	}
	// Check if service settings for environments refresh is ready
	if !settingsmgr.IsValue(settings.ServiceAPI, settings.RefreshEnvs) {
		if err := settingsmgr.NewIntegerValue(settings.ServiceAPI, settings.RefreshEnvs, int64(defaultRefresh)); err != nil {
			log.Fatalf("Failed to add %s to configuration: %v", settings.RefreshEnvs, err)
		}
	}
	// Check if service settings for settings refresh is ready
	if !settingsmgr.IsValue(settings.ServiceAPI, settings.RefreshSettings) {
		if err := settingsmgr.NewIntegerValue(settings.ServiceAPI, settings.RefreshSettings, int64(defaultRefresh)); err != nil {
			log.Fatalf("Failed to add %s to configuration: %v", settings.RefreshSettings, err)
		}
	}
	// Metrics
	loadingMetrics()
	// Write JSON config to settings
	if err := settingsmgr.SetAllJSON(settings.ServiceAPI, apiConfig.Listener, apiConfig.Port, apiConfig.Host, apiConfig.Auth, apiConfig.Logging); err != nil {
		log.Fatalf("Failed to add JSON values to configuration: %v", err)
	}
}
