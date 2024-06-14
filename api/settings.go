package main

import (
	"log"

	"github.com/jmpsec/osctrl/metrics"
	"github.com/jmpsec/osctrl/settings"
)

// Function to load the metrics settings
func loadingMetrics() {
	// Check if service settings for metrics is ready, initialize if so
	if !settingsmgr.IsValue(settings.ServiceAPI, settings.ServiceMetrics, settings.NoEnvironmentID) {
		if err := settingsmgr.NewBooleanValue(settings.ServiceAPI, settings.ServiceMetrics, false, settings.NoEnvironmentID); err != nil {
			log.Printf("Failed to add %s to configuration: %v", settings.ServiceMetrics, err)
		}
	} else if settingsmgr.ServiceMetrics(settings.ServiceAPI) {
		_mCfg, err := metrics.LoadConfiguration()
		if err != nil {
			if err := settingsmgr.SetBoolean(false, settings.ServiceAPI, settings.ServiceMetrics, settings.NoEnvironmentID); err != nil {
				log.Fatalf("Failed to disable metrics: %v", err)
			}
			log.Printf("Failed to initialize metrics: %v", err)
		} else {
			_metrics, err = metrics.CreateMetrics(_mCfg.Protocol, _mCfg.Host, _mCfg.Port, serviceName)
			if err != nil {
				log.Fatalf("Failed to initialize metrics: %v", err)
				if err := settingsmgr.SetBoolean(false, settings.ServiceAPI, settings.ServiceMetrics, settings.NoEnvironmentID); err != nil {
					log.Fatalf("Failed to disable metrics: %v", err)
				}
			}
		}
	}
}

// Function to load all settings for the service
func loadingSettings() {
	// Check if service settings for debug service is ready
	if !settingsmgr.IsValue(settings.ServiceAPI, settings.DebugService, settings.NoEnvironmentID) {
		if err := settingsmgr.NewBooleanValue(settings.ServiceAPI, settings.DebugService, false, settings.NoEnvironmentID); err != nil {
			log.Fatalf("Failed to add %s to settings: %v", settings.DebugService, err)
		}
	}
	// Check if service settings for debug HTTP is ready
	if !settingsmgr.IsValue(settings.ServiceAPI, settings.DebugHTTP, settings.NoEnvironmentID) {
		if err := settingsmgr.NewBooleanValue(settings.ServiceAPI, settings.DebugHTTP, false, settings.NoEnvironmentID); err != nil {
			log.Fatalf("Failed to add %s to settings: %v", settings.DebugHTTP, err)
		}
	}
	// Check if service settings for metrics is ready, initialize if so
	if !settingsmgr.IsValue(settings.ServiceAPI, settings.ServiceMetrics, settings.NoEnvironmentID) {
		if err := settingsmgr.NewBooleanValue(settings.ServiceAPI, settings.ServiceMetrics, false, settings.NoEnvironmentID); err != nil {
			log.Printf("Failed to add %s to settings: %v", settings.ServiceMetrics, err)
		}
	} else if settingsmgr.ServiceMetrics(settings.ServiceAPI) {
		_mCfg, err := metrics.LoadConfiguration()
		if err != nil {
			if err := settingsmgr.SetBoolean(false, settings.ServiceAPI, settings.ServiceMetrics, settings.NoEnvironmentID); err != nil {
				log.Fatalf("Failed to disable metrics: %v", err)
			}
			log.Printf("Failed to initialize metrics: %v", err)
		} else {
			_metrics, err = metrics.CreateMetrics(_mCfg.Protocol, _mCfg.Host, _mCfg.Port, serviceName)
			if err != nil {
				log.Fatalf("Failed to initialize metrics: %v", err)
				if err := settingsmgr.SetBoolean(false, settings.ServiceAPI, settings.ServiceMetrics, settings.NoEnvironmentID); err != nil {
					log.Fatalf("Failed to disable metrics: %v", err)
				}
			}
		}
	}
	// Check if service settings for environments refresh is ready
	if !settingsmgr.IsValue(settings.ServiceAPI, settings.RefreshEnvs, settings.NoEnvironmentID) {
		if err := settingsmgr.NewIntegerValue(settings.ServiceAPI, settings.RefreshEnvs, int64(defaultRefresh), settings.NoEnvironmentID); err != nil {
			log.Fatalf("Failed to add %s to settings: %v", settings.RefreshEnvs, err)
		}
	}
	// Check if service settings for settings refresh is ready
	if !settingsmgr.IsValue(settings.ServiceAPI, settings.RefreshSettings, settings.NoEnvironmentID) {
		if err := settingsmgr.NewIntegerValue(settings.ServiceAPI, settings.RefreshSettings, int64(defaultRefresh), settings.NoEnvironmentID); err != nil {
			log.Fatalf("Failed to add %s to settings: %v", settings.RefreshSettings, err)
		}
	}
	// Metrics
	loadingMetrics()
	// Write JSON config to settings
	if err := settingsmgr.SetAPIJSON(apiConfig, settings.NoEnvironmentID); err != nil {
		log.Fatalf("Failed to add JSON values to configuration: %v", err)
	}
}
