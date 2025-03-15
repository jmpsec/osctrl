package main

import (
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/rs/zerolog/log"
)

// Helper to refresh the environments map until cache/Redis support is implemented
func refreshEnvironments() environments.MapEnvironments {
	log.Info().Msg("Refreshing environments...")
	_envsmap, err := envs.GetMap()
	if err != nil {
		log.Err(err).Msg("error refreshing environments")
		return environments.MapEnvironments{}
	}
	return _envsmap
}

// Helper to refresh the settings until cache/Redis support is implemented
func refreshSettings() settings.MapSettings {
	log.Info().Msg("Refreshing settings...")
	_settingsmap, err := settingsmgr.GetMap(settings.ServiceAPI, settings.NoEnvironmentID)
	if err != nil {
		log.Err(err).Msg("error refreshing settings")
		return settings.MapSettings{}
	}
	return _settingsmap
}

// Helper to compose paths for API
func _apiPath(target string) string {
	return apiPrefixPath + apiVersionPath + target
}
