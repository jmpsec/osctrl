package main

import (
	"flag"
	"fmt"
	"os"
	"osctrl/internal/environments"
	"osctrl/internal/settings"

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

// Usage for service binary
func apiUsage() {
	fmt.Printf("NAME:\n   %s - %s\n\n", serviceName, serviceDescription)
	fmt.Printf("USAGE: %s [global options] [arguments...]\n\n", serviceName)
	fmt.Printf("VERSION:\n   %s\n\n", serviceVersion)
	fmt.Printf("DESCRIPTION:\n   %s\n\n", appDescription)
	fmt.Printf("GLOBAL OPTIONS:\n")
	flag.PrintDefaults()
	fmt.Printf("\n")
}

// Display binary version
func apiVersion() {
	fmt.Printf("%s v%s\n", serviceName, serviceVersion)
	os.Exit(0)
}

// Helper to compose paths for API
func _apiPath(target string) string {
	return apiPrefixPath + apiVersionPath + target
}
