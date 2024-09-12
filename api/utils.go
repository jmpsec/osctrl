package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/jmpsec/osctrl/environments"
	"github.com/jmpsec/osctrl/settings"
)

// Helper to refresh the environments map until cache/Redis support is implemented
func refreshEnvironments() environments.MapEnvironments {
	log.Printf("Refreshing environments...\n")
	_envsmap, err := envs.GetMap()
	if err != nil {
		log.Printf("error refreshing environments %v\n", err)
		return environments.MapEnvironments{}
	}
	return _envsmap
}

// Helper to refresh the settings until cache/Redis support is implemented
func refreshSettings() settings.MapSettings {
	log.Printf("Refreshing settings...\n")
	_settingsmap, err := settingsmgr.GetMap(settings.ServiceAPI, settings.NoEnvironmentID)
	if err != nil {
		log.Printf("error refreshing settings %v\n", err)
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
