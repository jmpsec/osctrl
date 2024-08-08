package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/jmpsec/osctrl/environments"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/types"
	"github.com/jmpsec/osctrl/utils"
)

// Helper to send metrics if it is enabled
func incMetric(name string) {
	if _metrics != nil && settingsmgr.ServiceMetrics(settings.ServiceAPI) {
		_metrics.Inc(name)
	}
}

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

// Helper to verify if a platform is valid
func checkValidPlatform(platforms []string, platform string) bool {
	for _, p := range platforms {
		if p == platform {
			return true
		}
	}
	return false
}

// Helper to remove duplicates from []string
func removeStringDuplicates(s []string) []string {
	seen := make(map[string]struct{}, len(s))
	i := 0
	for _, v := range s {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		s[i] = v
		i++
	}
	return s[:i]
}

// Helper to handle API error responses
func apiErrorResponse(w http.ResponseWriter, msg string, code int, err error) {
	log.Printf("apiErrorResponse %s: %v", msg, err)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, code, types.ApiErrorResponse{Error: msg})
}
