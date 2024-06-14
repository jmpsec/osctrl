package main

import (
	"log"

	"github.com/jmpsec/osctrl/environments"
	"github.com/jmpsec/osctrl/settings"
)

// Helper to determine if an IPv4 is public, based on the following:
// Class   Starting IPAddress  Ending IPAddress
// A       		10.0.0.0       	 10.255.255.255
// B       		172.16.0.0       172.31.255.255
// C       		192.168.0.0      192.168.255.255
// Link-local 169.254.0.0      169.254.255.255
// Local      127.0.0.0        127.255.255.255
/*
func isPublicIP(ip net.IP) bool {
	// Use native functions
	if ip.IsLoopback() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() {
		return false
	}
	// Check each octet
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] == 10:
			return false
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return false
		case ip4[0] == 192 && ip4[1] == 168:
			return false
		default:
			return true
		}
	}
	return false
}
*/

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
	_settingsmap, err := settingsmgr.GetMap(settings.ServiceTLS, settings.NoEnvironmentID)
	if err != nil {
		log.Printf("error refreshing settings %v\n", err)
		return settings.MapSettings{}
	}
	return _settingsmap
}
