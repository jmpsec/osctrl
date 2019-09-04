package main

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/segmentio/ksuid"
)

// Helper to generate a random enough node key
func generateNodeKey(uuid string) string {
	timestamp := strconv.FormatInt(time.Now().UTC().UnixNano(), 10)
	hasher := md5.New()
	_, _ = hasher.Write([]byte(uuid + timestamp))
	return hex.EncodeToString(hasher.Sum(nil))
}

// Helper to generate a carve session_id using KSUID
// See https://github.com/segmentio/ksuid for more info about KSUIDs
func generateCarveSessionID() string {
	id := ksuid.New()
	return id.String()
}

// Helper to check if the provided secret is valid for this environment
func checkValidSecret(enrollSecret string, environment string) bool {
	env, err := envs.Get(environment)
	if err != nil {
		return false
	}
	return (strings.TrimSpace(enrollSecret) == env.Secret)
}

// Helper to check if the provided SecretPath is valid for enrolling in a environment
func checkValidEnrollSecretPath(environment, secretpath string) bool {
	env, err := envs.Get(environment)
	if err != nil {
		return false
	}
	return ((strings.TrimSpace(secretpath) == env.EnrollSecretPath) && (!environments.IsItExpired(env.EnrollExpire)))
}

// Helper to check if the provided SecretPath is valid for removing in a environment
func checkValidRemoveSecretPath(environment, secretpath string) bool {
	env, err := envs.Get(environment)
	if err != nil {
		return false
	}
	return ((strings.TrimSpace(secretpath) == env.RemoveSecretPath) && (!environments.IsItExpired(env.RemoveExpire)))
}

// Helper to convert an enrollment request into a osquery node
func nodeFromEnroll(req types.EnrollRequest, environment, ipaddress, nodekey string) nodes.OsqueryNode {
	// Prepare the enrollment request to be stored as raw JSON
	enrollRaw, err := json.Marshal(req)
	if err != nil {
		log.Printf("error serializing enrollment: %v", err)
		enrollRaw = []byte("")
	}
	// Avoid the error "unsupported Unicode escape sequence" due to \u0000
	enrollRaw = bytes.Replace(enrollRaw, []byte("\\u0000"), []byte(""), -1)
	return nodes.OsqueryNode{
		NodeKey:         nodekey,
		UUID:            req.HostIdentifier,
		Platform:        req.HostDetails.EnrollOSVersion.Platform,
		PlatformVersion: req.HostDetails.EnrollOSVersion.Version,
		OsqueryVersion:  req.HostDetails.EnrollOsqueryInfo.Version,
		Hostname:        req.HostDetails.EnrollSystemInfo.Hostname,
		Localname:       req.HostDetails.EnrollSystemInfo.LocalHostname,
		IPAddress:       ipaddress,
		Username:        "unknown",
		OsqueryUser:     "unknown",
		Environment:     environment,
		CPU:             strings.TrimRight(req.HostDetails.EnrollSystemInfo.CPUBrand, "\x00"),
		Memory:          req.HostDetails.EnrollSystemInfo.PhysicalMemory,
		HardwareSerial:  req.HostDetails.EnrollSystemInfo.HardwareSerial,
		ConfigHash:      req.HostDetails.EnrollOsqueryInfo.ConfigHash,
		RawEnrollment:   enrollRaw,
		LastStatus:      time.Time{},
		LastResult:      time.Time{},
		LastConfig:      time.Time{},
		LastQueryRead:   time.Time{},
		LastQueryWrite:  time.Time{},
	}
}

// Helper to remove duplicates from array of strings
func uniq(duplicated []string) []string {
	keys := make(map[string]bool)
	result := []string{}
	for _, entry := range duplicated {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			result = append(result, entry)
		}
	}
	return result
}

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

// Helper to send metrics if it is enabled
func incMetric(name string) {
	if _metrics != nil && settingsmgr.ServiceMetrics(settings.ServiceTLS) {
		_metrics.Inc(name)
	}
}

// Helper to refresh the environments map until cache/Redis support is implemented
func refreshEnvironments() {
	log.Printf("Refreshing environments...\n")
	var err error
	envsmap, err = envs.GetMap()
	if err != nil {
		log.Printf("error refreshing environments %v\n", err)
	}
}

// Helper to refresh the settings until cache/Redis support is implemented
func refreshSettings() {
	log.Printf("Refreshing settings...\n")
	var err error
	settingsmap, err = settingsmgr.GetMap(settings.ServiceTLS)
	if err != nil {
		log.Printf("error refreshing settings %v\n", err)
	}
}

// Usage for service binary
func tlsUsage() {
	fmt.Printf("NAME:\n   %s - %s\n\n", serviceName, serviceDescription)
	fmt.Printf("USAGE: %s [global options] [arguments...]\n\n", serviceName)
	fmt.Printf("VERSION:\n   %s\n\n", serviceVersion)
	fmt.Printf("DESCRIPTION:\n   %s\n\n", appDescription)
	fmt.Printf("GLOBAL OPTIONS:\n")
	flag.PrintDefaults()
	fmt.Printf("\n")
}

// Display binary version
func tlsVersion() {
	fmt.Printf("%s v%s\n", serviceName, serviceVersion)
	os.Exit(0)
}
