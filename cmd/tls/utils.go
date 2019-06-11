package main

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	"github.com/javuto/osctrl/pkg/environments"
	"github.com/javuto/osctrl/pkg/nodes"
	"github.com/javuto/osctrl/pkg/settings"
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
func nodeFromEnroll(req EnrollRequest, environment, ipaddress, nodekey string) nodes.OsqueryNode {
	// Prepare the enrollment request to be stored as JSON
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
		 Environment:         environment,
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

// Helper for debugging purposes and dump a full HTTP request
func debugHTTPDump(r *http.Request, debugCheck bool, showBody bool) {
	if debugCheck {
		log.Println("-------------------------------------------------- request")
		requestDump, err := httputil.DumpRequest(r, showBody)
		if err != nil {
			log.Printf("error while dumprequest %v", err)
		}
		log.Println(string(requestDump))
		if !showBody {
			log.Println("---------------- Skipping Request Body -------------------")
		}
		log.Println("-------------------------------------------------------end")
	}
}

// Helper function to send HTTP requests
func sendRequest(secure bool, reqType, url string, params io.Reader, headers map[string]string) (int, []byte, error) {
	var client *http.Client
	if secure {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client = &http.Client{Transport: tr}
	} else {
		client = &http.Client{}
	}
	req, err := http.NewRequest(reqType, url, params)
	if err != nil {
		return 0, []byte("Cound not prepare request"), err
	}
	// Prepare headers
	for key, value := range headers {
		req.Header.Add(key, value)
	}
	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return 0, []byte("Error sending request"), err
	}
	//defer resp.Body.Close()
	defer func() {
		err := resp.Body.Close()
		if err != nil {
			log.Printf("Failed to close body %v", err)
		}
	}()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, []byte("Can not read response"), err
	}

	return resp.StatusCode, bodyBytes, nil
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

// Helper to send metrics if it is enabled
func incMetric(name string) {
	if settingsmgr.ServiceMetrics(settings.ServiceTLS) {
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
