package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/types"
)

// Function to generate a secure CSRF token
func generateCSRF() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// Helper to remove backslashes from text
func removeBackslash(rawString string) string {
	return strings.Replace(rawString, "\\", " ", -1)
}

// Helper to generate a link to results for on-demand queries
func queryResultLink(name string) (string, string) {
	defaultLink := strings.Replace(settings.QueryLink, "{{NAME}}", removeBackslash(name), 1)
	dbLink := strings.Replace(settingsmgr.QueryResultLink(), "{{NAME}}", removeBackslash(name), 1)
	return defaultLink, dbLink
}

// Helper to generate a link to results for status logs
func statusLogsLink(uuid string) string {
	return strings.Replace(settingsmgr.StatusLogsLink(), "{{UUID}}", removeBackslash(uuid), 1)
}

// Helper to generate a link to results for result logs
func resultLogsLink(uuid string) string {
	return strings.Replace(settingsmgr.ResultLogsLink(), "{{UUID}}", removeBackslash(uuid), 1)
}

// Helper to calculate the osquery config_hash and skip sending a blob that won't change anything
// https://github.com/facebook/osquery/blob/master/osquery/config/config.cpp#L911
// osquery calculates the SHA1 of the configuration blob, then the SHA1 hash of that
/*
func generateOsqueryConfigHash(config string) string {
	firstHasher := sha1.New()
	secondHasher := sha1.New()
	// Get SHA1 of configuration blob
	_, _ = firstHasher.Write([]byte(config))
	// Get SHA1 of the first hash
	_, _ = secondHasher.Write([]byte(hex.EncodeToString(firstHasher.Sum(nil))))
	return hex.EncodeToString(secondHasher.Sum(nil))
}
*/

// Helper to convert from settings values to JSON configuration
func toJSONConfigurationService(values []settings.SettingValue) types.JSONConfigurationService {
	var cfg types.JSONConfigurationService
	for _, v := range values {
		if v.Name == settings.JSONListener {
			cfg.Listener = v.String
		}
		if v.Name == settings.JSONPort {
			cfg.Port = v.String
		}
		if v.Name == settings.JSONHost {
			cfg.Host = v.String
		}
		if v.Name == settings.JSONAuth {
			cfg.Auth = v.String
		}
		if v.Name == settings.JSONLogging {
			cfg.Logging = strings.Split(v.String, ",")
		}
	}
	return cfg
}

// Helper to send metrics if it is enabled
func incMetric(name string) {
	if adminMetrics != nil && settingsmgr.ServiceMetrics(settings.ServiceAdmin) {
		adminMetrics.Inc(name)
	}
}

// Helper to convert json.RawMessage into indented string
func jsonRawIndent(raw json.RawMessage) string {
	var out bytes.Buffer
	if err := json.Indent(&out, raw, "", "    "); err != nil {
		return string(raw)
	}
	return string(out.Bytes())
}

// Helper to verify the service is valid
func checkTargetService(service string) bool {
	if service == settings.ServiceTLS {
		return true
	}
	if service == settings.ServiceAdmin {
		return true
	}
	if service == settings.ServiceAPI {
		return true
	}
	return false
}

// Function to load the JSON data for osquery tables
func loadOsqueryTables(file string) ([]types.OsqueryTable, error) {
	var tables []types.OsqueryTable
	jsonFile, err := os.Open(file)
	if err != nil {
		return tables, err
	}
	//defer jsonFile.Close()
	defer func() {
		if err := jsonFile.Close(); err != nil {
			log.Fatalf("Failed to close tables file %v", err)
		}
	}()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	if err := json.Unmarshal(byteValue, &tables); err != nil {
		return tables, err
	}
	// Add a string for platforms to be used as filter
	for i, t := range tables {
		filter := ""
		for _, p := range t.Platforms {
			filter += " filter-" + p
		}
		tables[i].Filter = strings.TrimSpace(filter)
	}
	return tables, nil
}
