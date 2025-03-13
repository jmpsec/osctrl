package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/rs/zerolog/log"
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
func toJSONConfigurationAdmin(values []settings.SettingValue) types.JSONConfigurationAdmin {
	var cfg types.JSONConfigurationAdmin
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
		if v.Name == settings.JSONLogger {
			cfg.Logger = v.String
		}
	}
	return cfg
}

// Helper to convert string into indented string
func jsonRawIndent(raw string) string {
	var out bytes.Buffer
	if err := json.Indent(&out, []byte(raw), "", "    "); err != nil {
		return string(raw)
	}
	return out.String()
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
	defer func() {
		if err := jsonFile.Close(); err != nil {
			log.Fatal().Msgf("Failed to close tables file %v", err)
		}
	}()
	byteValue, _ := io.ReadAll(jsonFile)
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
