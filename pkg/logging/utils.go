package logging

import (
	"github.com/jmpsec/osctrl/pkg/backend"
)

const (
	// NotReturned - Value not returned from agent
	NotReturned = "not returned"
	// Mismatched - Value mismatched in log entries
	Mismatched = "mismatched"
)

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

// Helper to check if two DB configurations are the same
func sameConfigDB(loggerOne, loggerTwo backend.JSONConfigurationDB) bool {
	return (loggerOne.Host == loggerTwo.Host) && (loggerOne.Port == loggerTwo.Port) && (loggerOne.Name == loggerTwo.Name)
}

// Helper to be used preparing metadata for each decorator
func metadataVerification(dst, src string) string {
	if src != dst {
		if dst == "" {
			return src
		}
		if src == "" {
			return dst
		}
	}
	return src
}

// Helper to make sure all metadata values are not empty
func metadataNotEmpty(value string) string {
	if value == "" {
		return NotReturned
	}
	return value
}
