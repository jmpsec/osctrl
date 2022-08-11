package logging

import "github.com/jmpsec/osctrl/backend"

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
