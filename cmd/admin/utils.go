package main

import (
	"encoding/json"
	"io"
	"os"
	"strings"

	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/rs/zerolog/log"
)

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
