// Package osquery provides shared helpers for working with the osquery schema.
package osquery

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/jmpsec/osctrl/pkg/types"
)

// LoadTables reads the osquery schema JSON file at path and returns a slice of
// OsqueryTable values. It mirrors the logic previously inlined in
// cmd/admin/utils.go loadOsqueryTables so both admin and api can share it.
func LoadTables(path string) ([]types.OsqueryTable, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var tables []types.OsqueryTable
	if err := json.Unmarshal(b, &tables); err != nil {
		return nil, err
	}
	// Build the filter string used for platform-based CSS filtering in the
	// legacy admin templates. Kept here for parity; the API returns it too.
	for i, t := range tables {
		filter := ""
		for _, p := range t.Platforms {
			filter += " filter-" + p
		}
		tables[i].Filter = strings.TrimSpace(filter)
	}
	return tables, nil
}
