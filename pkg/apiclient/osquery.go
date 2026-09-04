package apiclient

import (
	"encoding/json"
	"fmt"
	"path"

	"github.com/jmpsec/osctrl/pkg/types"
)

// PlatformCounts mirrors the per-platform node tallies the stats endpoint
// returns for each environment.
type PlatformCounts struct {
	Linux   int64 `json:"linux"`
	Darwin  int64 `json:"darwin"`
	Windows int64 `json:"windows"`
	Other   int64 `json:"other"`
}

// EnvStats is the per-environment slice of the stats response.
type EnvStats struct {
	UUID           string         `json:"uuid"`
	Name           string         `json:"name"`
	TotalNodes     int64          `json:"total_nodes"`
	ActiveNodes    int64          `json:"active_nodes"`
	InactiveNodes  int64          `json:"inactive_nodes"`
	PlatformCounts PlatformCounts `json:"platform_counts"`
}

// StatsResponse mirrors GET /api/v1/stats.
//
// Hand-typed here rather than imported: the canonical struct lives in
// cmd/api/handlers, and importing that package would drag the whole server
// (database, settings, logger sinks) into every client. The API only ever
// adds fields to this response, and unknown fields decode away silently, so
// the duplication is cheap to keep in sync.
//
// Note the response is already scoped to what the caller may see — the
// handler filters environments through Users.CheckPermissions, so a
// restricted token gets a smaller Environments slice, not a 403.
type StatsResponse struct {
	TotalNodes         int64          `json:"total_nodes"`
	ActiveNodes        int64          `json:"active_nodes"`
	InactiveNodes      int64          `json:"inactive_nodes"`
	InactiveHours      int64          `json:"inactive_hours"`
	TotalActiveQueries int            `json:"total_active_queries"`
	TotalActiveCarves  int            `json:"total_active_carves"`
	Platforms          PlatformCounts `json:"platform_counts"`
	Environments       []EnvStats     `json:"environments"`
}

// GetStats to retrieve fleet-wide counts from osctrl
func (api *OsctrlAPI) GetStats() (StatsResponse, error) {
	var s StatsResponse
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, APIStats))
	rawS, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return s, fmt.Errorf("error api request - %w - %s", err, string(rawS))
	}
	if err := json.Unmarshal(rawS, &s); err != nil {
		return s, fmt.Errorf("can not parse body - %w", err)
	}
	return s, nil
}

// GetOsqueryTables to retrieve the osquery schema osctrl was configured with
func (api *OsctrlAPI) GetOsqueryTables() ([]types.OsqueryTable, error) {
	var t []types.OsqueryTable
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, APIOsquery, "tables"))
	rawT, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return t, fmt.Errorf("error api request - %w - %s", err, string(rawT))
	}
	if err := json.Unmarshal(rawT, &t); err != nil {
		return t, fmt.Errorf("can not parse body - %w", err)
	}
	return t, nil
}
