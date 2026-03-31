package version

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/mod/semver"
)

const (
	// OsctrlVersion to have the version for all components
	OsctrlVersion = "0.5.0"
	// OsqueryVersion to have the version for osquery defined
	OsqueryVersion = "5.22.1"
	// VersionDataURL to have the URL to retrieve the latest version for all osctrl components
	VersionDataURL = "https://stats.osctrl.net/version_data.json"
	// versionDataRequestTimeout sets the max time to wait for version data retrieval.
	versionDataRequestTimeout = 10 * time.Second
)

// VersionData to retrieve the latest version for all osctrl components
type VersionData struct {
	LatestRelease    string `json:"latestRelease"`
	OsqueryVersion   string `json:"osqueryVersion"`
	SuggestedRelease string `json:"suggestedRelease"`
	MoreInformation  string `json:"moreInformation"`
}

// CheckSuggestedRelease to check if the current version is equal or higher than the suggested release
func CheckSuggestedRelease(suggestedRelease string) bool {
	return semver.Compare("v"+OsctrlVersion, "v"+suggestedRelease) >= 0
}

func RetrieveVersionData(url string) (*VersionData, error) {
	ctx, cancel := context.WithTimeout(context.Background(), versionDataRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var versionData VersionData
	if err := json.Unmarshal(data, &versionData); err != nil {
		return nil, err
	}
	return &versionData, nil
}
