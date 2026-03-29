package version

import (
	"encoding/json"
	"net/http"

	"golang.org/x/mod/semver"

	"github.com/jmpsec/osctrl/pkg/utils"
)

const (
	// OsctrlVersion to have the version for all components
	OsctrlVersion = "0.5.0"
	// OsqueryVersion to have the version for osquery defined
	OsqueryVersion = "5.21.0"
	// VersionDataURL to have the URL to retrieve the latest version for all osctrl components
	VersionDataURL = "https://stats.osctrl.net/version_data.json"
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
	return semver.Compare(OsctrlVersion, suggestedRelease) >= 0
}

func RetrieveVersionData() (*VersionData, error) {
	status, data, err := utils.SendRequest(http.MethodGet, VersionDataURL, nil, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, err
	}
	var versionData VersionData
	if err := json.Unmarshal(data, &versionData); err != nil {
		return nil, err
	}
	return &versionData, nil
}
